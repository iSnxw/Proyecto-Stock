import logging
import os
import threading
import time
from datetime import date, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, session
from flask_wtf.csrf import CSRFError, CSRFProtect, generate_csrf
from psycopg2 import IntegrityError
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

from db import get_db

load_dotenv()

# ============================================================
# CONFIGURACIÓN Y CONSTANTES DEL DOMINIO (SECCIÓN 9)
# ============================================================
FAMILIAS_PRODUCTO = (
    "Analgésicos",
    "Antibióticos",
    "Antiinflamatorios",
    "Antihipertensivos",
    "Antidiabéticos",
    "Respiratorios",
    "Vacunas y Biológicos",
    "Sueros y Soluciones",
    "Curación e Insumos",
    "Otros",
)

UNIDADES_MEDIDA = ("UNIDAD", "CAJA", "FRASCO", "AMPOLLA", "DOSIS")
TIPOS_MOVIMIENTO = (
    "ENTRADA",
    "SALIDA",
    "AJUSTE_MAS",
    "AJUSTE_MENOS",
    "CUARENTENA",
    "LIBERACION",
    "BAJA",
)

ES_PRODUCCION = os.environ.get("FLASK_ENV", "production").lower() == "production"
FRIO_INTERVALO_HORAS = float(os.environ.get("FRIO_INTERVALO_HORAS", "12"))

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    if ES_PRODUCCION:
        raise RuntimeError("Falta SECRET_KEY en variables de entorno.")
    secret_key = "dev-secret-cambiar-en-produccion"

app.config.update(
    SECRET_KEY=secret_key,
    DEBUG=False,
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,  # 1 MB (STRIDE D)
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_REFRESH_EACH_REQUEST=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=ES_PRODUCCION,
    WTF_CSRF_TIME_LIMIT=3600,
)

csrf = CSRFProtect(app)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = app.logger

# Control en memoria de intentos fallidos de login (5 intentos / 5 minutos)
_LOGIN_LOCK = threading.Lock()
_LOGIN_FAILS: dict[str, list[float]] = {}
MAX_LOGIN_INTENTOS = 5
VENTANA_LOGIN_SEG = 300


# ============================================================
# CABECERAS DE SEGURIDAD Y MANEJO GENÉRICO DE ERRORES
# ============================================================
@app.after_request
def agregar_cabeceras_seguras(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data: blob:; "
        "media-src 'self' blob:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"
    if ES_PRODUCCION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(CSRFError)
def error_csrf(err):
    logger.warning("Fallo CSRF en %s desde %s: %s", request.path, request.remote_addr, err.description)
    return jsonify({"error": "Token de seguridad inválido o expirado. Recargue la página."}), 400


@app.errorhandler(413)
def error_tamano(_err):
    return jsonify({"error": "La solicitud excede el tamaño máximo permitido."}), 413


@app.errorhandler(404)
def error_404(_err):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Recurso no encontrado."}), 404
    return jsonify({"error": "Ruta no encontrada."}), 404


@app.errorhandler(500)
def error_500(err):
    logger.exception("Error interno del servidor en %s: %s", request.path, err)
    return jsonify({"error": "Error interno del servidor. Intente nuevamente."}), 500


# ============================================================
# AUXILIARES DE SEGURIDAD Y VALIDACIÓN
# ============================================================
def _get_json() -> dict | None:
    """Acepta únicamente JSON válido (bloquea cargas XML / A4:2017 XXE)."""
    if not request.is_json:
        return None
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def _parse_int(val, minimo=None, maximo=None) -> int | None:
    if isinstance(val, bool) or val is None:
        return None
    try:
        num = int(val)
    except (TypeError, ValueError):
        return None
    if minimo is not None and num < minimo:
        return None
    if maximo is not None and num > maximo:
        return None
    return num


def _parse_temp(val) -> Decimal | None:
    if isinstance(val, bool) or val is None:
        return None
    try:
        dec = Decimal(str(val).strip()).quantize(Decimal("0.1"))
    except (InvalidOperation, ValueError):
        return None
    if dec < Decimal("-50.0") or dec > Decimal("60.0"):
        return None
    return dec


def _parse_date_iso(val) -> date | None:
    if not isinstance(val, str):
        return None
    try:
        return date.fromisoformat(val.strip())
    except ValueError:
        return None


def _clean_text(val, max_len: int) -> str:
    if not isinstance(val, str):
        return ""
    return val.strip()[:max_len]


def _rate_limit_key(correo: str) -> str:
    return f"{request.remote_addr or 'unknown'}|{correo}"


def _esta_bloqueado(key: str) -> bool:
    ahora = time.time()
    with _LOGIN_LOCK:
        intentos = [t for t in _LOGIN_FAILS.get(key, []) if ahora - t < VENTANA_LOGIN_SEG]
        _LOGIN_FAILS[key] = intentos
        return len(intentos) >= MAX_LOGIN_INTENTOS


def _registrar_fallo_login(key: str) -> None:
    ahora = time.time()
    with _LOGIN_LOCK:
        intentos = [t for t in _LOGIN_FAILS.get(key, []) if ahora - t < VENTANA_LOGIN_SEG]
        intentos.append(ahora)
        _LOGIN_FAILS[key] = intentos


def _limpiar_fallos_login(key: str) -> None:
    with _LOGIN_LOCK:
        _LOGIN_FAILS.pop(key, None)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session or "rol" not in session:
            return jsonify({"error": "Debe iniciar sesión."}), 401
        return fn(*args, **kwargs)
    return wrapper


def role_required(*roles_permitidos):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            rol_actual = session.get("rol")
            if rol_actual not in roles_permitidos:
                logger.warning(
                    "Acceso denegado (403) a %s %s por usuario_id=%s rol=%s",
                    request.method,
                    request.path,
                    session.get("user_id"),
                    rol_actual,
                )
                return jsonify({"error": "Acceso denegado para su rol."}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def _iso_dt(dt) -> str | None:
    return dt.isoformat() if dt else None


def _iso_date(d) -> str | None:
    return d.isoformat() if d else None


# ============================================================
# VISTAS BASE Y HEALTHCHECK
# ============================================================
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


# ============================================================
# MÓDULO 1: AUTENTICACIÓN Y SESIÓN (CU-01, RF-13)
# ============================================================
@app.post("/api/login")
def api_login():
    data = _get_json()
    if data is None:
        return jsonify({"error": "Formato JSON requerido."}), 400

    correo = _clean_text(data.get("correo"), 120).lower()
    password = data.get("password") if isinstance(data.get("password"), str) else ""

    if not correo or not password:
        return jsonify({"error": "Debe ingresar correo y contraseña."}), 400

    rl_key = _rate_limit_key(correo)
    if _esta_bloqueado(rl_key):
        logger.warning("Login bloqueado temporalmente (429) para %s", rl_key)
        return jsonify({"error": "Demasiados intentos fallidos. Espere 5 minutos."}), 429

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, nombre, correo, password_hash, rol, activo
                FROM usuarios
                WHERE LOWER(correo) = %s
                """,
                (correo,),
            )
            user = cur.fetchone()

    if not user or not user["activo"] or not check_password_hash(user["password_hash"], password):
        _registrar_fallo_login(rl_key)
        logger.warning("Intento de login fallido para %s desde %s", correo, request.remote_addr)
        return jsonify({"error": "Credenciales inválidas o cuenta deshabilitada."}), 401

    _limpiar_fallos_login(rl_key)
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["nombre"] = user["nombre"]
    session["correo"] = user["correo"]
    session["rol"] = user["rol"]

    return jsonify(
        {
            "usuario": {
                "id": user["id"],
                "nombre": user["nombre"],
                "correo": user["correo"],
                "rol": user["rol"],
            },
            "csrf_token": generate_csrf(),
        }
    ), 200


@app.post("/api/logout")
@login_required
def api_logout():
    session.clear()
    return jsonify({"ok": True, "csrf_token": generate_csrf()}), 200


@app.get("/api/me")
def api_me():
    if "user_id" not in session:
        return jsonify({"autenticado": False, "csrf_token": generate_csrf()}), 200
    return jsonify(
        {
            "autenticado": True,
            "usuario": {
                "id": session["user_id"],
                "nombre": session["nombre"],
                "correo": session["correo"],
                "rol": session["rol"],
            },
            "csrf_token": generate_csrf(),
            "familias": list(FAMILIAS_PRODUCTO),
            "unidades": list(UNIDADES_MEDIDA),
            "intervalo_frio_horas": FRIO_INTERVALO_HORAS,
        }
    ), 200


# ============================================================
# MÓDULO 2: PRODUCTOS, LOTES FEFO Y BODEGA (CU-02 a CU-05, CU-08, CU-09)
# ============================================================
@app.get("/api/lotes")
@login_required
def api_lotes():
    """Lista lotes en orden FEFO con alertas de stock mínimo y vencimiento (America/Santiago)."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                WITH fecha_cl AS (
                    SELECT (NOW() AT TIME ZONE 'America/Santiago')::date AS hoy
                ),
                stock_por_producto AS (
                    SELECT
                        l.producto_id,
                        COALESCE(SUM(
                            CASE
                                WHEN l.estado = 'DISPONIBLE' AND l.fecha_vencimiento >= f.hoy
                                THEN l.cantidad_actual
                                ELSE 0
                            END
                        ), 0) AS stock_vigente
                    FROM lotes l
                    CROSS JOIN fecha_cl f
                    GROUP BY l.producto_id
                )
                SELECT
                    l.id,
                    l.producto_id,
                    l.equipo_frio_id,
                    l.numero_lote,
                    l.fecha_vencimiento,
                    l.cantidad_inicial,
                    l.cantidad_actual,
                    l.estado,
                    p.codigo_barras,
                    p.nombre AS producto_nombre,
                    p.familia,
                    p.presentacion,
                    p.unidad_medida,
                    p.requiere_frio,
                    p.stock_minimo,
                    e.nombre AS equipo_frio_nombre,
                    f.hoy AS hoy_cl,
                    (l.fecha_vencimiento - f.hoy)::int AS dias_para_vencer,
                    COALESCE(sp.stock_vigente, 0)::int AS stock_vigente_producto
                FROM lotes l
                JOIN productos p ON p.id = l.producto_id
                LEFT JOIN equipos_frio e ON e.id = l.equipo_frio_id
                LEFT JOIN stock_por_producto sp ON sp.producto_id = p.id
                CROSS JOIN fecha_cl f
                WHERE p.activo = TRUE
                  AND l.estado <> 'BAJA'
                ORDER BY p.familia ASC, p.nombre ASC, l.fecha_vencimiento ASC, l.id ASC
                """
            )
            rows = cur.fetchall()

            cur.execute("SELECT (NOW() AT TIME ZONE 'America/Santiago')::date AS hoy")
            hoy_cl = cur.fetchone()["hoy"]

    lotes = []
    contadores = {"disponibles": 0, "vencidos": 0, "cuarentena": 0, "agotados": 0}

    for r in rows:
        dias = r["dias_para_vencer"]
        vencido = dias < 0
        proximo = (not vencido) and (dias <= 30)
        stock_bajo = r["stock_vigente_producto"] <= r["stock_minimo"]

        if r["estado"] == "CUARENTENA":
            contadores["cuarentena"] += 1
        elif vencido and r["cantidad_actual"] > 0:
            contadores["vencidos"] += 1
        elif r["estado"] == "DISPONIBLE" and not vencido and r["cantidad_actual"] > 0:
            contadores["disponibles"] += 1
        elif r["estado"] == "AGOTADO" and not vencido:
            contadores["agotados"] += 1

        lotes.append(
            {
                "id": r["id"],
                "producto_id": r["producto_id"],
                "equipo_frio_id": r["equipo_frio_id"],
                "equipo_frio_nombre": r["equipo_frio_nombre"],
                "codigo_barras": r["codigo_barras"],
                "producto_nombre": r["producto_nombre"],
                "familia": r["familia"],
                "presentacion": r["presentacion"],
                "unidad_medida": r["unidad_medida"],
                "requiere_frio": r["requiere_frio"],
                "stock_minimo": r["stock_minimo"],
                "stock_vigente_producto": r["stock_vigente_producto"],
                "stock_bajo": stock_bajo,
                "numero_lote": r["numero_lote"],
                "fecha_vencimiento": _iso_date(r["fecha_vencimiento"]),
                "cantidad_inicial": r["cantidad_inicial"],
                "cantidad_actual": r["cantidad_actual"],
                "estado": r["estado"],
                "dias_para_vencer": dias,
                "vencido": vencido,
                "proximo_vencer": proximo,
            }
        )

    return jsonify(
        {
            "hoy_cl": _iso_date(hoy_cl),
            "familias": list(FAMILIAS_PRODUCTO),
            "unidades": list(UNIDADES_MEDIDA),
            "contadores": contadores,
            "lotes": lotes,
        }
    ), 200


@app.get("/api/productos/buscar")
@login_required
def api_buscar_producto():
    """Busca un producto por código de barras y devuelve sus lotes vigentes en orden FEFO."""
    codigo = _clean_text(request.args.get("codigo"), 64)
    if not codigo:
        return jsonify({"error": "Debe ingresar o escanear un código de barras."}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, codigo_barras, nombre, familia, presentacion,
                       unidad_medida, requiere_frio, stock_minimo, activo
                FROM productos
                WHERE codigo_barras = %s
                """,
                (codigo,),
            )
            prod = cur.fetchone()
            if not prod:
                return jsonify({"existe": False, "codigo_barras": codigo}), 200

            cur.execute(
                """
                WITH fecha_cl AS (
                    SELECT (NOW() AT TIME ZONE 'America/Santiago')::date AS hoy
                )
                SELECT
                    l.id, l.numero_lote, l.fecha_vencimiento, l.cantidad_actual,
                    l.estado, l.equipo_frio_id,
                    (l.fecha_vencimiento - f.hoy)::int AS dias_para_vencer
                FROM lotes l
                CROSS JOIN fecha_cl f
                WHERE l.producto_id = %s
                  AND l.estado <> 'BAJA'
                ORDER BY l.fecha_vencimiento ASC, l.id ASC
                """,
                (prod["id"],),
            )
            todos_lotes = cur.fetchall()

    disponibles = []
    bloqueados = {"vencidos": 0, "cuarentena": 0}
    for l in todos_lotes:
        if l["estado"] == "CUARENTENA":
            bloqueados["cuarentena"] += 1
        elif l["dias_para_vencer"] < 0 and l["cantidad_actual"] > 0:
            bloqueados["vencidos"] += 1
        elif l["estado"] == "DISPONIBLE" and l["dias_para_vencer"] >= 0 and l["cantidad_actual"] > 0:
            disponibles.append(
                {
                    "id": l["id"],
                    "numero_lote": l["numero_lote"],
                    "fecha_vencimiento": _iso_date(l["fecha_vencimiento"]),
                    "cantidad_actual": l["cantidad_actual"],
                    "dias_para_vencer": l["dias_para_vencer"],
                }
            )

    return jsonify(
        {
            "existe": True,
            "producto": dict(prod),
            "lotes_disponibles": disponibles,
            "bloqueados": bloqueados,
        }
    ), 200


@app.get("/api/productos")
@role_required("BODEGA")
def api_listar_productos():
    """Catálogo completo de productos para mantenedor de Bodega (CU-04)."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, codigo_barras, nombre, familia, presentacion,
                       unidad_medida, requiere_frio, stock_minimo, activo
                FROM productos
                ORDER BY familia ASC, nombre ASC
                """
            )
            productos = [dict(r) for r in cur.fetchall()]
    return jsonify({"productos": productos}), 200


@app.put("/api/productos/<int:producto_id>")
@role_required("BODEGA")
def api_editar_producto(producto_id: int):
    """Edita datos fijos de un producto del catálogo (CU-04, RF-05)."""
    data = _get_json()
    if data is None:
        return jsonify({"error": "Formato JSON requerido."}), 400

    nombre = _clean_text(data.get("nombre"), 150)
    familia = _clean_text(data.get("familia"), 80)
    presentacion = _clean_text(data.get("presentacion"), 60)
    unidad_medida = _clean_text(data.get("unidad_medida"), 30).upper()
    stock_minimo = _parse_int(data.get("stock_minimo"), minimo=0, maximo=1000000)
    requiere_frio = bool(data.get("requiere_frio", False))
    activo = bool(data.get("activo", True))

    if not nombre or not presentacion:
        return jsonify({"error": "Nombre y presentación son obligatorios."}), 400
    if familia not in FAMILIAS_PRODUCTO:
        return jsonify({"error": "Familia fuera del catálogo permitido."}), 400
    if unidad_medida not in UNIDADES_MEDIDA:
        return jsonify({"error": "Unidad de medida no permitida."}), 400
    if stock_minimo is None:
        return jsonify({"error": "Stock mínimo debe ser un entero mayor o igual a 0."}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE productos
                SET nombre = %s,
                    familia = %s,
                    presentacion = %s,
                    unidad_medida = %s,
                    requiere_frio = %s,
                    stock_minimo = %s,
                    activo = %s
                WHERE id = %s
                RETURNING id
                """,
                (nombre, familia, presentacion, unidad_medida, requiere_frio, stock_minimo, activo, producto_id),
            )
            if not cur.fetchone():
                return jsonify({"error": "Producto no encontrado."}), 404
        conn.commit()

    return jsonify({"ok": True, "mensaje": "Producto actualizado correctamente."}), 200


@app.post("/api/bodega/ingresos")
@role_required("BODEGA")
def api_bodega_ingreso():
    """Ingreso de producto nuevo o lote existente en Bodega (CU-03, RF-05, RF-06, RF-07)."""
    data = _get_json()
    if data is None:
        return jsonify({"error": "Formato JSON requerido."}), 400

    if data.get("confirmado") is not True:
        return jsonify({"error": "Debe marcar la casilla de revisión antes de confirmar."}), 400

    codigo_barras = _clean_text(data.get("codigo_barras"), 64)
    numero_lote = _clean_text(data.get("numero_lote"), 60)
    cantidad = _parse_int(data.get("cantidad"), minimo=1, maximo=1000000)
    fecha_venc = _parse_date_iso(data.get("fecha_vencimiento"))

    if not codigo_barras or not numero_lote:
        return jsonify({"error": "Código de barras y número de lote son obligatorios."}), 400
    if cantidad is None:
        return jsonify({"error": "La cantidad debe ser un entero mayor a 0."}), 400
    if fecha_venc is None:
        return jsonify({"error": "Fecha de vencimiento inválida (formato YYYY-MM-DD)."}), 400

    usuario_id = session["user_id"]

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT (NOW() AT TIME ZONE 'America/Santiago')::date AS hoy")
            hoy_cl = cur.fetchone()["hoy"]

            if fecha_venc < hoy_cl:
                return jsonify({"error": "No se puede ingresar un lote ya vencido."}), 400

            cur.execute(
                """
                SELECT id, requiere_frio, activo
                FROM productos
                WHERE codigo_barras = %s
                FOR UPDATE
                """,
                (codigo_barras,),
            )
            prod = cur.fetchone()

            if prod is None:
                # Producto nuevo (RF-05)
                nombre = _clean_text(data.get("nombre"), 150)
                familia = _clean_text(data.get("familia"), 80)
                presentacion = _clean_text(data.get("presentacion"), 60)
                unidad_medida = _clean_text(data.get("unidad_medida"), 30).upper()
                stock_minimo = _parse_int(data.get("stock_minimo", 0), minimo=0, maximo=1000000)
                requiere_frio = bool(data.get("requiere_frio", False))

                if not nombre or not presentacion:
                    return jsonify({"error": "Nombre y presentación son obligatorios para un producto nuevo."}), 400
                if familia not in FAMILIAS_PRODUCTO:
                    return jsonify({"error": "Seleccione una familia válida del catálogo."}), 400
                if unidad_medida not in UNIDADES_MEDIDA:
                    return jsonify({"error": "Seleccione una unidad de medida válida."}), 400
                if stock_minimo is None:
                    return jsonify({"error": "Stock mínimo inválido."}), 400

                cur.execute(
                    """
                    INSERT INTO productos
                        (codigo_barras, nombre, familia, presentacion, unidad_medida, requiere_frio, stock_minimo)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id, requiere_frio
                    """,
                    (codigo_barras, nombre, familia, presentacion, unidad_medida, requiere_frio, stock_minimo),
                )
                prod = cur.fetchone()
            elif not prod["activo"]:
                return jsonify({"error": "El producto se encuentra deshabilitado."}), 409

            # Validar equipo de frío si requiere_frio = TRUE (Sección 9, Tabla 4)
            equipo_frio_id = None
            if prod["requiere_frio"]:
                equipo_frio_id = _parse_int(data.get("equipo_frio_id"), minimo=1)
                if equipo_frio_id is None:
                    return jsonify({"error": "Este producto requiere frío: seleccione un equipo operativo."}), 400
                cur.execute(
                    "SELECT id FROM equipos_frio WHERE id = %s AND activo = TRUE",
                    (equipo_frio_id,),
                )
                if not cur.fetchone():
                    return jsonify({"error": "El equipo de frío seleccionado no existe o está inactivo."}), 400

            # Verificar unicidad UNIQUE (producto_id, numero_lote) (RF-06)
            cur.execute(
                """
                SELECT id, fecha_vencimiento, estado, equipo_frio_id
                FROM lotes
                WHERE producto_id = %s AND numero_lote = %s
                FOR UPDATE
                """,
                (prod["id"], numero_lote),
            )
            lote_existente = cur.fetchone()

            if lote_existente:
                if lote_existente["estado"] in ("BAJA", "CUARENTENA"):
                    return jsonify(
                        {
                            "error": (
                                f"El lote {numero_lote} está en estado {lote_existente['estado']} "
                                "y no admite nuevos ingresos."
                            )
                        }
                    ), 409
                if lote_existente["fecha_vencimiento"] < hoy_cl:
                    return jsonify(
                        {"error": f"El lote {numero_lote} ya se encuentra vencido y no admite ingresos."}
                    ), 409
                if lote_existente["fecha_vencimiento"] != fecha_venc:
                    return jsonify(
                        {
                            "error": (
                                f"El lote {numero_lote} ya existe con fecha "
                                f"{lote_existente['fecha_vencimiento'].isoformat()}; "
                                "no puede ingresarse con una fecha distinta."
                            )
                        }
                    ), 409
                if prod["requiere_frio"] and lote_existente["equipo_frio_id"] != equipo_frio_id:
                    return jsonify(
                        {"error": f"El lote {numero_lote} ya está asignado a otro equipo de frío."}
                    ), 409

                cur.execute(
                    """
                    UPDATE lotes
                    SET cantidad_inicial = cantidad_inicial + %s,
                        cantidad_actual = cantidad_actual + %s,
                        estado = 'DISPONIBLE'
                    WHERE id = %s
                    RETURNING id
                    """,
                    (cantidad, cantidad, lote_existente["id"]),
                )
                lote_id = cur.fetchone()["id"]
                accion = "sumado"
            else:
                cur.execute(
                    """
                    INSERT INTO lotes
                        (producto_id, equipo_frio_id, numero_lote, fecha_vencimiento,
                         cantidad_inicial, cantidad_actual, estado)
                    VALUES (%s, %s, %s, %s, %s, %s, 'DISPONIBLE')
                    RETURNING id
                    """,
                    (prod["id"], equipo_frio_id, numero_lote, fecha_venc, cantidad, cantidad),
                )
                lote_id = cur.fetchone()["id"]
                accion = "creado"

            cur.execute(
                """
                INSERT INTO movimientos (lote_id, usuario_id, tipo_movimiento, cantidad, observacion)
                VALUES (%s, %s, 'ENTRADA', %s, %s)
                """,
                (lote_id, usuario_id, cantidad, _clean_text(data.get("observacion"), 300) or None),
            )
        conn.commit()

    return jsonify(
        {
            "ok": True,
            "lote_id": lote_id,
            "mensaje": f"Ingreso confirmado: lote {numero_lote} {accion} (+{cantidad}).",
        }
    ), 201


@app.post("/api/salidas")
@role_required("TENS")
def api_salida_fefo():
    """Descuento clínico atómico de un lote vigente (CU-05, RF-02, RF-03, A10:2025)."""
    data = _get_json()
    if data is None:
        return jsonify({"error": "Formato JSON requerido."}), 400

    lote_id = _parse_int(data.get("lote_id"), minimo=1)
    cantidad = _parse_int(data.get("cantidad", 1), minimo=1, maximo=100000)

    if lote_id is None or cantidad is None:
        return jsonify({"error": "Lote y cantidad válida (mínimo 1) son obligatorios."}), 400

    usuario_id = session["user_id"]

    with get_db() as conn:
        with conn.cursor() as cur:
            # Actualización atómica contra concurrencia y bloqueo de vencidos/cuarentena/baja
            cur.execute(
                """
                UPDATE lotes
                SET cantidad_actual = cantidad_actual - %s,
                    estado = CASE WHEN cantidad_actual - %s = 0 THEN 'AGOTADO' ELSE estado END
                WHERE id = %s
                  AND estado = 'DISPONIBLE'
                  AND fecha_vencimiento >= (NOW() AT TIME ZONE 'America/Santiago')::date
                  AND cantidad_actual >= %s
                RETURNING id, numero_lote, cantidad_actual, estado
                """,
                (cantidad, cantidad, lote_id, cantidad),
            )
            actualizado = cur.fetchone()

            if not actualizado:
                conn.rollback()
                return jsonify(
                    {
                        "error": (
                            "No se pudo descontar: el lote está vencido, en cuarentena, "
                            "en baja o no tiene stock suficiente."
                        )
                    }
                ), 409

            cur.execute(
                """
                INSERT INTO movimientos (lote_id, usuario_id, tipo_movimiento, cantidad)
                VALUES (%s, %s, 'SALIDA', %s)
                """,
                (lote_id, usuario_id, cantidad),
            )
        conn.commit()

    return jsonify(
        {
            "ok": True,
            "lote_id": actualizado["id"],
            "cantidad_actual": actualizado["cantidad_actual"],
            "estado": actualizado["estado"],
            "mensaje": f"Salida registrada (-{cantidad}) en lote {actualizado['numero_lote']}.",
        }
    ), 200


@app.post("/api/lotes/<int:lote_id>/ajustar")
@role_required("BODEGA")
def api_ajustar_lote(lote_id: int):
    """Ajuste de stock por Bodega con motivo obligatorio (CU-08, RF-09)."""
    data = _get_json()
    if data is None:
        return jsonify({"error": "Formato JSON requerido."}), 400

    nueva_cantidad = _parse_int(data.get("nueva_cantidad"), minimo=0, maximo=1000000)
    observacion = _clean_text(data.get("observacion"), 500)

    if nueva_cantidad is None:
        return jsonify({"error": "La nueva cantidad debe ser un entero mayor o igual a 0."}), 400
    if not observacion:
        return jsonify({"error": "Debe escribir el motivo del ajuste en observación."}), 400

    usuario_id = session["user_id"]

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, numero_lote, cantidad_actual, estado, fecha_vencimiento,
                       (NOW() AT TIME ZONE 'America/Santiago')::date AS hoy_cl
                FROM lotes
                WHERE id = %s
                FOR UPDATE
                """,
                (lote_id,),
            )
            lote = cur.fetchone()
            if not lote:
                return jsonify({"error": "Lote no encontrado."}), 404
            if lote["estado"] == "BAJA":
                return jsonify({"error": "Un lote en BAJA es terminal y no se puede ajustar."}), 409
            if lote["estado"] == "CUARENTENA":
                return jsonify({"error": "Un lote en CUARENTENA debe resolverse desde la pestaña Cuarentena."}), 409
            if lote["fecha_vencimiento"] < lote["hoy_cl"]:
                return jsonify({"error": "Un lote vencido no se puede ajustar; solo permite baja lógica."}), 409

            diferencia = nueva_cantidad - lote["cantidad_actual"]
            if diferencia == 0:
                return jsonify({"error": "La nueva cantidad es igual al stock actual."}), 400

            tipo_mov = "AJUSTE_MAS" if diferencia > 0 else "AJUSTE_MENOS"
            nuevo_estado = "AGOTADO" if nueva_cantidad == 0 else "DISPONIBLE"

            cur.execute(
                """
                UPDATE lotes
                SET cantidad_actual = %s, estado = %s
                WHERE id = %s
                """,
                (nueva_cantidad, nuevo_estado, lote_id),
            )
            cur.execute(
                """
                INSERT INTO movimientos (lote_id, usuario_id, tipo_movimiento, cantidad, observacion)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (lote_id, usuario_id, tipo_mov, abs(diferencia), observacion),
            )
        conn.commit()

    return jsonify(
        {
            "ok": True,
            "mensaje": f"Ajuste ({tipo_mov}) aplicado en lote {lote['numero_lote']}.",
        }
    ), 200


@app.post("/api/lotes/<int:lote_id>/baja")
@role_required("BODEGA")
def api_baja_lote(lote_id: int):
    """Baja lógica irreversible sin eliminación física (CU-08, CU-09, RF-09, RF-11)."""
    data = _get_json()
    if data is None:
        return jsonify({"error": "Formato JSON requerido."}), 400

    observacion = _clean_text(data.get("observacion"), 500)
    if not observacion:
        return jsonify({"error": "Debe indicar el motivo obligatorio para dar de baja."}), 400

    usuario_id = session["user_id"]

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, numero_lote, cantidad_actual, estado FROM lotes WHERE id = %s FOR UPDATE",
                (lote_id,),
            )
            lote = cur.fetchone()
            if not lote:
                return jsonify({"error": "Lote no encontrado."}), 404
            if lote["estado"] == "BAJA":
                return jsonify({"error": "El lote ya se encuentra en estado BAJA."}), 409

            cur.execute(
                "UPDATE lotes SET estado = 'BAJA', cantidad_actual = 0 WHERE id = %s",
                (lote_id,),
            )
            cur.execute(
                """
                INSERT INTO movimientos (lote_id, usuario_id, tipo_movimiento, cantidad, observacion)
                VALUES (%s, %s, 'BAJA', %s, %s)
                """,
                (lote_id, usuario_id, lote["cantidad_actual"], observacion),
            )
        conn.commit()

    return jsonify({"ok": True, "mensaje": f"Lote {lote['numero_lote']} dado de baja definitivamente."}), 200


@app.post("/api/lotes/<int:lote_id>/liberar")
@role_required("BODEGA")
def api_liberar_cuarentena(lote_id: int):
    """Libera un lote desde CUARENTENA tras evaluación técnica con motivo obligatorio (CU-09, RF-11)."""
    data = _get_json()
    if data is None:
        return jsonify({"error": "Formato JSON requerido."}), 400

    observacion = _clean_text(data.get("observacion"), 500)
    if not observacion:
        return jsonify({"error": "Debe ingresar la justificación técnica para liberar de cuarentena."}), 400

    usuario_id = session["user_id"]

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, numero_lote, cantidad_actual, estado FROM lotes WHERE id = %s FOR UPDATE",
                (lote_id,),
            )
            lote = cur.fetchone()
            if not lote:
                return jsonify({"error": "Lote no encontrado."}), 404
            if lote["estado"] != "CUARENTENA":
                return jsonify({"error": "Solo se pueden liberar lotes en estado CUARENTENA."}), 409

            nuevo_estado = "DISPONIBLE" if lote["cantidad_actual"] > 0 else "AGOTADO"
            cur.execute("UPDATE lotes SET estado = %s WHERE id = %s", (nuevo_estado, lote_id))
            cur.execute(
                """
                INSERT INTO movimientos (lote_id, usuario_id, tipo_movimiento, cantidad, observacion)
                VALUES (%s, %s, 'LIBERACION', %s, %s)
                """,
                (lote_id, usuario_id, lote["cantidad_actual"], observacion),
            )
        conn.commit()

    return jsonify({"ok": True, "mensaje": f"Lote {lote['numero_lote']} liberado a {nuevo_estado}."}), 200


# ============================================================
# MÓDULO 3: CADENA DE FRÍO (CU-04, CU-06, CU-07, RF-10, RF-11, RF-14)
# ============================================================
@app.get("/api/equipos-frio")
@login_required
def api_equipos_frio():
    """Lista equipos de frío con su última lectura y detección de atraso en línea."""
    solo_activos = session.get("rol") != "BODEGA"

    with get_db() as conn:
        with conn.cursor() as cur:
            filtro = "WHERE e.activo = TRUE" if solo_activos else ""
            cur.execute(
                f"""
                SELECT
                    e.id, e.nombre, e.ubicacion, e.temp_min_c, e.temp_max_c, e.activo,
                    rf.temperatura_c AS ultima_temp_c,
                    rf.estado_alerta AS ultima_alerta,
                    rf.fecha_registro AS ultima_fecha,
                    EXTRACT(EPOCH FROM (NOW() - rf.fecha_registro)) / 3600.0 AS horas_desde_ultima,
                    (
                        SELECT COUNT(*) FROM lotes l
                        WHERE l.equipo_frio_id = e.id AND l.estado = 'DISPONIBLE' AND l.cantidad_actual > 0
                    )::int AS lotes_disponibles,
                    (
                        SELECT COUNT(*) FROM lotes l
                        WHERE l.equipo_frio_id = e.id AND l.estado = 'CUARENTENA'
                    )::int AS lotes_cuarentena
                FROM equipos_frio e
                LEFT JOIN LATERAL (
                    SELECT temperatura_c, estado_alerta, fecha_registro
                    FROM registros_frio
                    WHERE equipo_frio_id = e.id
                    ORDER BY fecha_registro DESC
                    LIMIT 1
                ) rf ON TRUE
                {filtro}
                ORDER BY e.activo DESC, e.id ASC
                """
            )
            rows = cur.fetchall()

    equipos = []
    for r in rows:
        horas = round(float(r["horas_desde_ultima"]), 1) if r["horas_desde_ultima"] is not None else None
        atrasado = (horas is not None) and (horas > FRIO_INTERVALO_HORAS)
        equipos.append(
            {
                "id": r["id"],
                "nombre": r["nombre"],
                "ubicacion": r["ubicacion"],
                "temp_min_c": float(r["temp_min_c"]),
                "temp_max_c": float(r["temp_max_c"]),
                "activo": r["activo"],
                "ultima_temp_c": float(r["ultima_temp_c"]) if r["ultima_temp_c"] is not None else None,
                "ultima_alerta": r["ultima_alerta"],
                "ultima_fecha": _iso_dt(r["ultima_fecha"]),
                "horas_desde_ultima": horas,
                "atrasado": atrasado,
                "lotes_disponibles": r["lotes_disponibles"],
                "lotes_cuarentena": r["lotes_cuarentena"],
            }
        )

    return jsonify({"intervalo_horas": FRIO_INTERVALO_HORAS, "equipos": equipos}), 200


@app.post("/api/equipos-frio")
@role_required("BODEGA")
def api_crear_equipo_frio():
    """Crea un equipo de frío en EQUIPOS_FRIO (RF-14, CU-04)."""
    data = _get_json()
    if data is None:
        return jsonify({"error": "Formato JSON requerido."}), 400

    nombre = _clean_text(data.get("nombre"), 100)
    ubicacion = _clean_text(data.get("ubicacion"), 100)
    tmin = _parse_temp(data.get("temp_min_c", 2.0))
    tmax = _parse_temp(data.get("temp_max_c", 8.0))

    if not nombre or not ubicacion:
        return jsonify({"error": "Nombre y ubicación son obligatorios."}), 400
    if tmin is None or tmax is None or tmax <= tmin:
        return jsonify({"error": "Rango de temperatura inválido (máxima debe ser mayor a mínima)."}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO equipos_frio (nombre, ubicacion, temp_min_c, temp_max_c, activo)
                VALUES (%s, %s, %s, %s, TRUE)
                RETURNING id
                """,
                (nombre, ubicacion, tmin, tmax),
            )
            nuevo_id = cur.fetchone()["id"]
        conn.commit()

    return jsonify({"ok": True, "id": nuevo_id, "mensaje": f"Equipo '{nombre}' creado."}), 201


@app.put("/api/equipos-frio/<int:equipo_id>")
@role_required("BODEGA")
def api_editar_equipo_frio(equipo_id: int):
    """Edita o habilita/deshabilita un equipo de frío (RF-14, CU-04)."""
    data = _get_json()
    if data is None:
        return jsonify({"error": "Formato JSON requerido."}), 400

    nombre = _clean_text(data.get("nombre"), 100)
    ubicacion = _clean_text(data.get("ubicacion"), 100)
    tmin = _parse_temp(data.get("temp_min_c"))
    tmax = _parse_temp(data.get("temp_max_c"))
    activo = bool(data.get("activo", True))

    if not nombre or not ubicacion:
        return jsonify({"error": "Nombre y ubicación son obligatorios."}), 400
    if tmin is None or tmax is None or tmax <= tmin:
        return jsonify({"error": "Rango de temperatura inválido (máxima debe ser mayor a mínima)."}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE equipos_frio
                SET nombre = %s, ubicacion = %s, temp_min_c = %s, temp_max_c = %s, activo = %s
                WHERE id = %s
                RETURNING id
                """,
                (nombre, ubicacion, tmin, tmax, activo, equipo_id),
            )
            if not cur.fetchone():
                return jsonify({"error": "Equipo de frío no encontrado."}), 404
        conn.commit()

    return jsonify({"ok": True, "mensaje": f"Equipo '{nombre}' actualizado."}), 200


@app.post("/api/registros-frio")
@role_required("TENS")
def api_registrar_frio():
    """Registra lectura térmica, evalúa VERDE/AMARILLA/ROJA y activa cuarentena automática (CU-06, CU-07)."""
    data = _get_json()
    if data is None:
        return jsonify({"error": "Formato JSON requerido."}), 400

    equipo_id = _parse_int(data.get("equipo_frio_id"), minimo=1)
    temperatura = _parse_temp(data.get("temperatura_c"))

    if equipo_id is None or temperatura is None:
        return jsonify({"error": "Debe seleccionar un equipo e ingresar una temperatura válida (°C)."}), 400

    usuario_id = session["user_id"]

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, nombre, temp_min_c, temp_max_c, activo
                FROM equipos_frio
                WHERE id = %s
                """,
                (equipo_id,),
            )
            equipo = cur.fetchone()
            if not equipo or not equipo["activo"]:
                return jsonify({"error": "El equipo de frío no existe o está inactivo."}), 404

            # Revisar atraso respecto a la lectura anterior
            cur.execute(
                """
                SELECT EXTRACT(EPOCH FROM (NOW() - fecha_registro)) / 3600.0 AS horas
                FROM registros_frio
                WHERE equipo_frio_id = %s
                ORDER BY fecha_registro DESC
                LIMIT 1
                """,
                (equipo_id,),
            )
            prev = cur.fetchone()
            atraso = bool(prev and float(prev["horas"]) > FRIO_INTERVALO_HORAS)

            tmin = equipo["temp_min_c"]
            tmax = equipo["temp_max_c"]
            margen = Decimal("0.5")

            # Regla de precedencia (CU-06 / RF-10): ROJA prevalece siempre
            if temperatura < tmin or temperatura > tmax:
                alerta = "ROJA"
            elif (temperatura - tmin) <= margen or (tmax - temperatura) <= margen or atraso:
                alerta = "AMARILLA"
            else:
                alerta = "VERDE"

            cur.execute(
                """
                INSERT INTO registros_frio (equipo_frio_id, usuario_id, temperatura_c, estado_alerta)
                VALUES (%s, %s, %s, %s)
                RETURNING id, fecha_registro
                """,
                (equipo_id, usuario_id, temperatura, alerta),
            )
            reg = cur.fetchone()

            lotes_bloqueados = 0
            if alerta == "ROJA":
                # CU-07: Cuarentena automática de lotes DISPONIBLE asociados al equipo
                cur.execute(
                    """
                    UPDATE lotes
                    SET estado = 'CUARENTENA'
                    WHERE equipo_frio_id = %s
                      AND estado = 'DISPONIBLE'
                      AND cantidad_actual > 0
                    RETURNING id, cantidad_actual
                    """,
                    (equipo_id,),
                )
                afectados = cur.fetchall()
                lotes_bloqueados = len(afectados)
                obs_cuarentena = (
                    f"Cuarentena automática por alerta roja en {equipo['nombre']} "
                    f"({temperatura} °C; rango {tmin}–{tmax} °C)."
                )
                for l in afectados:
                    cur.execute(
                        """
                        INSERT INTO movimientos
                            (lote_id, usuario_id, registro_frio_id, tipo_movimiento, cantidad, observacion)
                        VALUES (%s, %s, %s, 'CUARENTENA', %s, %s)
                        """,
                        (l["id"], usuario_id, reg["id"], l["cantidad_actual"], obs_cuarentena),
                    )
        conn.commit()

    if alerta == "ROJA":
        mensaje = (
            f"Alerta ROJA ({temperatura} °C): {lotes_bloqueados} lote(s) pasaron "
            "automáticamente a CUARENTENA."
        )
    elif alerta == "AMARILLA":
        mensaje = (
            f"Alerta AMARILLA ({temperatura} °C): cerca del límite o lectura atrasada. "
            "Volver a medir en 1 a 2 horas."
        )
    else:
        mensaje = f"Alerta VERDE ({temperatura} °C): temperatura dentro de rango seguro."

    return jsonify(
        {
            "ok": True,
            "registro_id": reg["id"],
            "estado_alerta": alerta,
            "lotes_cuarentena": lotes_bloqueados,
            "mensaje": mensaje,
        }
    ), 201


# ============================================================
# MÓDULO 4: HISTORIAL Y AUDITORÍA (CU-10, RF-12 — SOLO BODEGA)
# ============================================================
@app.get("/api/historial")
@role_required("BODEGA")
def api_historial():
    """Historial solo lectura de movimientos y registros térmicos (403 para TENS)."""
    tipo = _clean_text(request.args.get("tipo"), 20).upper()
    producto_q = _clean_text(request.args.get("producto"), 100)
    desde = _parse_date_iso(request.args.get("desde"))
    hasta = _parse_date_iso(request.args.get("hasta"))

    condiciones = []
    params = []

    if tipo and tipo in TIPOS_MOVIMIENTO:
        condiciones.append("m.tipo_movimiento = %s")
        params.append(tipo)
    if producto_q:
        condiciones.append("(p.nombre ILIKE %s OR l.numero_lote ILIKE %s)")
        patron = f"%{producto_q}%"
        params.extend([patron, patron])
    if desde:
        condiciones.append("(m.fecha_registro AT TIME ZONE 'America/Santiago')::date >= %s")
        params.append(desde)
    if hasta:
        condiciones.append("(m.fecha_registro AT TIME ZONE 'America/Santiago')::date <= %s")
        params.append(hasta)

    where_sql = ("WHERE " + " AND ".join(condiciones)) if condiciones else ""

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT
                    m.id,
                    m.tipo_movimiento,
                    m.cantidad,
                    m.observacion,
                    m.fecha_registro,
                    m.registro_frio_id,
                    l.numero_lote,
                    p.nombre AS producto_nombre,
                    p.presentacion,
                    u.nombre AS usuario_nombre,
                    u.rol AS usuario_rol
                FROM movimientos m
                JOIN lotes l ON l.id = m.lote_id
                JOIN productos p ON p.id = l.producto_id
                JOIN usuarios u ON u.id = m.usuario_id
                {where_sql}
                ORDER BY m.fecha_registro DESC, m.id DESC
                LIMIT 250
                """,
                params,
            )
            movs = [
                {
                    "id": r["id"],
                    "fecha_registro": _iso_dt(r["fecha_registro"]),
                    "usuario_nombre": r["usuario_nombre"],
                    "usuario_rol": r["usuario_rol"],
                    "tipo_movimiento": r["tipo_movimiento"],
                    "producto_nombre": r["producto_nombre"],
                    "presentacion": r["presentacion"],
                    "numero_lote": r["numero_lote"],
                    "cantidad": r["cantidad"],
                    "observacion": r["observacion"] or "",
                    "registro_frio_id": r["registro_frio_id"],
                }
                for r in cur.fetchall()
            ]

            cur.execute(
                """
                SELECT
                    rf.id,
                    rf.temperatura_c,
                    rf.estado_alerta,
                    rf.fecha_registro,
                    e.nombre AS equipo_nombre,
                    e.ubicacion,
                    u.nombre AS usuario_nombre
                FROM registros_frio rf
                JOIN equipos_frio e ON e.id = rf.equipo_frio_id
                JOIN usuarios u ON u.id = rf.usuario_id
                ORDER BY rf.fecha_registro DESC, rf.id DESC
                LIMIT 100
                """
            )
            frios = [
                {
                    "id": r["id"],
                    "fecha_registro": _iso_dt(r["fecha_registro"]),
                    "equipo_nombre": r["equipo_nombre"],
                    "ubicacion": r["ubicacion"],
                    "usuario_nombre": r["usuario_nombre"],
                    "temperatura_c": float(r["temperatura_c"]),
                    "estado_alerta": r["estado_alerta"],
                }
                for r in cur.fetchall()
            ]

    return jsonify({"movimientos": movs, "registros_frio": frios}), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)