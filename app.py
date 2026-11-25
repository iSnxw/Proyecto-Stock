import os
from datetime import datetime, timedelta, timezone
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash

from db import get_connection

load_dotenv()

app = Flask(__name__)

secret_key = os.getenv("SECRET_KEY")
if not secret_key:
    raise ValueError("Falta SECRET_KEY en el archivo .env")

app.config["SECRET_KEY"] = secret_key
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("FLASK_ENV") == "production"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

csrf = CSRFProtect(app)

# Control de fuerza bruta (máximo 5 intentos -> bloqueo de 5 min)
MAX_INTENTOS_LOGIN = 5
MINUTOS_BLOQUEO = 5
intentos_fallidos = {}


def _clave_intento(correo):
    ip = request.remote_addr or "local"
    return f"{ip}|{correo}"


def _esta_bloqueado(clave):
    registro = intentos_fallidos.get(clave)
    if not registro:
        return False
    bloqueado_hasta = registro.get("bloqueado_hasta")
    if bloqueado_hasta and datetime.now(timezone.utc) < bloqueado_hasta:
        return True
    if bloqueado_hasta and datetime.now(timezone.utc) >= bloqueado_hasta:
        intentos_fallidos.pop(clave, None)
    return False


def _registrar_fallo(clave):
    registro = intentos_fallidos.get(clave, {"conteo": 0, "bloqueado_hasta": None})
    registro["conteo"] += 1
    if registro["conteo"] >= MAX_INTENTOS_LOGIN:
        registro["bloqueado_hasta"] = datetime.now(timezone.utc) + timedelta(
            minutes=MINUTOS_BLOQUEO
        )
    intentos_fallidos[clave] = registro


@app.before_request
def cargar_usuario_sesion():
    """Valida en cada petición que el usuario siga activo en Neon."""
    g.usuario = None
    usuario_id = session.get("usuario_id")
    if not usuario_id:
        return

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, nombre, correo, rol, activo
                FROM usuarios
                WHERE id = %s;
                """,
                (usuario_id,),
            )
            usuario = cur.fetchone()
    finally:
        conn.close()

    if not usuario or not usuario["activo"]:
        session.clear()
        return

    g.usuario = usuario


@app.after_request
def agregar_cabeceras_seguridad(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self';"
    )
    return response


def login_requerido(vista):
    @wraps(vista)
    def envuelta(*args, **kwargs):
        if g.usuario is None:
            flash("Debes iniciar sesión para continuar.", "aviso")
            return redirect(url_for("login"))
        return vista(*args, **kwargs)

    return envuelta


def rol_requerido(*roles_permitidos):
    def decorador(vista):
        @wraps(vista)
        def envuelta(*args, **kwargs):
            if g.usuario is None:
                flash("Debes iniciar sesión para continuar.", "aviso")
                return redirect(url_for("login"))
            if g.usuario["rol"] not in roles_permitidos:
                abort(403)
            return vista(*args, **kwargs)

        return envuelta

    return decorador


@app.route("/")
def inicio():
    if g.usuario:
        return redirect(url_for("panel"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.usuario:
        return redirect(url_for("panel"))

    if request.method == "POST":
        correo = request.form.get("correo", "").strip().lower()
        clave = request.form.get("password", "")
        clave_bloqueo = _clave_intento(correo)

        if _esta_bloqueado(clave_bloqueo):
            flash(
                f"Demasiados intentos fallidos. Espera {MINUTOS_BLOQUEO} minutos.",
                "error",
            )
            return render_template("login.html"), 429

        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, nombre, correo, password_hash, rol, activo
                    FROM usuarios
                    WHERE LOWER(correo) = %s;
                    """,
                    (correo,),
                )
                usuario = cur.fetchone()
        finally:
            conn.close()

        credenciales_validas = (
            usuario is not None
            and usuario["activo"]
            and check_password_hash(usuario["password_hash"], clave)
        )

        if not credenciales_validas:
            _registrar_fallo(clave_bloqueo)
            flash("Correo o contraseña incorrectos.", "error")
            return render_template("login.html"), 401

        intentos_fallidos.pop(clave_bloqueo, None)
        session.clear()
        session.permanent = True
        session["usuario_id"] = usuario["id"]
        flash(f"Bienvenido/a, {usuario['nombre']}.", "ok")
        return redirect(url_for("panel"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_requerido
def logout():
    session.clear()
    flash("Sesión cerrada correctamente.", "ok")
    return redirect(url_for("login"))


@app.route("/panel")
@login_requerido
def panel():
    return render_template("panel.html")


@app.route("/producto")
@rol_requerido("TENS", "BODEGA")
def gestion_producto():
    codigo_buscado = request.args.get("codigo", "").strip()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            if codigo_buscado:
                cur.execute(
                    """
                    SELECT
                        l.id,
                        l.numero_lote,
                        l.fecha_vencimiento,
                        l.cantidad_actual,
                        p.codigo_barras,
                        p.nombre AS producto_nombre,
                        p.familia,
                        p.presentacion,
                        p.unidad_medida
                    FROM lotes l
                    JOIN productos p ON p.id = l.producto_id
                    WHERE l.estado = 'DISPONIBLE'
                      AND l.cantidad_actual > 0
                      AND p.activo = TRUE
                      AND p.codigo_barras = %s
                    ORDER BY l.fecha_vencimiento ASC, l.id ASC;
                    """,
                    (codigo_buscado,),
                )
            else:
                cur.execute(
                    """
                    SELECT
                        l.id,
                        l.numero_lote,
                        l.fecha_vencimiento,
                        l.cantidad_actual,
                        p.codigo_barras,
                        p.nombre AS producto_nombre,
                        p.familia,
                        p.presentacion,
                        p.unidad_medida
                    FROM lotes l
                    JOIN productos p ON p.id = l.producto_id
                    WHERE l.estado = 'DISPONIBLE'
                      AND l.cantidad_actual > 0
                      AND p.activo = TRUE
                    ORDER BY l.fecha_vencimiento ASC, p.nombre ASC;
                    """
                )
            lotes = cur.fetchall()
    finally:
        conn.close()

    return render_template(
        "producto.html",
        lotes=lotes,
        codigo_buscado=codigo_buscado,
    )


@app.route("/producto/descontar", methods=["POST"])
@rol_requerido("TENS", "BODEGA")
def descontar_lote():
    lote_id_str = request.form.get("lote_id", "").strip()
    cantidad_str = request.form.get("cantidad", "").strip()
    codigo_filtro = request.form.get("codigo_filtro", "").strip()

    if not lote_id_str.isdigit() or not cantidad_str.isdigit():
        flash("Datos de retiro inválidos.", "error")
        return redirect(url_for("gestion_producto", codigo=codigo_filtro))

    lote_id = int(lote_id_str)
    cantidad = int(cantidad_str)
    if cantidad <= 0:
        flash("La cantidad a retirar debe ser mayor a 0.", "error")
        return redirect(url_for("gestion_producto", codigo=codigo_filtro))

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT l.id, l.numero_lote, l.cantidad_actual, l.estado, p.nombre AS producto_nombre
                FROM lotes l
                JOIN productos p ON p.id = l.producto_id
                WHERE l.id = %s
                FOR UPDATE;
                """,
                (lote_id,),
            )
            lote = cur.fetchone()

            if not lote or lote["estado"] != "DISPONIBLE":
                flash("El lote no está disponible para retiro.", "error")
                return redirect(url_for("gestion_producto", codigo=codigo_filtro))

            if cantidad > lote["cantidad_actual"]:
                flash(
                    f"Stock insuficiente en el lote {lote['numero_lote']} (disponible: {lote['cantidad_actual']}).",
                    "error",
                )
                return redirect(url_for("gestion_producto", codigo=codigo_filtro))

            cur.execute(
                """
                UPDATE lotes
                SET cantidad_actual = cantidad_actual - %s
                WHERE id = %s;
                """,
                (cantidad, lote_id),
            )

            cur.execute(
                """
                INSERT INTO movimientos (
                    lote_id, usuario_id, tipo_movimiento, cantidad,
                    observacion, origen_offline, fecha_dispositivo
                )
                VALUES (%s, %s, 'SALIDA', %s, %s, FALSE, %s);
                """,
                (
                    lote_id,
                    g.usuario["id"],
                    cantidad,
                    f"Retiro clínico desde Gestión de Producto (lote {lote['numero_lote']})",
                    datetime.now(timezone.utc),
                ),
            )
            conn.commit()
            flash(
                f"Retiro registrado: -{cantidad} de {lote['producto_nombre']} (lote {lote['numero_lote']}).",
                "ok",
            )
    finally:
        conn.close()

    return redirect(url_for("gestion_producto", codigo=codigo_filtro))


@app.route("/bodega")
@rol_requerido("BODEGA")
def gestion_bodega():
    codigo_buscado = request.args.get("codigo", "").strip()
    producto_encontrado = None

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            if codigo_buscado:
                cur.execute(
                    """
                    SELECT id, codigo_barras, nombre, familia, presentacion, unidad_medida, requiere_frio
                    FROM productos
                    WHERE codigo_barras = %s AND activo = TRUE;
                    """,
                    (codigo_buscado,),
                )
                producto_encontrado = cur.fetchone()

            cur.execute(
                """
                SELECT id, codigo_barras, nombre, familia, presentacion, unidad_medida, requiere_frio
                FROM productos
                WHERE activo = TRUE
                ORDER BY familia, nombre;
                """
            )
            productos = cur.fetchall()

            cur.execute(
                """
                SELECT id, nombre, temp_min_c, temp_max_c
                FROM equipos_frio
                WHERE activo = TRUE
                ORDER BY nombre;
                """
            )
            equipos = cur.fetchall()

            cur.execute(
                """
                SELECT
                    l.id,
                    l.numero_lote,
                    l.fecha_vencimiento,
                    l.cantidad_actual,
                    l.estado,
                    p.nombre AS producto_nombre,
                    p.familia,
                    p.presentacion,
                    p.unidad_medida,
                    e.nombre AS equipo_nombre
                FROM lotes l
                JOIN productos p ON p.id = l.producto_id
                LEFT JOIN equipos_frio e ON e.id = l.equipo_frio_id
                ORDER BY l.fecha_vencimiento ASC, p.nombre ASC;
                """
            )
            lotes = cur.fetchall()
    finally:
        conn.close()

    return render_template(
        "bodega.html",
        productos=productos,
        equipos=equipos,
        lotes=lotes,
        codigo_buscado=codigo_buscado,
        producto_encontrado=producto_encontrado,
    )


@app.route("/bodega/productos", methods=["POST"])
@rol_requerido("BODEGA")
def crear_producto():
    codigo_barras = request.form.get("codigo_barras", "").strip()
    nombre = request.form.get("nombre", "").strip()
    familia = request.form.get("familia", "").strip()
    presentacion = request.form.get("presentacion", "").strip()
    unidad_medida = request.form.get("unidad_medida", "").strip().upper()
    stock_minimo_str = request.form.get("stock_minimo", "0").strip()
    requiere_frio = request.form.get("requiere_frio") == "si"

    if not codigo_barras or not nombre or not familia or not presentacion:
        flash("Completa todos los campos del producto nuevo.", "error")
        return redirect(url_for("gestion_bodega", codigo=codigo_barras))

    if unidad_medida not in ("UNIDAD", "CAJA", "FRASCO", "DOSIS"):
        flash("Unidad de medida no válida.", "error")
        return redirect(url_for("gestion_bodega", codigo=codigo_barras))

    if not stock_minimo_str.isdigit():
        flash("El stock mínimo debe ser un número entero mayor o igual a 0.", "error")
        return redirect(url_for("gestion_bodega", codigo=codigo_barras))

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM productos WHERE codigo_barras = %s;",
                (codigo_barras,),
            )
            if cur.fetchone():
                flash("Ya existe un producto con ese código de barras.", "error")
                return redirect(url_for("gestion_bodega", codigo=codigo_barras))

            cur.execute(
                """
                INSERT INTO productos (
                    codigo_barras, nombre, familia, presentacion,
                    unidad_medida, requiere_frio, stock_minimo
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s);
                """,
                (
                    codigo_barras,
                    nombre,
                    familia,
                    presentacion,
                    unidad_medida,
                    requiere_frio,
                    int(stock_minimo_str),
                ),
            )
            conn.commit()
            flash(f"Producto '{nombre}' creado. Ahora puedes ingresar su primer lote.", "ok")
    finally:
        conn.close()

    return redirect(url_for("gestion_bodega", codigo=codigo_barras))


@app.route("/bodega/lotes", methods=["POST"])
@rol_requerido("BODEGA")
def ingresar_lote():
    producto_id = request.form.get("producto_id", "").strip()
    numero_lote = request.form.get("numero_lote", "").strip().upper()
    fecha_str = request.form.get("fecha_vencimiento", "").strip()
    cantidad_str = request.form.get("cantidad", "").strip()
    equipo_frio_id = request.form.get("equipo_frio_id", "").strip() or None
    confirmacion = request.form.get("confirmacion")

    if confirmacion != "si":
        flash("Debes marcar la casilla de confirmación física antes de guardar.", "error")
        return redirect(url_for("gestion_bodega"))

    if not producto_id.isdigit() or not numero_lote or not cantidad_str.isdigit():
        flash("Completa todos los campos obligatorios con valores válidos.", "error")
        return redirect(url_for("gestion_bodega"))

    cantidad = int(cantidad_str)
    if cantidad <= 0:
        flash("La cantidad recibida debe ser mayor a 0.", "error")
        return redirect(url_for("gestion_bodega"))

    try:
        fecha_vencimiento = datetime.strptime(fecha_str, "%Y-%m-%d").date()
    except ValueError:
        flash("La fecha de vencimiento no es válida.", "error")
        return redirect(url_for("gestion_bodega"))

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, nombre, requiere_frio FROM productos WHERE id = %s AND activo = TRUE;",
                (int(producto_id),),
            )
            producto = cur.fetchone()
            if not producto:
                flash("El producto seleccionado no existe o está inactivo.", "error")
                return redirect(url_for("gestion_bodega"))

            if producto["requiere_frio"] and not equipo_frio_id:
                flash(
                    f"{producto['nombre']} requiere cadena de frío: selecciona un equipo de frío.",
                    "error",
                )
                return redirect(url_for("gestion_bodega"))

            if not producto["requiere_frio"]:
                equipo_frio_id = None

            cur.execute(
                "SELECT id FROM lotes WHERE producto_id = %s AND numero_lote = %s;",
                (int(producto_id), numero_lote),
            )
            if cur.fetchone():
                flash(f"El lote {numero_lote} ya existe para {producto['nombre']}.", "error")
                return redirect(url_for("gestion_bodega"))

            cur.execute(
                """
                INSERT INTO lotes (
                    producto_id, equipo_frio_id, numero_lote,
                    fecha_vencimiento, cantidad_inicial, cantidad_actual, estado
                )
                VALUES (%s, %s, %s, %s, %s, %s, 'DISPONIBLE')
                RETURNING id;
                """,
                (
                    int(producto_id),
                    int(equipo_frio_id) if equipo_frio_id else None,
                    numero_lote,
                    fecha_vencimiento,
                    cantidad,
                    cantidad,
                ),
            )
            nuevo_lote_id = cur.fetchone()["id"]

            # Trazabilidad: usuario_id siempre sale de la sesión (g.usuario)
            cur.execute(
                """
                INSERT INTO movimientos (
                    lote_id, usuario_id, tipo_movimiento, cantidad,
                    observacion, origen_offline, fecha_dispositivo
                )
                VALUES (%s, %s, 'ENTRADA', %s, %s, FALSE, %s);
                """,
                (
                    nuevo_lote_id,
                    g.usuario["id"],
                    cantidad,
                    f"Recepción inicial lote {numero_lote}",
                    datetime.now(timezone.utc),
                ),
            )
            conn.commit()
            flash(
                f"Lote {numero_lote} de {producto['nombre']} ingresado correctamente (+{cantidad}).",
                "ok",
            )
    finally:
        conn.close()

    return redirect(url_for("gestion_bodega"))


@app.route("/frio")
@rol_requerido("TENS", "BODEGA")
def gestion_frio():
    return render_template(
        "modulo_pendiente.html",
        titulo="Gestión de Frío",
        detalle="Módulo de control de temperatura y cuarentena. Lo implementaremos en el Paso 6.",
    )


@app.errorhandler(403)
def acceso_denegado(e):
    return render_template("error_403.html"), 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)