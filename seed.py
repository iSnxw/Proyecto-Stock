from werkzeug.security import generate_password_hash
from db import get_connection


def main():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 1. Usuarios de prueba (hash scrypt por defecto en Werkzeug)
            usuarios = [
                ("María González (TENS)", "tens@posta.cl", "Tens2026!", "TENS"),
                ("Carlos Pérez (Bodega)", "bodega@posta.cl", "Bodega2026!", "BODEGA"),
            ]
            for nombre, correo, clave, rol in usuarios:
                cur.execute(
                    """
                    INSERT INTO usuarios (nombre, correo, password_hash, rol)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (correo) DO NOTHING;
                    """,
                    (nombre, correo, generate_password_hash(clave), rol),
                )

            # 2. Equipo de frío inicial (2.0 °C a 8.0 °C)
            cur.execute(
                "SELECT id FROM equipos_frio WHERE nombre = %s;",
                ("Refri-01 Vacunatorio",),
            )
            if not cur.fetchone():
                cur.execute(
                    """
                    INSERT INTO equipos_frio (nombre, ubicacion, temp_min_c, temp_max_c)
                    VALUES (%s, %s, %s, %s);
                    """,
                    ("Refri-01 Vacunatorio", "Vacunatorio Posta", 2.0, 8.0),
                )

            # 3. Productos iniciales con familia, presentación y unidad separadas
            productos = [
                ("780123456001", "Paracetamol", "Analgésicos", "500 mg", "CAJA", False, 20),
                ("780123456002", "Vacuna Influenza", "Vacunas", "0.5 ml", "DOSIS", True, 10),
            ]
            for codigo, nombre, familia, presentacion, unidad, frio, minimo in productos:
                cur.execute(
                    """
                    INSERT INTO productos (
                        codigo_barras, nombre, familia, presentacion,
                        unidad_medida, requiere_frio, stock_minimo
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (codigo_barras) DO NOTHING;
                    """,
                    (codigo, nombre, familia, presentacion, unidad, frio, minimo),
                )

            conn.commit()

            # Verificación en consola
            cur.execute("SELECT id, nombre, correo, rol FROM usuarios ORDER BY id;")
            print("OK - Conexión exitosa a Neon PostgreSQL.")
            print("\nUsuarios:")
            for u in cur.fetchall():
                print(f" - [{u['rol']}] {u['nombre']} ({u['correo']})")

            cur.execute(
                "SELECT codigo_barras, nombre, familia, presentacion, unidad_medida FROM productos ORDER BY id;"
            )
            print("\nProductos:")
            for p in cur.fetchall():
                print(
                    f" - {p['codigo_barras']} | {p['nombre']} ({p['familia']}) "
                    f"- {p['presentacion']} [{p['unidad_medida']}]"
                )
    finally:
        conn.close()


if __name__ == "__main__":
    main()