import os
import psycopg2
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()

def main():
    admin_url = os.environ.get("DATABASE_ADMIN_URL")
    if not admin_url:
        raise SystemExit("Falta DATABASE_ADMIN_URL en .env")

    clave_bodega = os.environ.get("SEED_BODEGA_PASS", "Bodega2026!")
    clave_tens = os.environ.get("SEED_TENS_PASS", "Tens2026!")

    usuarios = [
        ("Encargado de Bodega", "bodega@posta.cl", generate_password_hash(clave_bodega), "BODEGA"),
        ("TENS de Turno", "tens@posta.cl", generate_password_hash(clave_tens), "TENS"),
    ]

    equipos = [
        ("Refrigerador Vacunas", "Vacunatorio", 2.0, 8.0),
        ("Refrigerador Bodega", "Bodega", 2.0, 8.0),
    ]

    with psycopg2.connect(admin_url) as conn:
        with conn.cursor() as cur:
            for nombre, correo, pw_hash, rol in usuarios:
                cur.execute(
                    """
                    INSERT INTO usuarios (nombre, correo, password_hash, rol)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (correo) DO NOTHING
                    """,
                    (nombre, correo, pw_hash, rol),
                )

            cur.execute("SELECT COUNT(*) FROM equipos_frio")
            if cur.fetchone()[0] == 0:
                for nombre, ubicacion, tmin, tmax in equipos:
                    cur.execute(
                        """
                        INSERT INTO equipos_frio (nombre, ubicacion, temp_min_c, temp_max_c)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (nombre, ubicacion, tmin, tmax),
                    )
        conn.commit()
    print("Seed ejecutado correctamente (usuarios y equipos iniciales listos).")

if __name__ == "__main__":
    main()