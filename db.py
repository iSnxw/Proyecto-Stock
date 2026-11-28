import os
from contextlib import contextmanager
import psycopg2
from psycopg2.extras import RealDictCursor


def _get_database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("Falta la variable de entorno DATABASE_URL.")
    return url


@contextmanager
def get_db():
    """Entrega una conexión PostgreSQL con cursor de diccionario y rollback seguro."""
    conn = psycopg2.connect(
        _get_database_url(),
        cursor_factory=RealDictCursor,
        connect_timeout=10,
    )
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()