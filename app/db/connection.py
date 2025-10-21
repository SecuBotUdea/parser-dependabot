from contextlib import contextmanager
from typing import Optional

import psycopg2
from config import DATABASE_URL, POOL_MAXCONN, POOL_MINCONN
from psycopg2.pool import SimpleConnectionPool

_pool: Optional[SimpleConnectionPool] = None


def init_pool():
    global _pool
    if _pool is not None:
        return
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    _pool = SimpleConnectionPool(POOL_MINCONN, POOL_MAXCONN, dsn=DATABASE_URL)


def close_pool():
    global _pool
    if _pool:
        _pool.closeall()
        _pool = None


@contextmanager
def get_conn():
    """
    Context manager that yields a connection from the pool (or a direct conn if pool unavailable).
    Always closes/returns the connection.
    """
    global _pool
    if _pool is None:
        # fallback: create transient connection (not ideal for production)
        if not DATABASE_URL:
            raise RuntimeError("DATABASE_URL not set")
        conn = psycopg2.connect(DATABASE_URL)
        try:
            yield conn
        finally:
            conn.close()
        return

    conn = _pool.getconn()
    try:
        yield conn
    finally:
        _pool.putconn(conn)
