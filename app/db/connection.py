import os
from contextlib import contextmanager

import psycopg2

DATABASE_URL = os.getenv("DATABASE_URL")
POOL_MINCONN = int(os.getenv("POOL_MINCONN", "1"))
POOL_MAXCONN = int(os.getenv("POOL_MAXCONN", "10"))

_pool = None


def init_pool():
    global _pool
    if _pool is not None:
        return
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")

    _pool = psycopg2.pool.SimpleConnectionPool(
        POOL_MINCONN,
        POOL_MAXCONN,
        dsn=DATABASE_URL,
        connect_timeout=10,
        keepalives=1,
        keepalives_idle=30,
        keepalives_interval=10,
        keepalives_count=5,
    )


@contextmanager
def get_conn():
    conn = None
    try:
        if _pool is None:
            init_pool()
        conn = _pool.getconn()
        yield conn
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        raise e
    finally:
        if conn:
            _pool.putconn(conn)


def close_pool():
    global _pool
    if _pool is not None:
        _pool.closeall()
        _pool = None
