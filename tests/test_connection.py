from app.db.connection import get_conn, init_pool


def test_db_connection():
    """
    Intenta inicializar el pool y luego ejecutar una consulta simple.
    """
    # No necesitas print() si usas pytest -s, pero mantengámoslos por ahora.
    print("Iniciando prueba de conexión a la BD...")
    try:
        init_pool()
        print("✅ Pool de conexiones inicializado.")

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
                result = cur.fetchone()
                if result and result[0] == 1:
                    print(
                        f"🎉 La conexión a la base de datos es exitosa. Resultado de la prueba: {result[0]}"
                    )
                    # En pytest, normalmente solo necesitas 'assert'
                    assert result[0] == 1
                    return  # Opcional, ya que assert fallará si no es 1
                else:
                    # Esto debería fallar si llegas aquí y el resultado no es 1
                    assert False, "La consulta de prueba no devolvió 1"

    except RuntimeError as e:
        # Si falla la configuración, pytest lo reportará como un fallo de setup
        assert False, f"Error de configuración: {e}"
    except Exception as e:
        # Si falla la conexión, pytest lo reportará como un fallo
        assert False, f"Falló la conexión: {e}"
    finally:
        from app.db.connection import close_pool

        close_pool()
