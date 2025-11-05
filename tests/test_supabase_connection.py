import pytest
from app.core.config import get_supabase

@pytest.mark.connection
def test_supabase_connection():
    """
    Verifica que Supabase esté accesible y la clave sea válida,
    usando una tabla de prueba accesible desde la API REST.
    """
    supabase = get_supabase()

    try:
        # Usa una tabla tuya, no del sistema
        response = supabase.table("test_connection").select("*").limit(1).execute()
        assert response.status_code == 200, f"Status inesperado: {response.status_code}"
        assert response.error is None, f"Error devuelto por Supabase: {response.error}"
    except Exception as e:
        pytest.fail(f"Error al conectar con Supabase: {e}")
