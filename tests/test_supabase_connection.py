import pytest

from app.core.config import get_supabase


@pytest.mark.connection
def test_supabase_connection():
    """
    Verifica que Supabase esté accesible y la clave sea válida.
    """
    try:
        supabase = get_supabase()
        response = supabase.table("test_connection").select("*").limit(1).execute()
        assert response.data is not None, "La respuesta no contiene el atributo 'data'."
        assert isinstance(response.data, list), "Los datos deben ser una lista"
    except Exception as e:
        pytest.fail(f"Error al conectar o ejecutar la consulta: {str(e)}")
