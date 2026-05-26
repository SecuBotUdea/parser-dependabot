import os
from typing import Optional

from dotenv import load_dotenv
from supabase import Client, create_client

load_dotenv()

_supabase_client: Optional[Client] = None


def get_supabase() -> Client:
    """
    Retorna cliente de Supabase con lazy loading.
    Solo se conecta cuando se necesita, no al importar.
    """
    global _supabase_client

    if _supabase_client is not None:
        return _supabase_client

    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY")

    if not SUPABASE_URL or not SUPABASE_KEY:
        raise ValueError(
            "❌ Error: SUPABASE_URL o SUPABASE_KEY no configuradas en el entorno."
        )

    _supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
    return _supabase_client
