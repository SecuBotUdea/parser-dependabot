import os

from dotenv import load_dotenv
from supabase import Client, create_client

load_dotenv()

def get_supabase() -> Client:
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY")

    if not url or not key:
        raise ValueError("❌ Error: SUPABASE_URL o SUPABASE_KEY no configuradas en el entorno.")
    
    return create_client(SUPABASE_URL, SUPABASE_KEY)
