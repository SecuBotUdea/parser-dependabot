import os
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

DATABASE_URL: Optional[str] = os.getenv("DATABASE_URL")
POOL_MINCONN: int = int(os.getenv("POOL_MINCONN", "5"))
POOL_MAXCONN: int = int(os.getenv("POOL_MAXCONN", "15"))
