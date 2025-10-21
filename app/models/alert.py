# models/alert.py
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class AlertModel(BaseModel):
    id: str
    source: Optional[str] = "dependabot"
    created_at: Optional[str] = None
    package: Optional[Dict[str, Any]] = {}
    severity: Optional[str] = None
    cvss: Optional[float] = None
    cve: Optional[List[str]] = None
    description: Optional[str] = None
    location: Optional[Dict[str, Any]] = {}
    raw: Optional[Dict[str, Any]] = {}

    class Config:
        extra = "allow"
