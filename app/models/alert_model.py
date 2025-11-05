from typing import Any, Dict, Optional

from pydantic import BaseModel


class AlertModel(BaseModel):
    id: str
    repo: Optional[str]
    source: Optional[str] = "dependabot"
    severity: Optional[float] = None
    cvss: Optional[float] = None
    cve: Optional[str] = None
    description: Optional[str] = None
    package: Optional[Dict[str, Any]] = {}
    location: Optional[Dict[str, Any]] = {}
    raw: Optional[Dict[str, Any]] = {}
    created_at: Optional[str] = None

    class Config:
        extra = "allow"
