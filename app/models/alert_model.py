from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Alert(BaseModel):
    alert_id: str  # PK
    signature: Optional[str] = None
    source_id: Optional[str] = None
    severity: Optional[str] = None
    component: Optional[str] = None
    status: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    quality: Optional[str] = None
    normalized_payload: Dict[str, Any] = Field(default_factory=dict)
    lifecycle_history: List[Dict[str, Any]] = Field(default_factory=list)
    reopen_count: Optional[int] = 0
    last_reopened_at: Optional[datetime] = None
    version: Optional[int] = 1

    class Config:
        extra = "allow"
        orm_mode = True
