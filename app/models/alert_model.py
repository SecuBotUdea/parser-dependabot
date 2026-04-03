from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Literal

from pydantic import BaseModel, Field


class AlertSource(str, Enum):
    dependabot = "dependabot"
    zap = "zap"
    trivy = "trivy"


class AlertSeverity(str, Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"
    unknown = "unknown"


class AlertStatus(str, Enum):
    open = "open"
    fixed = "fixed"
    dismissed = "dismissed"
    resolved = "resolved"
    unknown = "unknown"


class Alert(BaseModel):
    alert_id: str
    source_type: AlertSource
    source_id: str

    title: str
    severity: AlertSeverity = AlertSeverity.unknown
    external_references: str
    status: AlertStatus = AlertStatus.unknown
    component: str
    location: str

    first_seen: datetime
    last_seen: Optional[datetime] = None

    normalized_payload: Dict[str, Any] = Field(default_factory=dict)
    raw_payload: Dict[str, Any] = Field(default_factory=dict)
    lifecycle_history: List[Dict[str, Any]] = Field(default_factory=list)

    reopen_count: int = 0
    version: int = 1

    class Config:
        extra = "forbid"
