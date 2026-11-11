"""Data models for audit results."""
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class Finding:
    check_id: str
    severity: str
    title: str
    path: str
    detail: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
