"""Risk model parameters. Every value is documented in docs/RISK_SCORING.md and editable by an Administrator."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy.orm import Session

from app.models import SettingEntry

SETTING_KEY = "risk_config"

FACTORS = ("destination_privilege", "exploitability", "proximity", "relationship_severity", "confidence",
           "exposure", "alternatives", "evidence_completeness", "asset_criticality")
SEVERITIES = ("Critical", "High", "Medium", "Low")

DEFAULT_WEIGHTS = {
    "destination_privilege": 0.30, "exploitability": 0.15, "proximity": 0.15, "relationship_severity": 0.10,
    "confidence": 0.10, "exposure": 0.08, "alternatives": 0.04, "evidence_completeness": 0.05,
    "asset_criticality": 0.03,
}
DEFAULT_PRIVILEGE = {
    "domain": 1.0, "domain_controllers": 1.0, "domain_admins": 1.0, "enterprise_admins": 1.0, "administrators": 1.0,
    "dcsync": 1.0, "builtin_accounts": 1.0, "schema_admins": 0.9, "key_admins": 0.9, "operators": 0.8,
    "custom": 0.8, "hint": 0.6,
}


class RiskConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    weights: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    category_privilege: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_PRIVILEGE))
    default_privilege: float = Field(0.7, ge=0, le=1)       # target selected but no known category
    hop_decay: float = Field(0.85, gt=0, le=1)               # proximity = hop_decay ** (hops - 1)
    conditional_factor: float = Field(0.7, ge=0, le=1)       # exploitability of a conditional path
    exposure_saturation: int = Field(100, ge=1)              # sources reaching a target for exposure = 1.0
    alternatives_saturation: int = Field(5, ge=2)            # routes per identity for alternatives = 1.0
    bands: dict[str, float] = Field(default_factory=lambda: {"Critical": 80.0, "High": 60.0, "Medium": 40.0})
    conditional_max_severity: str = "High"                   # unvalidated conditional paths are capped here
    asset_criticality: dict[str, float] = Field(default_factory=dict)  # object_id -> 0..1 business criticality

    @field_validator("weights")
    @classmethod
    def _weights(cls, value: dict[str, float]) -> dict[str, float]:
        if set(value) != set(FACTORS):
            raise ValueError(f"weights must define exactly: {', '.join(FACTORS)}")
        if any(v < 0 for v in value.values()) or sum(value.values()) <= 0:
            raise ValueError("weights must be non-negative and not all zero")
        return value

    @field_validator("category_privilege", "asset_criticality")
    @classmethod
    def _unit_interval(cls, value: dict[str, float]) -> dict[str, float]:
        if any(not 0 <= v <= 1 for v in value.values()):
            raise ValueError("values must be between 0 and 1")
        return value

    @field_validator("asset_criticality")
    @classmethod
    def _upper_ids(cls, value: dict[str, float]) -> dict[str, float]:
        return {k.strip().upper(): v for k, v in value.items()}

    @model_validator(mode="after")
    def _bands(self) -> RiskConfig:
        b = self.bands
        if set(b) != {"Critical", "High", "Medium"} or not 100 >= b["Critical"] > b["High"] > b["Medium"] > 0:
            raise ValueError("bands must satisfy 100 >= Critical > High > Medium > 0")
        if self.conditional_max_severity not in SEVERITIES:
            raise ValueError(f"conditional_max_severity must be one of {', '.join(SEVERITIES)}")
        return self

    def normalised_weights(self) -> dict[str, float]:
        total = sum(self.weights.values())
        return {k: v / total for k, v in self.weights.items()}


def load_risk_config(session: Session) -> RiskConfig:
    entry = session.get(SettingEntry, SETTING_KEY)
    return RiskConfig.model_validate(entry.value) if entry else RiskConfig()


def save_risk_config(session: Session, config: RiskConfig, updated_by: int | None = None) -> None:
    entry = session.get(SettingEntry, SETTING_KEY)
    if entry is None:
        session.add(SettingEntry(key=SETTING_KEY, value=config.model_dump(), updated_by=updated_by))
    else:
        entry.value = config.model_dump()
        entry.updated_by = updated_by
    session.commit()
