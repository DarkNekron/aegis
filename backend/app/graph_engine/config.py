"""Administrator-configurable analysis settings, stored in the ``settings`` table."""

from __future__ import annotations

import hashlib
import json

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from app.models import SettingEntry

TIER0_CATEGORIES: dict[str, str] = {
    "domain": "The domain object",
    "domain_controllers": "Domain controllers and the Domain Controllers group (516)",
    "domain_admins": "Domain Admins (512)",
    "enterprise_admins": "Enterprise Admins (519)",
    "schema_admins": "Schema Admins (518)",
    "administrators": "BUILTIN Administrators (544)",
    "operators": "Account (548), Server (549), Print (550) and Backup (551) Operators",
    "key_admins": "Key Admins (526) and Enterprise Key Admins (527)",
    "builtin_accounts": "Administrator (500) and krbtgt (502)",
    "dcsync": "Principals holding GetChanges + GetChangesAll on a domain",
}

SETTING_KEY = "analysis_config"


class AnalysisConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tier0_categories: list[str] = Field(default_factory=lambda: list(TIER0_CATEGORIES))
    custom_tier0_object_ids: list[str] = Field(default_factory=list, max_length=1000)
    trust_input_hints: bool = False  # treat imported "highvalue"/"admin_tier_0" flags as tier-0
    traverse_trusts: bool = False

    @field_validator("tier0_categories")
    @classmethod
    def _known(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - set(TIER0_CATEGORIES))
        if unknown:
            raise ValueError(f"unknown tier-0 categories: {', '.join(unknown)}")
        return sorted(set(value))

    @field_validator("custom_tier0_object_ids")
    @classmethod
    def _upper(cls, value: list[str]) -> list[str]:
        return sorted({v.strip().upper() for v in value if v.strip()})

    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(self.model_dump(), sort_keys=True).encode()).hexdigest()[:16]


def load_config(session: Session) -> AnalysisConfig:
    entry = session.get(SettingEntry, SETTING_KEY)
    return AnalysisConfig.model_validate(entry.value) if entry else AnalysisConfig()


def save_config(session: Session, config: AnalysisConfig, updated_by: int | None = None) -> None:
    entry = session.get(SettingEntry, SETTING_KEY)
    if entry is None:
        session.add(SettingEntry(key=SETTING_KEY, value=config.model_dump(), updated_by=updated_by))
    else:
        entry.value = config.model_dump()
        entry.updated_by = updated_by
    session.commit()
