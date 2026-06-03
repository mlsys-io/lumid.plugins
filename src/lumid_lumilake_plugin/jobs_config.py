"""Lumilake jobs plugin configuration."""

import os
from dataclasses import dataclass
from typing import Any, Self

from ._core import CoreSettings


@dataclass(frozen=True)
class JobsSettings(CoreSettings):
    lumid_lumilake_acl_db_path: str

    @classmethod
    def _env_fields(cls) -> dict[str, Any]:
        return super()._env_fields() | {
            "lumid_lumilake_acl_db_path": os.getenv(
                "LUMID_LUMILAKE_ACL_DB_PATH",
                "/app/plugin-data/lumid_lumilake_acl.sqlite",
            ),
        }

    @classmethod
    def from_env(cls) -> Self:
        return cls(**cls._env_fields())
