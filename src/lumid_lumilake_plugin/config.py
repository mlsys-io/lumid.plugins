"""Lumilake-side configuration for the lum.id plugin."""

import os
from dataclasses import dataclass
from typing import Any

from ._core import CoreSettings


@dataclass(frozen=True)
class Settings(CoreSettings):
    lumid_acl_db_path: str
    lumilake_remote_optimizer_url: str

    @classmethod
    def _env_fields(cls) -> dict[str, Any]:
        return super()._env_fields() | {
            "lumid_acl_db_path": os.getenv(
                "LUMID_ACL_DB_PATH", "/app/plugin-data/lumid_acl.sqlite"
            ),
            "lumilake_remote_optimizer_url": os.getenv("LUMILAKE_REMOTE_OPTIMIZER_URL", ""),
        }
