"""Host-neutral lum.id plugin building blocks.

Exposed inside each plugin via a `_core` symlink to this directory.
"""

from ._cache import TTLCache
from .acl import GrantLevel, GrantStore, open_store, open_store_sync
from .config import CoreSettings
from .identity import (
    IntrospectedToken,
    LumidIdentityProvider,
    build_email_cache,
)
from .permissions import PermissionChecker, PermissionPolicy

__all__ = [
    "CoreSettings",
    "GrantLevel",
    "GrantStore",
    "IntrospectedToken",
    "LumidIdentityProvider",
    "PermissionChecker",
    "PermissionPolicy",
    "TTLCache",
    "build_email_cache",
    "open_store",
    "open_store_sync",
]
