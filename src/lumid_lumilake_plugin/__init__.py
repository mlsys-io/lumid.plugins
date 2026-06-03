"""Lumilake plugin: lum.id identity + optional jobs ACL + optional remote optimizer.

A single `install()` returns one `BaseBindings`. Identity is always registered;
the jobs ACL surface and the remote-optimizer surface activate only when their
env vars are set, so identity-only deployments need no extra config.
"""

import os
from datetime import UTC, datetime

from lumilake_hook import BaseBindings

from ._core import (
    CoreSettings,
    IntrospectedToken,
    LumidIdentityProvider,
    build_email_cache,
)
from .acl import open_store_sync
from .jobs_config import JobsSettings
from .permissions import LumidPermissionChecker
from .registrar import LumidResourceRegistrar


def install() -> BaseBindings:
    core = CoreSettings.from_env()
    email_cache = build_email_cache()

    identity = LumidIdentityProvider(
        base_url=core.lum_id_base_url,
        org_id=core.lumid_org_id,
        email_cache=email_cache,
        name="lumid_lumilake_plugin.identity",
    )

    permission_checkers: tuple[LumidPermissionChecker, ...] = ()
    resource_registrars: tuple[LumidResourceRegistrar, ...] = ()
    if os.environ.get("LUMID_LUMILAKE_ACL_DB_PATH"):
        settings = JobsSettings.from_env()
        # Fail loudly at install time if the DB path is not writable.
        try:
            store = open_store_sync(settings.lumid_lumilake_acl_db_path)
        except (PermissionError, OSError) as exc:
            raise RuntimeError(
                f"lumid_lumilake_plugin: ACL DB at "
                f"{settings.lumid_lumilake_acl_db_path!r} is not writable. "
                f"Set LUMID_LUMILAKE_ACL_DB_PATH to a writable location or mount "
                f"/app/plugin-data as a writable volume."
            ) from exc
        try:
            # BEGIN IMMEDIATE acquires a RESERVED write lock and requires write
            # access to both the DB file and its -journal. Deferred BEGIN would
            # silently succeed on a read-only file.
            store._conn.execute("BEGIN IMMEDIATE")
            store._conn.execute("ROLLBACK")
        except Exception as exc:
            raise RuntimeError(
                f"lumid_lumilake_plugin: ACL DB at "
                f"{settings.lumid_lumilake_acl_db_path!r} is not writable. "
                f"Set LUMID_LUMILAKE_ACL_DB_PATH to a writable location or mount "
                f"/app/plugin-data as a writable volume."
            ) from exc
        session_start = datetime.now(UTC)
        permission_checkers = (LumidPermissionChecker(store),)
        resource_registrars = (LumidResourceRegistrar(store, session_start),)

    optimizer_providers: tuple[object, ...] = ()
    if url := os.environ.get("LUMILAKE_REMOTE_OPTIMIZER_URL"):
        # Imported lazily: ``optimizer.py`` depends on the image-only
        # ``lumilake_server`` runtime, which isn't installed when the plugin
        # is loaded for identity- or jobs-only use cases.
        from .optimizer import RemoteOptimizerProvider

        bearer = os.environ.get("LUMILAKE_REMOTE_OPTIMIZER_BEARER") or None
        provider = RemoteOptimizerProvider(base_url=url, bearer=bearer)
        provider.list_optimizers()
        optimizer_providers = (provider,)

    return BaseBindings(
        identity_providers=(identity,),
        permission_checkers=permission_checkers,
        resource_registrars=resource_registrars,
        optimizer_providers=optimizer_providers,
    )


__all__ = [
    "BaseBindings",
    "IntrospectedToken",
    "LumidIdentityProvider",
    "LumidPermissionChecker",
    "LumidResourceRegistrar",
    "install",
]
