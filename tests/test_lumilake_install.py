"""Tests for `lumid_lumilake_plugin.install()`."""

import pytest
from lumid_hooks import HookBindings as SharedHookBindings
from lumilake_hook import BaseBindings as LumilakeBaseBindings

from lumid_lumilake_plugin import install

# Same physical sources but distinct sys.modules entries vs the FlowMesh
# `_core`, so isinstance only matches against this import path.
from lumid_lumilake_plugin._core import LumidIdentityProvider


async def test_install_returns_lumilake_basebindings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("LUM_ID_BASE_URL", "https://lum.id")
    monkeypatch.setenv("LUMID_ACL_DB_PATH", str(tmp_path / "acl.sqlite"))
    async with install() as bindings:
        assert isinstance(bindings, LumilakeBaseBindings)
        assert isinstance(bindings, SharedHookBindings)


async def test_install_registers_identity_and_jobs_auth(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("LUM_ID_BASE_URL", "https://lum.id")
    monkeypatch.setenv("LUMID_ACL_DB_PATH", str(tmp_path / "acl.sqlite"))
    async with install() as bindings:
        assert len(bindings.identity_providers) == 1
        assert isinstance(bindings.identity_providers[0], LumidIdentityProvider)
        assert len(bindings.submission_guards) == 0
        assert len(bindings.usage_sinks) == 0
        assert len(bindings.permission_checkers) == 1
        assert len(bindings.resource_registrars) == 1


async def test_identity_name_is_lumilake_scoped(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("LUM_ID_BASE_URL", "https://lum.id")
    monkeypatch.setenv("LUMID_ACL_DB_PATH", str(tmp_path / "acl.sqlite"))
    async with install() as bindings:
        identity = bindings.identity_providers[0]
        assert identity.name == "lumid_lumilake_plugin.identity"


async def test_install_reads_org_id_from_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("LUM_ID_BASE_URL", "https://lum.id")
    monkeypatch.setenv("LUMID_ORG_ID", "lumid-prod")
    monkeypatch.setenv("LUMID_ACL_DB_PATH", str(tmp_path / "acl.sqlite"))
    async with install() as bindings:
        identity = bindings.identity_providers[0]
        assert identity._org_id == "lumid-prod"
