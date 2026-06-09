"""Tests for ``lumid_lumilake_plugin`` optimizer surface.

The plugin imports ``RemoteOptimizer`` / ``OptimizerHandle`` from
``lumilake_hook`` at module top, so this repo's standalone test environment
only needs ``lumilake-hook`` installed; no ``lumilake_server`` stubs are
required. Tests that want to assert what the provider passes to
``RemoteOptimizer`` patch the symbol on the plugin module directly.
"""

from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
from lumilake_hook import BaseBindings

import lumid_lumilake_plugin as plugin
import lumid_lumilake_plugin.optimizer as plugin_optimizer


class _FakeRemoteOptimizer:
    """Stand-in used when a test wants to capture the kwargs the provider
    forwards. Mirrors ``lumilake_hook.RemoteOptimizer``'s keyword-only init
    surface so the provider call site is exercised unchanged.
    """

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


@pytest.fixture(autouse=True)
def _writable_acl_db(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """``install()`` always opens the ACL store (FlowMesh-parity), so every
    test in this module needs a writable ``LUMID_ACL_DB_PATH``."""
    monkeypatch.setenv("LUMID_ACL_DB_PATH", str(tmp_path / "acl.sqlite"))


# install() — async context manager


async def test_install_skips_optimizer_when_url_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LUMILAKE_REMOTE_OPTIMIZER_URL", raising=False)

    async with plugin.install() as bindings:
        assert bindings.optimizer_providers == ()


async def test_install_raises_when_remote_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUMILAKE_REMOTE_OPTIMIZER_URL", "https://oaas.example.com")
    monkeypatch.delenv("LUMILAKE_RUNTIME_TOKEN", raising=False)

    with (
        patch("httpx.get", side_effect=httpx.ConnectError("connection refused")),
        pytest.raises(RuntimeError) as exc,
    ):
        async with plugin.install():
            pass
    assert "/api/v1/optimizer" in str(exc.value)


async def test_install_returns_provider_with_remote_types(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUMILAKE_REMOTE_OPTIMIZER_URL", "https://oaas.example.com")
    monkeypatch.delenv("LUMILAKE_RUNTIME_TOKEN", raising=False)

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"types": ["halo-greedy", "halo-helium"]}
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.get", return_value=mock_resp):
        async with plugin.install() as bindings:
            assert isinstance(bindings, BaseBindings)
            assert len(bindings.optimizer_providers) == 1
            provider = bindings.optimizer_providers[0]
            assert sorted(provider.list_optimizers()) == [
                "halo-greedy",
                "halo-helium",
            ]


async def test_provider_list_optimizers_is_cached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUMILAKE_REMOTE_OPTIMIZER_URL", "https://oaas.example.com")
    monkeypatch.delenv("LUMILAKE_RUNTIME_TOKEN", raising=False)

    call_count = 0

    def fake_get(url: str, **kwargs: Any) -> MagicMock:
        nonlocal call_count
        call_count += 1
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"types": ["halo-greedy"]}
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    with patch("httpx.get", side_effect=fake_get):
        async with plugin.install() as bindings:
            provider = bindings.optimizer_providers[0]
            # install() already called list_optimizers() once.
            assert call_count == 1
            provider.list_optimizers()
            provider.list_optimizers()
            assert call_count == 1


async def test_provider_create_optimizer_returns_RemoteOptimizer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``create_optimizer`` instantiates ``lumilake_hook.RemoteOptimizer``
    via the plugin-module-level binding, so patching that binding lets us
    capture the kwargs without contacting a real remote.
    """
    monkeypatch.setenv("LUMILAKE_REMOTE_OPTIMIZER_URL", "https://oaas.example.com")
    monkeypatch.delenv("LUMILAKE_RUNTIME_TOKEN", raising=False)
    monkeypatch.setattr(plugin_optimizer, "RemoteOptimizer", _FakeRemoteOptimizer)

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"types": ["halo-greedy", "halo-helium"]}
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.get", return_value=mock_resp):
        async with plugin.install() as bindings:
            provider = bindings.optimizer_providers[0]
            result = provider.create_optimizer("halo-greedy")
            assert isinstance(result, _FakeRemoteOptimizer)
            assert result.kwargs.get("optimizer_type") == "halo-greedy"
            assert result.kwargs.get("base_url") == "https://oaas.example.com"


async def test_provider_create_optimizer_rejects_unknown_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUMILAKE_REMOTE_OPTIMIZER_URL", "https://oaas.example.com")
    monkeypatch.delenv("LUMILAKE_RUNTIME_TOKEN", raising=False)

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"types": ["halo-greedy"]}
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.get", return_value=mock_resp):
        async with plugin.install() as bindings:
            provider = bindings.optimizer_providers[0]
            with pytest.raises(ValueError) as exc:
                provider.create_optimizer("unknown-type")
            assert "unknown-type" in str(exc.value)
            assert "halo-greedy" in str(exc.value)


async def test_provider_create_optimizer_is_case_insensitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OptimizerProvider Protocol: Lumilake lowercases the optimizer name
    before dispatching. A remote advertising ``Halo-Greedy`` must accept
    ``halo-greedy`` as the lookup key; the original casing must be forwarded
    verbatim to ``RemoteOptimizer``.
    """
    monkeypatch.setenv("LUMILAKE_REMOTE_OPTIMIZER_URL", "https://oaas.example.com")
    monkeypatch.delenv("LUMILAKE_RUNTIME_TOKEN", raising=False)
    monkeypatch.setattr(plugin_optimizer, "RemoteOptimizer", _FakeRemoteOptimizer)

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"types": ["Halo-Greedy"]}
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.get", return_value=mock_resp):
        async with plugin.install() as bindings:
            provider = bindings.optimizer_providers[0]
            result = provider.create_optimizer("halo-greedy")
            assert isinstance(result, _FakeRemoteOptimizer)
            # Original casing forwarded unchanged.
            assert result.kwargs.get("optimizer_type") == "halo-greedy"


async def test_install_forwards_runtime_token_to_catalog_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The install-time catalog probe forwards LUMILAKE_RUNTIME_TOKEN as the
    Bearer header so the remote can authenticate this scheduler-internal call.
    Per-job schedule calls follow a different path (``RemoteOptimizer`` reads
    ``runtime_token_var`` set by the auth middleware), so this token is never
    used to attribute user-submitted jobs.
    """
    monkeypatch.setenv("LUMILAKE_REMOTE_OPTIMIZER_URL", "https://oaas.example.com")
    monkeypatch.setenv("LUMILAKE_RUNTIME_TOKEN", "scheduler-internal-token")

    captured_headers: dict[str, str] = {}

    def fake_get(
        url: str, headers: dict[str, str] | None = None, **kwargs: Any
    ) -> MagicMock:
        if headers:
            captured_headers.update(headers)
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"types": ["halo-greedy"]}
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    with patch("httpx.get", side_effect=fake_get):
        async with plugin.install():
            pass

    assert captured_headers.get("Authorization") == "Bearer scheduler-internal-token"


@pytest.mark.parametrize(
    "body",
    [
        {"optimizer_list": ["halo-greedy"]},  # dict with missing "types" key
        {"types": [1, 2, 3]},  # non-string elements
        ["bare", "list"],  # not a dict at all
    ],
)
async def test_install_response_shape_validation(
    monkeypatch: pytest.MonkeyPatch, body: object
) -> None:
    monkeypatch.setenv("LUMILAKE_REMOTE_OPTIMIZER_URL", "https://oaas.example.com")
    monkeypatch.delenv("LUMILAKE_RUNTIME_TOKEN", raising=False)

    mock_resp = MagicMock()
    mock_resp.json.return_value = body
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.get", return_value=mock_resp), pytest.raises(RuntimeError) as exc:
        async with plugin.install():
            pass
    assert "unexpected response shape" in str(exc.value)


# URL scheme validation


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "ftp://example.com",
        "http://10.0.0.1:8080",
    ],
)
def test_provider_rejects_non_https_non_loopback_urls(url: str) -> None:
    from lumid_lumilake_plugin.optimizer import RemoteOptimizerProvider

    with pytest.raises(ValueError, match="must use https://"):
        RemoteOptimizerProvider(base_url=url)


@pytest.mark.parametrize(
    "url",
    [
        "https://oaas.example.com",
        "http://localhost:8090",
        "http://127.0.0.1:8090",
        "http://[::1]:8090",
    ],
)
def test_provider_accepts_https_and_loopback_http_urls(url: str) -> None:
    """Constructor must accept https and loopback http without contacting the
    remote (the probe happens in list_optimizers / install)."""
    from lumid_lumilake_plugin.optimizer import RemoteOptimizerProvider

    RemoteOptimizerProvider(base_url=url)


# Settings.from_env()


def test_settings_loads_both_optional_fields_from_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUMID_ACL_DB_PATH", "/tmp/some/acl.sqlite")
    monkeypatch.setenv("LUMILAKE_REMOTE_OPTIMIZER_URL", "https://oaas.example.com")

    from lumid_lumilake_plugin.config import Settings

    s = Settings.from_env()
    assert s.lumid_acl_db_path == "/tmp/some/acl.sqlite"
    assert s.lumilake_remote_optimizer_url == "https://oaas.example.com"


def test_settings_defaults_when_env_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LUMID_ACL_DB_PATH", raising=False)
    monkeypatch.delenv("LUMILAKE_REMOTE_OPTIMIZER_URL", raising=False)

    from lumid_lumilake_plugin.config import Settings

    s = Settings.from_env()
    assert s.lumid_acl_db_path == "/app/plugin-data/lumid_acl.sqlite"
    assert s.lumilake_remote_optimizer_url == ""
