"""Tests for lumid_lumilake_plugin.

``lumilake_server`` is not installed in the lumid.plugin test environment (this
repo is standalone). Each test stubs the required modules in ``sys.modules``
before triggering the import, then restores the original state with
``monkeypatch``.
"""

import sys
import types
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
from lumilake_hook import BaseBindings

# ---------------------------------------------------------------------------
# Stub helpers
# ---------------------------------------------------------------------------


class _FakeBaseOptimizer:
    pass


class _FakeRemoteOptimizer(_FakeBaseOptimizer):
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


def _install_stubs(monkeypatch: pytest.MonkeyPatch) -> type[_FakeRemoteOptimizer]:
    """Inject stub modules so the optimizer plugin can be imported cleanly.

    Returns the RemoteOptimizer stub class so tests can assert isinstance checks.
    """
    # lumilake_server hierarchy
    server_mod = types.ModuleType("lumilake_server")
    runtime_mod = types.ModuleType("lumilake_server.runtime")
    opt_mod = types.ModuleType("lumilake_server.runtime.optimizer")
    base_mod = types.ModuleType("lumilake_server.runtime.optimizer.base")
    remote_mod = types.ModuleType("lumilake_server.runtime.optimizer.remote")

    base_mod.BaseOptimizer = _FakeBaseOptimizer  # type: ignore[attr-defined]
    remote_mod.RemoteOptimizer = _FakeRemoteOptimizer  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "lumilake_server", server_mod)
    monkeypatch.setitem(sys.modules, "lumilake_server.runtime", runtime_mod)
    monkeypatch.setitem(sys.modules, "lumilake_server.runtime.optimizer", opt_mod)
    monkeypatch.setitem(sys.modules, "lumilake_server.runtime.optimizer.base", base_mod)
    monkeypatch.setitem(sys.modules, "lumilake_server.runtime.optimizer.remote", remote_mod)

    # Evict the plugin and provider from sys.modules so each test gets a clean import.
    monkeypatch.delitem(sys.modules, "lumid_lumilake_plugin", raising=False)
    monkeypatch.delitem(sys.modules, "lumid_lumilake_plugin.optimizer", raising=False)

    return _FakeRemoteOptimizer


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_install_skips_optimizer_when_url_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stubs(monkeypatch)
    monkeypatch.delenv("LUMILAKE_REMOTE_OPTIMIZER_URL", raising=False)

    import lumid_lumilake_plugin as plugin

    bindings = plugin.install()
    assert bindings.optimizer_providers == ()


def test_install_raises_when_remote_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stubs(monkeypatch)
    monkeypatch.setenv("LUMILAKE_REMOTE_OPTIMIZER_URL", "https://oaas.example.com")
    monkeypatch.delenv("LUMILAKE_REMOTE_OPTIMIZER_BEARER", raising=False)

    with patch("httpx.get", side_effect=httpx.ConnectError("connection refused")):
        import lumid_lumilake_plugin as plugin

        with pytest.raises(RuntimeError) as exc:
            plugin.install()
    assert "/api/v1/optimizer" in str(exc.value)


def test_install_returns_provider_with_remote_types(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stubs(monkeypatch)
    monkeypatch.setenv("LUMILAKE_REMOTE_OPTIMIZER_URL", "https://oaas.example.com")
    monkeypatch.delenv("LUMILAKE_REMOTE_OPTIMIZER_BEARER", raising=False)

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"types": ["halo-greedy", "halo-helium"]}
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.get", return_value=mock_resp):
        import lumid_lumilake_plugin as plugin

        bindings = plugin.install()

    assert isinstance(bindings, BaseBindings)
    assert len(bindings.optimizer_providers) == 1
    provider = bindings.optimizer_providers[0]
    assert sorted(provider.list_optimizers()) == ["halo-greedy", "halo-helium"]


def test_provider_list_optimizers_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stubs(monkeypatch)
    monkeypatch.setenv("LUMILAKE_REMOTE_OPTIMIZER_URL", "https://oaas.example.com")
    monkeypatch.delenv("LUMILAKE_REMOTE_OPTIMIZER_BEARER", raising=False)

    call_count = 0

    def fake_get(url: str, **kwargs: Any) -> MagicMock:
        nonlocal call_count
        call_count += 1
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"types": ["halo-greedy"]}
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    with patch("httpx.get", side_effect=fake_get):
        import lumid_lumilake_plugin as plugin

        bindings = plugin.install()

    provider = bindings.optimizer_providers[0]
    # install() already called list_optimizers() once (the eager call)
    assert call_count == 1
    provider.list_optimizers()
    provider.list_optimizers()
    # No additional network calls after cache is warm
    assert call_count == 1


def test_provider_create_optimizer_returns_RemoteOptimizer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    remote_cls = _install_stubs(monkeypatch)
    monkeypatch.setenv("LUMILAKE_REMOTE_OPTIMIZER_URL", "https://oaas.example.com")
    monkeypatch.delenv("LUMILAKE_REMOTE_OPTIMIZER_BEARER", raising=False)

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"types": ["halo-greedy", "halo-helium"]}
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.get", return_value=mock_resp):
        import lumid_lumilake_plugin as plugin

        bindings = plugin.install()

    provider = bindings.optimizer_providers[0]
    result = provider.create_optimizer("halo-greedy")
    assert isinstance(result, remote_cls)
    assert result.kwargs.get("optimizer_type") == "halo-greedy"


def test_provider_create_optimizer_rejects_unknown_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_stubs(monkeypatch)
    monkeypatch.setenv("LUMILAKE_REMOTE_OPTIMIZER_URL", "https://oaas.example.com")
    monkeypatch.delenv("LUMILAKE_REMOTE_OPTIMIZER_BEARER", raising=False)

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"types": ["halo-greedy"]}
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.get", return_value=mock_resp):
        import lumid_lumilake_plugin as plugin

        bindings = plugin.install()

    provider = bindings.optimizer_providers[0]
    with pytest.raises(ValueError) as exc:
        provider.create_optimizer("unknown-type")
    assert "unknown-type" in str(exc.value)
    assert "halo-greedy" in str(exc.value)


def test_install_forwards_bearer_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stubs(monkeypatch)
    monkeypatch.setenv("LUMILAKE_REMOTE_OPTIMIZER_URL", "https://oaas.example.com")
    monkeypatch.setenv("LUMILAKE_REMOTE_OPTIMIZER_BEARER", "my-service-token")

    captured_headers: dict[str, str] = {}

    def fake_get(url: str, headers: dict[str, str] | None = None, **kwargs: Any) -> MagicMock:
        if headers:
            captured_headers.update(headers)
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"types": ["halo-greedy"]}
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    with patch("httpx.get", side_effect=fake_get):
        import lumid_lumilake_plugin as plugin

        plugin.install()

    assert captured_headers.get("Authorization") == "Bearer my-service-token"


@pytest.mark.parametrize(
    "body",
    [
        {"optimizer_list": ["halo-greedy"]},  # missing "types" key
        {"types": [1, 2, 3]},                 # non-string elements
    ],
)
def test_install_response_shape_validation(
    monkeypatch: pytest.MonkeyPatch, body: dict[str, object]
) -> None:
    _install_stubs(monkeypatch)
    monkeypatch.setenv("LUMILAKE_REMOTE_OPTIMIZER_URL", "https://oaas.example.com")
    monkeypatch.delenv("LUMILAKE_REMOTE_OPTIMIZER_BEARER", raising=False)

    mock_resp = MagicMock()
    mock_resp.json.return_value = body
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.get", return_value=mock_resp):
        import lumid_lumilake_plugin as plugin

        with pytest.raises(RuntimeError) as exc:
            plugin.install()
    assert "unexpected response shape" in str(exc.value)
