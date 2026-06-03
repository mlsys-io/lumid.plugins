# lumid-plugins

lum.id host plugins for the two services that share its identity:

* **`lumid_flowmesh_plugin`** — full FlowMesh adapter: identity, permission checks, resource registrar, Runmesh billing, supplier attribution. Loaded via `FLOWMESH_PLUGINS=lumid_flowmesh_plugin`.
* **`lumid_lumilake_plugin`** — Lumilake adapter. Loaded via `LUMILAKE_PLUGINS=lumid_lumilake_plugin`. Always registers a `LumidIdentityProvider` (the same one FlowMesh uses, so a bearer Lumilake accepts is a bearer Lumilake can forward to FlowMesh — both sides re-introspect the same string). Two surfaces activate via env vars:
  * **Jobs auth** (`PermissionChecker` + `ResourceRegistrar`) — checks and registers grants for every concrete resource kind Lumilake sends (typically JOB, TRACE, ARTIFACT). The "jobs" framing reflects the primary use case; the ACL store is kind-agnostic so completed-job artifacts and traces remain authorized across restarts. Backed by a local SQLite ACL store. Activates when `LUMID_LUMILAKE_ACL_DB_PATH` is set; fails fast at install time if the DB path is not writable.
  * **Remote optimizer** (`OptimizerProvider`) — proxies optimizer requests to a trusted upstream URL, forwarding the caller's lum.id bearer token. Activates when `LUMILAKE_REMOTE_OPTIMIZER_URL` is set.

Both modules live in one repo (`lumid-plugins`) so the lum.id core is implemented once.

## Repo layout

```
src/
├── _shared_core/                 ← physical source of truth (TTLCache,
│   ├── _cache.py                   LumidIdentityProvider, CoreSettings)
│   ├── config.py
│   ├── identity.py
│   └── __init__.py
├── lumid_flowmesh_plugin/
│   ├── _core → ../_shared_core   ← symlink
│   ├── __init__.py / acl.py / permissions.py / ...
└── lumid_lumilake_plugin/
    ├── _core → ../_shared_core   ← symlink
    └── __init__.py
```

Each plugin imports its shared sources as `from ._core import ...` — no plugin reaches across to a sibling plugin. The two `_core` symlinks point at the same physical directory, so editing `src/_shared_core/identity.py` is the single edit that ripples to both adapters.

Deploys must dereference the `_core` symlinks when copying the source tree (`cp -rL`); see the loading sections below.

## FlowMesh plugin: what it provides

| Hook | Behaviour |
|---|---|
| `IdentityProvider` | Resolves bearer tokens via `POST {LUM_ID_BASE_URL}/oauth/introspect`. Accepts lum.id JWT and `lm_pat_*` PATs. Caches active introspect responses for 60 s, sha256-keyed, capped at 10 k entries. lum.id scopes pass through verbatim onto `PrincipalContext.scopes`. Stashes `principal_id → email` for later use by the usage sink. |
| `PermissionChecker` | Admin-bypass + scope-driven kind-level checks + grant-driven concrete-id checks. See [Scope vocabulary](#scope-vocabulary) below. Reads grants from the SQLite ACL written by `ResourceRegistrar`. |
| `ResourceRegistrar` | Mirrors FlowMesh's resource lifecycle (`register` on create, `deregister` on hard-delete, `reconcile` at startup) into a SQLite grants table at `LUMID_ACL_DB_PATH`. The table is keyed by `(kind, id, principal_id)`, so multiple principals can hold grants on the same resource. `reconcile` runs as a single atomic transaction. Backed by the stdlib `sqlite3` module. |
| `SubmissionGuard` | Optional GPU-rental balance preflight against Runmesh. Off by default (`LUMID_BALANCE_GUARD=on` to enable). Fails open on Runmesh outage. |
| `UsageSink` | Mirrors usage rows to `POST {RUNMESH_BILLING_BASE_URL}/billing/flowmesh-entry` with `X-Bridge-Secret`. Forwards each row whose `principal_id` is in the email cache; rows without a cached email (anonymous or pre-restart principals) are skipped. One POST per row; failures logged and dropped. |
| `SupplierResolver` | Returns `worker.namespace` as the supplier id at dispatch time. |

`install()` is an `@asynccontextmanager`: it opens the ACL SQLite connection, bootstraps the schema, yields the bindings, and closes the connection on FastAPI shutdown. Stale grants are dropped by the host's startup `reconcile` sweep through `ResourceRegistrar`.

### Scope vocabulary

The FlowMesh adapter's `PermissionChecker` reads these scopes from the introspected token:

| Scope | Grants |
|---|---|
| `*` / `flowmesh:*` / `flowmesh:admin` | Admin bypass — all kinds, all actions. |
| `flowmesh:workflows:read` / `flowmesh:tasks:read` / `flowmesh:results:read` / `flowmesh:nodes:read` / `flowmesh:workers:read` / `flowmesh:system:read` | Call kind-level READ endpoints. Returned resources are filtered to those the principal holds a grant on. |
| `flowmesh:workflows:write` | Create workflows. |
| `flowmesh:nodes:write` | Register nodes. |
| `flowmesh:workers:write` | Register workers. |
| `flowmesh:results:write` | Upload task results and artifacts. |

Concrete-id access requires a grant on the resource.

## Compatibility

| Plugin | FlowMesh server | `flowmesh-hook` | Lumilake server | `lumilake-hook` | `lumid-hooks` |
|---|---|---|---|---|---|
| 0.1.1 | 0.1.0, 0.1.1 | 0.1.0, 0.1.1 | not supported | not supported | 0.1.0 |
| 0.2.0 | ≥ 0.1.2 | ≥ 0.1.2 | not supported | not supported | ≥ 0.2.0 |
| 0.2.1 | ≥ 0.1.2 | ≥ 0.1.2 | ≥ 0.1.2 | ≥ 0.1.2 | ≥ 0.2.0 |
| 0.2.2 | ≥ 0.1.2 | ≥ 0.1.2 | ≥ 0.1.3 | ≥ 0.1.3 | ≥ 0.2.0 |

Host servers are not pip-enforceable (plugins load into a running process), so they must be at least the version shown. FlowMesh 0.1.2 ships the `ResourceRegistrar.reconcile_resources` startup sweep, `/app/plugin-data` writable mount, and `RESULT/WRITE` gate that the FlowMesh adapter depends on. Lumilake 0.1.2 ships the `IdentityProvider` plugin gate. The `lumid_lumilake_plugin` jobs auth surface (PermissionChecker + ResourceRegistrar) and remote-optimizer surface (OptimizerProvider) need a Lumilake release after 0.1.2 — install against a host build that exposes those hooks (the compat table will gain a new row when the host is released).

## Environment variables

| Var | Required | Default | Notes |
|---|---|---|---|
| `LUM_ID_BASE_URL` | no | `https://lum.id` | Identity provider base URL. Used by `lumid_lumilake_plugin` and `lumid_flowmesh_plugin`. |
| `RUNMESH_BILLING_BASE_URL` | yes (for billing) | — | e.g. `https://kv.run:8000/Runmesh`. Empty disables sink + guard. |
| `FLOWMESH_BRIDGE_SECRET` | yes (for billing) | — | Shared secret used as `X-Bridge-Secret`. |
| `LUMID_BALANCE_GUARD` | no | `off` | `on` to enable preflight balance check. |
| `LUMID_ORG_ID` | no | `lumid` | Stamped on the `PrincipalContext.org_id` returned by the IdentityProvider. Used by both Lumilake and FlowMesh adapters. |
| `LUMID_ACL_DB_PATH` | no | `/app/plugin-data/lumid_acl.sqlite` | SQLite file for the FlowMesh `ResourceRegistrar` / `PermissionChecker` grants table. The default path lives under FlowMesh's `FLOWMESH_PLUGIN_DATA_DIR` mount. |
| `LUMID_LUMILAKE_ACL_DB_PATH` | no | `/app/plugin-data/lumid_lumilake_acl.sqlite` | Setting this turns on the jobs-auth surface in `lumid_lumilake_plugin` (SQLite ACL store). **This path must be writable.** The plugin creates parent directories automatically; if the path is unwritable, the plugin raises at install time (fail-fast, not fail-open). Leave unset to load identity only. |
| `LUMILAKE_OPTIMIZER_TYPE` | no (optimizer surface) | `halo` (Lumilake default) | Selects which optimizer Lumilake uses at runtime. Set to any type advertised by the remote (e.g. `halo-greedy`, `halo-helium`) to route through the plugin. Lumilake checks this; the plugin does not. |
| `LUMILAKE_REMOTE_OPTIMIZER_URL` | yes (optimizer surface) | — | Setting this turns on the remote-optimizer surface in `lumid_lumilake_plugin`. HTTPS URL of the remote optimizer service; `http://` is accepted only for loopback addresses. The caller's lum.id bearer is forwarded verbatim — point this only at a trusted service. Leave unset to load identity (and optionally jobs) only. |
| `LUMILAKE_RUNTIME_TOKEN` | yes (optimizer surface, if remote auth-gates catalog) | — | Scheduler-internal credential — Lumilake's existing system-level upstream bearer (see Lumilake's `docs/ENV.md`). The plugin reuses it for the install-time `/api/v1/optimizer` catalog probe when the remote auth-gates that endpoint. Per-job schedule calls do **not** use this token; they forward the submitter's lum.id bearer via Lumilake's `runtime_token_var`, so each schedule is audited to the real user. |

## Loading

Set the env vars:

```ini
FLOWMESH_PLUGINS=lumid_flowmesh_plugin
LUM_ID_BASE_URL=https://lum.id
RUNMESH_BILLING_BASE_URL=https://kv.run:8000/Runmesh
FLOWMESH_BRIDGE_SECRET=<shared-secret>
```

Drop the plugin's source tree under `${FLOWMESH_PLUGIN_DIR:-./plugins}` with `cp -rL` so the `_core` symlink is dereferenced into real files inside the deployed directory:

```bash
git clone --branch v<version> https://github.com/mlsys-io/lumid.flowmesh-plugin /tmp/lumid-plugins
cp -rL /tmp/lumid-plugins/src/lumid_flowmesh_plugin plugins/ # The `-L` flag is mandatory to import the shared directory.

flowmesh stack up
```

Runtime deps (`httpx`, `pydantic`, `fastapi`, `lumid-hooks`, `flowmesh-hook`) ship with the FlowMesh server image; the ACL store uses the stdlib `sqlite3` module.

## Lumilake plugin: what it provides

`lumid_lumilake_plugin` registers up to three surfaces in a single `install()`. Identity is always on; the other two activate via env vars.

### Identity (always on)

| Hook | Behaviour |
|---|---|
| `IdentityProvider` | The same `LumidIdentityProvider` as the FlowMesh plugin — resolves bearers via `POST {LUM_ID_BASE_URL}/oauth/introspect`, returns a `lumid_hooks.PrincipalContext` with the token's scopes verbatim, caches introspect responses for 60 s. |

### Jobs auth (set `LUMID_LUMILAKE_ACL_DB_PATH`)

| Hook | Behaviour |
|---|---|
| `PermissionChecker` | Admin-bypass + scope-driven kind-level checks + grant-driven concrete-id checks for every concrete resource kind Lumilake sends (typically JOB, TRACE, ARTIFACT). Reads grants from a local SQLite ACL store. The "jobs" framing reflects the primary use case; the ACL store is kind-agnostic so completed-job artifacts and traces remain authorized across restarts. |
| `ResourceRegistrar` | Mirrors resource lifecycle events (`register` on create, `deregister` on delete, `reconcile` at startup) into the SQLite grants table at `LUMID_LUMILAKE_ACL_DB_PATH`. Reconcile is scoped to the kinds present in the input set — TRACE and ARTIFACT grants are never dropped by a JOB-only reconcile sweep. |

The jobs surface ensures the ACL DB parent directory exists and performs an explicit writability check during `install()`; if the DB is not writable it raises `RuntimeError` immediately rather than letting the plugin load silently without a `PermissionChecker` registered.

### Remote optimizer (set `LUMILAKE_REMOTE_OPTIMIZER_URL`)

| Hook | Behaviour |
|---|---|
| `OptimizerProvider` | At install time, queries the remote `/api/v1/optimizer` once and caches the advertised optimizer types for the process lifetime. Lumilake's `create_optimizer(type)` falls through to this provider for any type the remote advertises (e.g. `halo-greedy`, `halo-helium`). Set `LUMILAKE_OPTIMIZER_TYPE` to any advertised type to activate remote routing — no static `oaas` alias required. If the remote adds new types, Lumilake must restart to pick them up. |

### Loading on Lumilake

Set the env vars on the Lumilake server image:

```ini
LUMILAKE_PLUGINS=lumid_lumilake_plugin
LUM_ID_BASE_URL=https://lum.id
LUMID_ORG_ID=lumid
LUMILAKE_REQUIRE_IDENTITY_PROVIDER=1
LUMID_LUMILAKE_ACL_DB_PATH=/app/plugin-data/lumid_lumilake_acl.sqlite
LUMILAKE_REMOTE_OPTIMIZER_URL=https://<optimizer-host>
LUMILAKE_OPTIMIZER_TYPE=halo-greedy
# Required if the remote auth-gates GET /api/v1/optimizer (used only for the
# install-time catalog probe; per-job calls forward the submitter's bearer).
# LUMILAKE_RUNTIME_TOKEN is Lumilake's existing scheduler-internal credential.
# LUMILAKE_RUNTIME_TOKEN=<lum.id PAT scoped for service-internal reads>
```

`LUMILAKE_REMOTE_OPTIMIZER_URL` is the only env var the plugin requires. At install time the plugin fetches the remote's `/api/v1/optimizer` endpoint once to discover available optimizer types; the result is cached for the process lifetime. `LUMILAKE_OPTIMIZER_TYPE` tells Lumilake which optimizer to use at runtime — set it to any type the remote advertises (e.g. `halo-greedy`, `halo-helium`). If the remote auth-gates the list endpoint, set `LUMILAKE_RUNTIME_TOKEN` (the same scheduler-internal credential Lumilake already configures for FlowMesh control-plane reads); the plugin reuses it for that single install-time request. **Per-job schedule calls do not use this token** — the upstream `RemoteOptimizer` reads `runtime_token_var`, which Lumilake's auth middleware sets to the submitter's lum.id bearer on every request, so each schedule is attributed to the real caller.

```bash
git clone --branch v<version> https://github.com/mlsys-io/lumid.flowmesh-plugin /tmp/lumid-plugins
cp -rL /tmp/lumid-plugins/src/lumid_lumilake_plugin plugins/

lumilake deploy restart
```

If `LUMID_LUMILAKE_ACL_DB_PATH` is set, `/app/plugin-data` must be mounted as a writable volume so the plugin can write its ACL database. If the mount is absent or read-only the plugin will raise at install time with a message naming `LUMID_LUMILAKE_ACL_DB_PATH`.

### Security notes

**Jobs ACL DB writability.** When `LUMID_LUMILAKE_ACL_DB_PATH` is set, an unwritable location causes `install()` to raise `RuntimeError` instead of skipping the jobs surface. This is intentional: a misconfigured ACL store must not cause authorization to be silently disabled.

**Optimizer install-time fetch.** When `LUMILAKE_REMOTE_OPTIMIZER_URL` is set, the plugin calls the remote `/api/v1/optimizer` once at install time, sending `Authorization: Bearer $LUMILAKE_RUNTIME_TOKEN` when that env var is set. **Per-job schedule calls go through the submitter's own bearer** (via `runtime_token_var`) — no static service-account credential is involved in the per-user path, so audit trails on the remote attribute each schedule to the real lum.id user. The URL is trusted implicitly — point `LUMILAKE_REMOTE_OPTIMIZER_URL` only at a service you control. Plain `http://` is rejected unless the host resolves to loopback.

## Tests

```bash
uv sync --all-extras
uv run pytest
```
