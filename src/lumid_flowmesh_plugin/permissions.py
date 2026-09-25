"""FlowMesh authorization policy for the shared ``PermissionChecker`` engine.

Defines the FlowMesh scope vocabulary and ownership rules; the decision logic
lives in ``_core.permissions``.

* **Admin** (`*`, `flowmesh:*`, or `flowmesh:admin` in `principal.scopes`)
  bypasses every check.
* **Kind-level checks** (`resource.id is None`) require the matching scope:

  | (kind, action)        | scope                          |
  |-----------------------|--------------------------------|
  | WORKFLOW, READ        | `flowmesh:workflows:read`      |
  | WORKFLOW, WRITE       | `flowmesh:workflows:write`     |
  | TASK, READ            | `flowmesh:tasks:read`          |
  | RESULT, READ          | `flowmesh:results:read`        |
  | RESULT, WRITE         | `flowmesh:results:write`       |
  | NODE, READ            | `flowmesh:nodes:read`          |
  | NODE, WRITE           | `flowmesh:nodes:write`         |
  | WORKER, READ          | `flowmesh:workers:read`        |
  | WORKER, WRITE         | `flowmesh:workers:write`       |
  | SYSTEM, READ          | `flowmesh:system:read`         |

  A valid `(kind, action)` absent from the table is admin-only; an unrecognised
  kind or action is unsupported. Both deny.
* **Fleet kinds** — WORKER and NODE are shared infrastructure that no principal
  owns, so reading them — the list and any single worker or node — is
  authorized by `flowmesh:workers:read` / `flowmesh:nodes:read` alone rather
  than by per-id grants. Writes stay grant-only: `flowmesh:nodes:write` does not
  let a principal start, stop, or destroy workers on a node it holds no grant
  on. WORKFLOW/TASK/RESULT are deliberately excluded: they are per-principal and
  their ownership filter is the tenancy boundary.
* **Concrete-id checks** (other than fleet reads) require a grant whose level
  covers the action: READ needs `GrantLevel.READ`, mutating actions (WRITE,
  CANCEL) need `GrantLevel.WRITE`. The `admin` action is never grant-satisfiable. RESULT has
  no grants of its own — ownership is inferred from the owning task, so a
  concrete RESULT check resolves against the TASK grant of the same id.
"""

from flowmesh_hook import ResourceAction, ResourceKind

from ._core import GrantLevel, GrantStore, PermissionChecker, PermissionPolicy

_POLICY = PermissionPolicy(
    admin_scopes=frozenset({"*", "flowmesh:*", "flowmesh:admin"}),
    # Anything not in this map is admin-only at kind level.
    kind_level_scopes={
        (ResourceKind.WORKFLOW.value, ResourceAction.READ.value): "flowmesh:workflows:read",
        (ResourceKind.WORKFLOW.value, ResourceAction.WRITE.value): "flowmesh:workflows:write",
        (ResourceKind.TASK.value, ResourceAction.READ.value): "flowmesh:tasks:read",
        (ResourceKind.RESULT.value, ResourceAction.READ.value): "flowmesh:results:read",
        (ResourceKind.RESULT.value, ResourceAction.WRITE.value): "flowmesh:results:write",
        (ResourceKind.NODE.value, ResourceAction.READ.value): "flowmesh:nodes:read",
        (ResourceKind.NODE.value, ResourceAction.WRITE.value): "flowmesh:nodes:write",
        (ResourceKind.WORKER.value, ResourceAction.READ.value): "flowmesh:workers:read",
        (ResourceKind.WORKER.value, ResourceAction.WRITE.value): "flowmesh:workers:write",
        (ResourceKind.SYSTEM.value, ResourceAction.READ.value): "flowmesh:system:read",
    },
    # Grant level a concrete-id action needs. Actions absent here (e.g. `admin`)
    # are never satisfiable by a grant — only the admin-scope bypass clears them.
    required_level={
        ResourceAction.READ.value: GrantLevel.READ,
        ResourceAction.WRITE.value: GrantLevel.WRITE,
        ResourceAction.CANCEL.value: GrantLevel.WRITE,
    },
    # Kinds whose ownership lives under a different kind's grants.
    ownership_kind={ResourceKind.RESULT.value: ResourceKind.TASK.value},
    # Shared fleet infrastructure: nobody owns a worker or a node. They are
    # registered under the fleet's own credential, so their grants name that
    # principal and never a human one -- an ownership filter would return zero
    # rows for every real user. `flowmesh:workers:read` / `flowmesh:nodes:read`
    # are the authorization here. WORKFLOW/TASK/RESULT stay out: they are
    # per-principal and their filter is the tenancy boundary.
    fleet_kinds=frozenset({ResourceKind.WORKER.value, ResourceKind.NODE.value}),
    # Only reads: a fleet-wide read scope may show every worker and node, but a
    # kind-level write scope must not open mutation of every one of them.
    fleet_actions=frozenset({ResourceAction.READ.value}),
    valid_kinds=frozenset(k.value for k in ResourceKind),
    valid_actions=frozenset(a.value for a in ResourceAction),
)


class LumidPermissionChecker(PermissionChecker):
    name = "lumid_flowmesh_plugin.permissions"

    def __init__(self, store: GrantStore) -> None:
        super().__init__(store, _POLICY)
