"""FlowMesh resource registrar — the shared registrar with a FlowMesh name.

FlowMesh fires ``register`` after each WORKFLOW / TASK / NODE / WORKER is
persisted and ``deregister`` after each hard-delete, and runs ``reconcile`` once
at startup with every live resource. The behavior lives in
``_core.registrar.ResourceRegistrar``; this subclass only sets the log name.
"""

from ._core import ResourceRegistrar


class LumidResourceRegistrar(ResourceRegistrar):
    name = "lumid_flowmesh_plugin.registrar"
