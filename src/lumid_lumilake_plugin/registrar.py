"""Lumilake resource registrar — the shared registrar with a Lumilake name.

Lumilake fires ``register`` after each JOB / TRACE / ARTIFACT is persisted and
``deregister`` after each hard-delete, and runs ``reconcile`` per kind. The
behavior lives in ``_core.registrar.ResourceRegistrar``; this subclass only sets
the log name.
"""

from ._core import ResourceRegistrar


class LumidResourceRegistrar(ResourceRegistrar):
    name = "lumid_lumilake_plugin.registrar"
