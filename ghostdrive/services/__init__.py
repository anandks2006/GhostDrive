"""Shared service layer used by both the FastAPI web app and the CLI.

Names are resolved lazily (PEP 562): importing a single service module — e.g.
``ghostdrive.services.recovery_kit`` for the offline restore tool — must not
drag in ``services.context``, which imports every backend plugin and the web
state. Explicit imports like ``from ghostdrive.services import files`` still
work through the normal submodule import machinery.
"""

from typing import Any

__all__ = [
    "active_backends",
    "build_backend",
    "ensure_local_backend",
    "get_master_key",
    "hkdf_salt",
    "nonce_manager",
    "require_db",
    "require_unlocked",
]

_LAZY = {
    "active_backends",
    "build_backend",
    "ensure_local_backend",
    "get_master_key",
    "hkdf_salt",
    "nonce_manager",
    "require_db",
    "require_unlocked",
}


def __getattr__(name: str) -> Any:
    if name in _LAZY:
        from ghostdrive.services import context

        return getattr(context, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(__all__) | _LAZY)
