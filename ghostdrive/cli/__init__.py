"""Command-line companion for GhostDrive (headless / scripted use).

``main`` is resolved lazily so that importing lightweight subcommands —
notably the offline recovery tool — does NOT pull in the full web/backend
stack (FastAPI, uvicorn, telethon, discord).
"""

from typing import Any

__all__ = ["main"]


def __getattr__(name: str) -> Any:
    if name == "main":
        from ghostdrive.cli.ghostdrive_cli import main

        return main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
