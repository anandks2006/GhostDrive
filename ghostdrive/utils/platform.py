import os
from pathlib import Path

def get_app_data_dir() -> Path:
    """Returns the absolute path to the GhostDrive application data directory.

    Guarantees the directory exists before returning.
    """
    path = Path(os.environ.get("APPDATA", os.path.expanduser("~"))) / ".ghostdrive"
    path.mkdir(parents=True, exist_ok=True)
    return path
