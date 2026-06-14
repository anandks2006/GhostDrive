"""
GhostDrive — Encrypted, redundant, multi-backend personal cloud drive.

BCA Final Year Project 2026–27
Specification: GhostDrive_ProjectSpec_v1.2
"""

__version__ = "0.1.0-alpha"
__spec_version__ = "1.2"
__author__ = "Anand K S"

def main() -> None:
    """Launch the GhostDrive GUI application."""
    from ghostdrive.gui.__main__ import main as gui_main
    gui_main()

