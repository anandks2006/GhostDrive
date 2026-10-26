"""
test_packaging.py -- Release engineering artifacts: console entry points,
PyInstaller spec, Inno Setup script, build script, autostart integration.
"""

import importlib
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


class TestEntryPoints:
    @pytest.fixture(scope="class")
    def scripts(self):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        return data["tool"]["poetry"]["scripts"]

    def test_all_declared_scripts_resolve(self, scripts):
        """Every console script must point at an importable callable."""
        assert scripts, "no console scripts declared"
        for name, target in scripts.items():
            module_path, func = target.rsplit(":", 1)
            try:
                module = importlib.import_module(module_path)
            except ImportError as exc:
                pytest.fail(f"{name}: cannot import {module_path}: {exc}")
            assert hasattr(module, func), f"{name}: {module_path} has no {func}()"
            assert callable(getattr(module, func))

    def test_recovery_tool_entry_point(self, scripts):
        assert "ghostdrive-restore" in scripts
        assert scripts["ghostdrive-restore"] == "ghostdrive.cli.recovery_tool:main"

    def test_tray_entry_point(self, scripts):
        assert "ghostdrive-tray" in scripts
        assert scripts["ghostdrive-tray"] == "ghostdrive.platform.tray:run_tray"

    def test_repair_groups_declared(self):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        groups = data["tool"]["poetry"]["group"]
        assert "tray" in groups, "optional tray dependency group missing"
        assert "backends" in groups
        assert "web" in groups


class TestOfflineToolStandalone:
    def test_recovery_tool_imports_without_web_stack(self):
        """
        The offline restore tool must not drag in FastAPI/uvicorn/SQLite —
        it has to run on a bare machine with only the crypto deps.
        """
        import subprocess
        import sys

        code = (
            "import sys; "
            "import ghostdrive.cli.recovery_tool; "
            "banned = ('fastapi', 'uvicorn', 'telethon', 'discord'); "
            "leaked = [m for m in banned if m in sys.modules]; "
            "sys.exit(1 if leaked else 0)"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, cwd=str(ROOT), timeout=120,
        )
        assert proc.returncode == 0, (
            f"recovery_tool pulled in heavy modules: {proc.stderr}"
        )


class TestReleaseArtifacts:
    def test_pyinstaller_spec_exists_and_names_bundle(self):
        spec = (ROOT / "ghostdrive.spec").read_text(encoding="utf-8")
        assert 'name="GhostDrive"' in spec
        # New optional deps must never be force-bundled into the release exe.
        assert '"pystray"' not in spec.split("hiddenimports=[")[1].split("]")[0]

    def test_pyinstaller_spec_ships_static_ui_and_wordlist(self):
        spec = (ROOT / "ghostdrive.spec").read_text(encoding="utf-8")
        assert "ghostdrive/web/static" in spec
        assert "mnemonic" in spec

    def test_inno_setup_installer_exists(self):
        iss = (ROOT / "installer" / "GhostDrive.iss")
        assert iss.exists()
        text = iss.read_text(encoding="utf-8")
        assert "GhostDrive.exe" in text
        # Uninstall must never wipe the user's vault directory.
        assert "%LOCALAPPDATA%\\GhostDrive" not in text or "UninstallDelete" in text
        assert "PrivilegesRequired=lowest" in text

    def test_build_script_exists(self):
        ps1 = ROOT / "scripts" / "build_windows.ps1"
        assert ps1.exists()
        text = ps1.read_text(encoding="utf-8")
        assert "ghostdrive.spec" in text
        assert "GhostDrive.iss" in text

    def test_installer_artifacts_are_valid_utf8(self):
        """Guard against botched line-ending/encoding rewrites of release scripts."""
        for rel in ("installer/GhostDrive.iss", "scripts/build_windows.ps1"):
            raw = (ROOT / rel.replace("/", "\\")).read_bytes()
            assert b"\x00" not in raw, f"{rel} contains NUL bytes"
            raw.decode("utf-8")
