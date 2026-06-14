"""
test_gui.py -- Automated unit tests for GhostDrive PyQt6 GUI components.
"""

import sys
import os
import pytest
from pathlib import Path
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication

from ghostdrive.gui.styles import get_stylesheet, THEME_PALETTES
from ghostdrive.gui.preflight_wizard import PreflightWizard, DiagnosticsWorker
from ghostdrive.gui.unlock_view import UnlockView
from ghostdrive.gui.main_view import MainWindow, TierAdvisorDialog
from ghostdrive.gui.telemetry_view import TelemetryView
from ghostdrive.crypto.keystore import KeystoreManager
from ghostdrive.database.db import GhostDriveDB

# Standard pytest fixture for QApplication lifecycle
@pytest.fixture(scope="session")
def qapp() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


def test_theme_stylesheets(qapp) -> None:
    """Validate that theme generator functions and outputs valid QSS keys."""
    dark_qss = get_stylesheet("dark")
    light_qss = get_stylesheet("light")
    
    assert "bg_main" not in dark_qss  # Variables should be resolved
    assert "#121214" in dark_qss
    assert "#f4f4f5" in light_qss
    assert "GlassCard" in dark_qss


def test_preflight_wizard_init(qapp) -> None:
    """Verify pre-flight diagnostics dialog loads widgets correctly."""
    wizard = PreflightWizard()
    assert wizard.windowTitle() == "GhostDrive Diagnostics"
    assert wizard.progress_bar.value() == 0
    assert wizard.retry_btn.isEnabled() is False
    assert wizard.skip_btn.isEnabled() is False


from tests.conftest import FAST_ARGON2_PARAMS


def test_unlock_view_routing(qapp, tmp_path) -> None:
    """Verify UnlockView loads and routes screen stack according to keystore file existence."""
    keystore_path = tmp_path / "keystore.json"
    
    # 1. No keystore -> Routes to first-run setup stack
    view_fresh = UnlockView(keystore_path=keystore_path)
    assert view_fresh.stack.currentWidget() == view_fresh.create_widget
    
    # 2. Keystore exists -> Routes to unlock screen
    keystore_path.touch()
    view_existing = UnlockView(keystore_path=keystore_path)
    assert view_existing.stack.currentWidget() == view_existing.unlock_widget


def test_unlock_view_wrong_password(qapp, tmp_path) -> None:
    """Verify UnlockView handles incorrect password without crashing and displays the red label."""
    keystore_path = tmp_path / "keystore.json"
    km = KeystoreManager(keystore_path)
    phrase = km.create_new(b"correct_password", calibrate=False, argon2_params=FAST_ARGON2_PARAMS)
    km.verify_and_save(phrase)
    
    view = UnlockView(keystore_path=keystore_path)
    assert view.stack.currentWidget() == view.unlock_widget
    
    # Try unlocking with wrong password
    view.pass_input.setText("wrong_password")
    
    # Trigger unlock
    view.on_unlock_clicked()
    
    # The error label should be visible (not hidden) and say "Incorrect password."
    assert view.unlock_error_label.text() == "Incorrect password."
    assert view.unlock_error_label.isHidden() is False


def test_tier_advisor_ingestion_heuristics(qapp) -> None:
    """Check that Storage Tier Advisor dialog resolves correct suggestions."""
    # Small password key -> CRITICAL
    adv_keys = TierAdvisorDialog(None, "secrets.pem", 512, "application/x-x509-ca-cert")
    assert adv_keys.selected_tier == "CRITICAL"

    # Large zip archive -> DISPOSABLE
    adv_zip = TierAdvisorDialog(None, "backup.zip", 100 * 1024 * 1024, "application/zip")
    assert adv_zip.selected_tier == "DISPOSABLE"

    # Regular file -> IMPORTANT
    adv_doc = TierAdvisorDialog(None, "document.docx", 2048, "application/vnd.openxmlformats-officedocument")
    assert adv_doc.selected_tier == "IMPORTANT"


def test_main_dashboard_views(qapp, tmp_path) -> None:
    """Ensure dashboard structures load child telemetry and table lists."""
    km = KeystoreManager(tmp_path / "keystore.json")
    # Stub active state
    km._master_key_buf = type('Stub', (), {'key': b"\x00"*32, '_zeroed': False})()
    km._hkdf_salt = b"\x01"*32
    km._genesis_seed = b"\x02"*32
    
    db = GhostDriveDB(tmp_path / "ghostdrive.db", b"\x00"*32, b"\x01"*32)
    db.open()

    dashboard = MainWindow(km, db)
    
    # Verify views stack matches nav count
    assert dashboard.stacked_views.count() == 5
    assert dashboard.nav_list.count() == 5
    assert dashboard.files_table.columnCount() == 5
    assert dashboard.trash_table.columnCount() == 4
    
    # Test color accent changes
    assert dashboard.current_accent == "#8b5cf6"  # Default Neon Violet
    dashboard.accent_combo.setCurrentIndex(1)      # Switch to Electric Cyan
    assert dashboard.current_accent == "#06b6d4"
    
    dashboard.close()
    db.close()


def test_auto_start_manager(monkeypatch, tmp_path):
    """Test AutoStartManager platform-agnostic auto-start registry/file writes."""
    from ghostdrive.gui.autostart import AutoStartManager
    
    # Mock platform.system
    # 1. Linux
    monkeypatch.setattr("platform.system", lambda: "Linux")
    home = tmp_path / "home"
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    
    # Enable autostart
    res = AutoStartManager.enable()
    assert res is True
    desktop_file = home / ".config" / "autostart" / "ghostdrive.desktop"
    assert desktop_file.exists()
    assert "[Desktop Entry]" in desktop_file.read_text(encoding="utf-8")
    assert AutoStartManager.is_enabled() is True
    
    # Disable autostart
    res = AutoStartManager.disable()
    assert res is True
    assert not desktop_file.exists()
    assert AutoStartManager.is_enabled() is False

    # 2. Darwin (macOS)
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    res = AutoStartManager.enable()
    assert res is True
    plist_file = home / "Library" / "LaunchAgents" / "com.ghostdrive.plist"
    assert plist_file.exists()
    assert "<plist" in plist_file.read_text(encoding="utf-8")
    assert AutoStartManager.is_enabled() is True
    
    res = AutoStartManager.disable()
    assert res is True
    assert not plist_file.exists()
    assert AutoStartManager.is_enabled() is False

    # 3. Windows
    monkeypatch.setattr("platform.system", lambda: "Windows")
    
    mock_reg = {}
    class MockKey:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        
    import sys
    import types
    winreg_mock = types.ModuleType("winreg")
    winreg_mock.HKEY_CURRENT_USER = "HKEY_CURRENT_USER"
    winreg_mock.REG_SZ = 1
    winreg_mock.KEY_READ = 2
    winreg_mock.KEY_SET_VALUE = 4
    
    def mock_OpenKey(hkey, path, reserved=0, access=0):
        return MockKey()
    
    def mock_SetValueEx(key, name, reserved, type_id, value):
        mock_reg[name] = value
        
    def mock_QueryValueEx(key, name):
        if name in mock_reg:
            return mock_reg[name], 1
        raise FileNotFoundError()
        
    def mock_DeleteValue(key, name):
        if name in mock_reg:
            del mock_reg[name]
        else:
            raise FileNotFoundError()
            
    winreg_mock.OpenKey = mock_OpenKey
    winreg_mock.SetValueEx = mock_SetValueEx
    winreg_mock.QueryValueEx = mock_QueryValueEx
    winreg_mock.DeleteValue = mock_DeleteValue
    
    monkeypatch.setitem(sys.modules, "winreg", winreg_mock)
    
    res = AutoStartManager.enable()
    assert res is True
    assert mock_reg["GhostDrive"] is not None
    assert AutoStartManager.is_enabled() is True
    
    res = AutoStartManager.disable()
    assert res is True
    assert "GhostDrive" not in mock_reg
    assert AutoStartManager.is_enabled() is False


def test_activity_feed(qapp, tmp_path):
    """Test that the recent activity log widget records and formats entries."""
    km = KeystoreManager(tmp_path / "keystore.json")
    km._master_key_buf = type('Stub', (), {'key': b"\x00"*32, '_zeroed': False})()
    km._hkdf_salt = b"\x01"*32
    km._genesis_seed = b"\x02"*32
    
    db = GhostDriveDB(tmp_path / "ghostdrive.db", b"\x00"*32, b"\x01"*32)
    db.open()
    
    dashboard = MainWindow(km, db)
    dashboard.add_activity_log("Test activity message")
    
    assert dashboard.activity_list.count() == 1
    item = dashboard.activity_list.item(0)
    assert "Test activity message" in item.text()
    
    # Verify limit is respected (max 100 entries)
    for i in range(110):
        dashboard.add_activity_log(f"Msg {i}")
    assert dashboard.activity_list.count() == 100
    
    dashboard.close()
    db.close()


def test_gui_sorting(qapp, tmp_path):
    """Verify sorting behavior on files table."""
    km = KeystoreManager(tmp_path / "keystore.json")
    km._master_key_buf = type('Stub', (), {'key': b"\x00"*32, '_zeroed': False})()
    km._hkdf_salt = b"\x01"*32
    km._genesis_seed = b"\x02"*32
    
    db = GhostDriveDB(tmp_path / "ghostdrive.db", b"\x00"*32, b"\x01"*32)
    db.open()
    
    db.insert_file({
        "id": "file-1",
        "name": "B_file.txt",
        "path": "/files/B_file.txt",
        "size": 100,
        "mime_type": "text/plain",
        "tier": "CRITICAL",
        "created_at": "2026-06-13T12:00:00Z",
        "modified_at": "2026-06-13T12:00:00Z",
        "version": 1,
        "version_of": None,
        "tombstone": 0,
        "tombstone_at": None,
    })
    db.insert_file({
        "id": "file-2",
        "name": "A_file.txt",
        "path": "/files/A_file.txt",
        "size": 200,
        "mime_type": "text/plain",
        "tier": "IMPORTANT",
        "created_at": "2026-06-13T12:01:00Z",
        "modified_at": "2026-06-13T12:01:00Z",
        "version": 1,
        "version_of": None,
        "tombstone": 0,
        "tombstone_at": None,
    })
    
    dashboard = MainWindow(km, db)
    dashboard.refresh_files()
    
    dashboard.files_table.sortItems(1, Qt.SortOrder.AscendingOrder)
    assert dashboard.files_table.item(0, 1).text() == "A_file.txt"
    assert dashboard.files_table.item(1, 1).text() == "B_file.txt"
    
    dashboard.files_table.sortItems(1, Qt.SortOrder.DescendingOrder)
    assert dashboard.files_table.item(0, 1).text() == "B_file.txt"
    assert dashboard.files_table.item(1, 1).text() == "A_file.txt"
    
    dashboard.close()
    db.close()


def test_gui_multi_select(qapp, tmp_path):
    """Confirm bulk operations collect selected file and trash IDs correctly."""
    km = KeystoreManager(tmp_path / "keystore.json")
    km._master_key_buf = type('Stub', (), {'key': b"\x00"*32, '_zeroed': False})()
    km._hkdf_salt = b"\x01"*32
    km._genesis_seed = b"\x02"*32
    
    db = GhostDriveDB(tmp_path / "ghostdrive.db", b"\x00"*32, b"\x01"*32)
    db.open()
    
    db.insert_file({
        "id": "file-1",
        "name": "file1.txt",
        "path": "/files/file1.txt",
        "size": 100,
        "mime_type": "text/plain",
        "tier": "CRITICAL",
        "created_at": "2026-06-13T12:00:00Z",
        "modified_at": "2026-06-13T12:00:00Z",
        "version": 1,
        "version_of": None,
        "tombstone": 0,
        "tombstone_at": None,
    })
    db.insert_file({
        "id": "file-2",
        "name": "file2.txt",
        "path": "/files/file2.txt",
        "size": 200,
        "mime_type": "text/plain",
        "tier": "IMPORTANT",
        "created_at": "2026-06-13T12:01:00Z",
        "modified_at": "2026-06-13T12:01:00Z",
        "version": 1,
        "version_of": None,
        "tombstone": 0,
        "tombstone_at": None,
    })
    
    dashboard = MainWindow(km, db)
    dashboard.refresh_files()
    
    dashboard.files_table.selectAll()
    selected_ids = dashboard.get_selected_file_ids()
    assert len(selected_ids) == 2
    assert "file-1" in selected_ids
    assert "file-2" in selected_ids
    
    dashboard.close()
    db.close()


def test_virtual_folders(qapp, tmp_path):
    """Verify virtual folder navigation path pushes and directory double-click triggers."""
    km = KeystoreManager(tmp_path / "keystore.json")
    km._master_key_buf = type('Stub', (), {'key': b"\x00"*32, '_zeroed': False})()
    km._hkdf_salt = b"\x01"*32
    km._genesis_seed = b"\x02"*32
    
    db = GhostDriveDB(tmp_path / "ghostdrive.db", b"\x00"*32, b"\x01"*32)
    db.open()
    
    db.insert_file({
        "id": "file-1",
        "name": "doc.pdf",
        "path": "/files/Documents/doc.pdf",
        "size": 100,
        "mime_type": "application/pdf",
        "tier": "IMPORTANT",
        "created_at": "2026-06-13T12:00:00Z",
        "modified_at": "2026-06-13T12:00:00Z",
        "version": 1,
        "version_of": None,
        "tombstone": 0,
        "tombstone_at": None,
    })
    
    dashboard = MainWindow(km, db)
    dashboard.refresh_files()
    
    assert "Documents" in dashboard._table_file_ids
    folder_idx = dashboard._table_file_ids.index("Documents")
    assert dashboard._table_item_types[folder_idx] == "folder"
    
    dashboard.navigate_to_folder("Documents")
    assert dashboard.current_folder_path == "/files/Documents"
    
    assert "file-1" in dashboard._table_file_ids
    assert dashboard._table_item_types[dashboard._table_file_ids.index("file-1")] == "file"
    
    dashboard.navigate_up()
    assert dashboard.current_folder_path == "/files"
    
    dashboard.close()
    db.close()
