"""
test_gui.py -- Automated unit tests for GhostDrive PyQt6 GUI components.
"""

import sys
import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication

from ghostdrive.gui.styles import get_stylesheet
from ghostdrive.gui.preflight_wizard import PreflightWizard
from ghostdrive.gui.unlock_view import UnlockView
from ghostdrive.gui.main_view import MainWindow, TierAdvisorDialog
from ghostdrive.crypto.keystore import KeystoreManager
from ghostdrive.database.db import GhostDriveDB

# Standard pytest fixture for QApplication lifecycle
@pytest.fixture(scope="session")
def qapp() -> QApplication:
    import asyncio
    import qasync
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = None
    if not isinstance(loop, qasync.QEventLoop):
        loop = qasync.QEventLoop(app)
        asyncio.set_event_loop(loop)
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


from tests.conftest import FAST_ARGON2_PARAMS  # noqa: E402


def test_unlock_view_routing(qapp, tmp_path) -> None:
    """Verify UnlockView loads and routes screen stack according to keystore file existence."""
    keystore_path = tmp_path / "keystore.json"
    
    # 1. No keystore -> Routes to first-run setup stack
    view_fresh = UnlockView(keystore_path=keystore_path)
    assert view_fresh.stack.currentWidget() == view_fresh.first_run_chooser_widget
    
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
    from PyQt6.QtCore import QSettings
    settings = QSettings("GhostDrive", "Preferences")
    orig_theme = settings.value("theme")
    orig_accent = settings.value("accent_color")
    settings.clear()

    try:
        km = KeystoreManager(tmp_path / "keystore.json")
        # Stub active state
        km._master_key_buf = type('Stub', (), {'key': b"\x00"*32, '_zeroed': False})()
        km._hkdf_salt = b"\x01"*32
        km._genesis_seed = b"\x02"*32
        
        db = GhostDriveDB(tmp_path / "ghostdrive.db", b"\x00"*32, b"\x01"*32, b"\x00"*32)
        db.open()

        dashboard = MainWindow(km, db)
        
        # Verify views stack matches nav count
        assert dashboard.stacked_views.count() == 8
        assert len(dashboard.nav_buttons) == 8
        assert dashboard.files_table.columnCount() == 5
        assert dashboard.trash_table.columnCount() == 4
        
        # Test color accent changes
        assert dashboard.current_accent == "#8b5cf6"  # Default Neon Violet
        dashboard.accent_combo.setCurrentIndex(1)      # Switch to Electric Cyan
        assert dashboard.current_accent == "#06b6d4"
        
        dashboard.close()
        db.close()
    finally:
        settings.clear()
        if orig_theme is not None:
            settings.setValue("theme", orig_theme)
        if orig_accent is not None:
            settings.setValue("accent_color", orig_accent)


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
    
    db = GhostDriveDB(tmp_path / "ghostdrive.db", b"\x00"*32, b"\x01"*32, b"\x00"*32)
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
    
    db = GhostDriveDB(tmp_path / "ghostdrive.db", b"\x00"*32, b"\x01"*32, b"\x00"*32)
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
    
    db = GhostDriveDB(tmp_path / "ghostdrive.db", b"\x00"*32, b"\x01"*32, b"\x00"*32)
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
    
    db = GhostDriveDB(tmp_path / "ghostdrive.db", b"\x00"*32, b"\x01"*32, b"\x00"*32)
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


def test_weekly_digest_scheduling(qapp, tmp_path):
    """Verify that check_and_trigger_weekly_digest can be called and executes send_weekly_digest."""
    km = KeystoreManager(tmp_path / "keystore.json")
    km._master_key_buf = type('Stub', (), {'key': b"\x00"*32, '_zeroed': False})()
    km._hkdf_salt = b"\x01"*32
    km._genesis_seed = b"\x02"*32
    
    db = GhostDriveDB(tmp_path / "ghostdrive.db", b"\x00"*32, b"\x01"*32, b"\x00"*32)
    db.open()
    
    dashboard = MainWindow(km, db)
    
    # Mock send_weekly_digest on notifications
    called = False
    def mock_send():
        nonlocal called
        called = True
        
    dashboard.notifications.send_weekly_digest = mock_send
    
    # Trigger the method directly
    dashboard.check_and_trigger_weekly_digest()
    
    assert called is True
    
    dashboard.close()
    db.close()


@pytest.mark.asyncio
async def test_hidden_space_ingestion(qapp, tmp_path):
    """Verify that Hidden Space ingestion securely erases the original file after successful upload."""
    from ghostdrive.gui.main_view import MainWindow
    from unittest.mock import AsyncMock, MagicMock, patch
    from PyQt6.QtWidgets import QDialog
    import asyncio

    km = KeystoreManager(tmp_path / "keystore.json")
    km._master_key_buf = type('Stub', (), {'key': b"\x00"*32, '_zeroed': False})()
    km._hkdf_salt = b"\x01"*32
    km._genesis_seed = b"\x02"*32

    db = GhostDriveDB(tmp_path / "ghostdrive.db", b"\x00"*32, b"\x01"*32, b"\x00"*32)
    db.open()

    # 1. Insert a healthy backend into the DB
    db._conn.execute(
        """INSERT INTO backends
           (id, type, credentials_ref, status, priority, quota_used, quota_limit, quota_reserved)
           VALUES ('backend-1', 'local', 'ref:test', 'healthy', 1, 0, 1073741824, 0)"""
    )

    # 2. Create the MainWindow
    dashboard = MainWindow(km, db)

    # 3. Stub/mock the active backend object in dashboard
    mock_backend = MagicMock()
    mock_backend.id = "backend-1"
    mock_backend.type = "local"
    mock_backend.connect = AsyncMock()
    mock_backend.logical_chunk_bytes = 50 * 1024 * 1024

    # Mock the backend upload method to return a reference ID
    mock_backend.upload = AsyncMock(return_value="ref-12345")

    dashboard.active_backends = {"local": mock_backend}

    # 4. Create the original file to ingest
    temp_file_path = tmp_path / "original_sensitive.txt"
    temp_file_path.write_bytes(b"Top secret content" * 100)
    assert temp_file_path.exists()

    # 5. Mock the TierAdvisorDialog
    mock_dialog = MagicMock()
    mock_dialog.exec = MagicMock(return_value=QDialog.DialogCode.Accepted)
    mock_dialog.selected_tier = "DISPOSABLE"
    mock_dialog.secure_erase_original = True

    # Track tasks
    dashboard._upload_tasks = set()

    # We patch the TierAdvisorDialog import from main_view
    with patch("ghostdrive.gui.main_view.TierAdvisorDialog", return_value=mock_dialog):
        await dashboard.ingest_file(str(temp_file_path))

    # Wait for all upload tasks to complete
    await asyncio.gather(*dashboard._upload_tasks)

    # 6. Wait for the secure erase background task to complete and delete the file
    for _ in range(30):
        if not temp_file_path.exists():
            break
        await asyncio.sleep(0.1)

    # Verify original file is gone
    assert not temp_file_path.exists()

    # Verify the file record exists in the database
    with db.transaction():
        file_row = db._conn.execute(
            "SELECT id, tier FROM files WHERE name = 'original_sensitive.txt'"
        ).fetchone()
    assert file_row is not None
    assert file_row["tier"] == "DISPOSABLE"

    # Verify the secure erase log is present in the destructive operations ledger
    with db.transaction():
        logs = db.list_destructive_ops(session_id="hidden-space-ingestion")
    assert len(logs) == 1
    assert logs[0]["result"] == "completed"

    dashboard.close()
    db.close()


@pytest.mark.asyncio
async def test_hidden_space_ingestion_failure_does_not_erase(qapp, tmp_path):
    """Verify that the original file is NOT erased if any chunk upload fails during ingestion."""
    from ghostdrive.gui.main_view import MainWindow
    from unittest.mock import AsyncMock, MagicMock, patch
    from PyQt6.QtWidgets import QDialog
    import asyncio

    km = KeystoreManager(tmp_path / "keystore.json")
    km._master_key_buf = type('Stub', (), {'key': b"\x00"*32, '_zeroed': False})()
    km._hkdf_salt = b"\x01"*32
    km._genesis_seed = b"\x02"*32

    db = GhostDriveDB(tmp_path / "ghostdrive.db", b"\x00"*32, b"\x01"*32, b"\x00"*32)
    db.open()

    # 1. Insert a healthy backend into the DB
    db._conn.execute(
        """INSERT INTO backends
           (id, type, credentials_ref, status, priority, quota_used, quota_limit, quota_reserved)
           VALUES ('backend-1', 'local', 'ref:test', 'healthy', 1, 0, 1073741824, 0)"""
    )

    # 2. Create the MainWindow
    dashboard = MainWindow(km, db)

    # 3. Stub/mock the active backend object in dashboard
    mock_backend = MagicMock()
    mock_backend.id = "backend-1"
    mock_backend.type = "local"
    mock_backend.connect = AsyncMock()
    mock_backend.logical_chunk_bytes = 50 * 1024 * 1024

    # Mock the backend upload method to fail
    mock_backend.upload = AsyncMock(side_effect=Exception("Network upload failure"))

    dashboard.active_backends = {"local": mock_backend}

    # 4. Create the original file to ingest
    temp_file_path = tmp_path / "original_sensitive.txt"
    temp_file_path.write_bytes(b"Top secret content" * 100)
    assert temp_file_path.exists()

    # 5. Mock the TierAdvisorDialog
    mock_dialog = MagicMock()
    mock_dialog.exec = MagicMock(return_value=QDialog.DialogCode.Accepted)
    mock_dialog.selected_tier = "DISPOSABLE"
    mock_dialog.secure_erase_original = True

    # Track tasks
    dashboard._upload_tasks = set()

    # We patch the TierAdvisorDialog import from main_view
    with patch("ghostdrive.gui.main_view.TierAdvisorDialog", return_value=mock_dialog):
        await dashboard.ingest_file(str(temp_file_path))

    # Wait for all upload tasks to complete (they will fail and handle exceptions)
    await asyncio.gather(*dashboard._upload_tasks)

    # 6. Wait a short period and assert the file still exists
    await asyncio.sleep(0.5)
    assert temp_file_path.exists()

    dashboard.close()
    db.close()


@pytest.mark.asyncio
async def test_local_folder_backend_lifecycle(qapp, tmp_path):
    """Verify the full lifecycle of a local folder backend: registration, loading, and successful chunk upload."""
    from ghostdrive.gui.main_view import MainWindow
    from ghostdrive.pipeline.drive_registration import DriveRegistrar
    from ghostdrive.backends.local_fs_backend import LocalFSBackend
    from unittest.mock import MagicMock, patch
    import asyncio

    km = KeystoreManager(tmp_path / "keystore.json")
    km._master_key_buf = type('Stub', (), {'key': b"\x00"*32, '_zeroed': False})()
    km._hkdf_salt = b"\x01"*32
    km._genesis_seed = b"\x02"*32

    db = GhostDriveDB(tmp_path / "ghostdrive.db", b"\x00"*32, b"\x01"*32, b"\x00"*32)
    db.open()

    # 1. Register a local folder via DriveRegistrar
    backup_folder = tmp_path / "my_backup_dir"
    backup_folder.mkdir()

    registrar = DriveRegistrar(db)
    reg_result = registrar.register_local_folder(backup_folder, "My Secret Folder Backup")

    backend_id = reg_result["backend_id"]
    folder_uuid = reg_result["drive_uuid"]
    assert backend_id is not None
    assert folder_uuid.startswith("folder-")

    # Verify DB records
    with db.transaction():
        b_row = db._conn.execute("SELECT * FROM backends WHERE id = ?", (backend_id,)).fetchone()
        d_row = db._conn.execute("SELECT * FROM drive_registry WHERE backend_id = ?", (backend_id,)).fetchone()

    assert b_row is not None
    assert b_row["type"] == "local"
    assert d_row is not None
    assert d_row["drive_label"] == "My Secret Folder Backup"
    assert d_row["drive_type"] == "unknown"
    assert d_row["mount_hint"] == str(backup_folder.resolve())

    # 2. Instantiate MainWindow and verify that the backend is automatically loaded on startup
    dashboard = MainWindow(km, db)

    # Check if the folder backend is loaded in active_backends
    assert backend_id in dashboard.active_backends
    b_obj = dashboard.active_backends[backend_id]
    assert isinstance(b_obj, LocalFSBackend)
    assert b_obj.id == backend_id
    assert b_obj.label == "My Secret Folder Backup"
    assert b_obj.root_path.resolve() == backup_folder.resolve()

    # 3. Create a test file and ingest it using the newly registered folder backend
    temp_file_path = tmp_path / "secret_document.pdf"
    temp_file_path.write_bytes(b"Top secret backup data" * 50)

    # Mock the TierAdvisorDialog to confirm upload to DISPOSABLE tier
    mock_dialog = MagicMock()
    mock_dialog.exec = MagicMock(return_value=1)
    mock_dialog.selected_tier = "DISPOSABLE"
    mock_dialog.secure_erase_original = False

    dashboard._upload_tasks = set()

    with patch("ghostdrive.gui.main_view.TierAdvisorDialog", return_value=mock_dialog):
        await dashboard.ingest_file(str(temp_file_path))

    # Wait for the chunk upload task to finish
    await asyncio.gather(*dashboard._upload_tasks)

    # Verify that the chunk file is actually written inside our backup folder!
    chunk_files = list(backup_folder.glob("*.gdc")) or list(backup_folder.glob(".*.gdc"))
    assert len(chunk_files) == 1
    assert chunk_files[0].stat().st_size > 0

    # Verify chunk record and confirmed location in database
    with db.transaction():
        file_row = db._conn.execute("SELECT id FROM files WHERE name = 'secret_document.pdf'").fetchone()
        assert file_row is not None
        chunk_row = db._conn.execute("SELECT id FROM chunks WHERE file_id = ?", (file_row["id"],)).fetchone()
        assert chunk_row is not None
        loc_row = db._conn.execute("SELECT * FROM chunk_locations WHERE chunk_id = ?", (chunk_row["id"],)).fetchone()
        assert loc_row is not None
        assert loc_row["backend_id"] == backend_id
        assert loc_row["status"] == "confirmed"

    dashboard.close()
    db.close()


