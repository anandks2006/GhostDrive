"""
test_portable_vault.py — Portable vault (.gdvault) export/import envelope.
"""

import json
import zipfile
import io

import pytest

from ghostdrive.crypto.hkdf import derive_index_mac_key, derive_index_backup_enc_key
from ghostdrive.crypto.keystore import KeystoreManager
from ghostdrive.database.db import GhostDriveDB
from ghostdrive.exceptions import AuthenticationError
from ghostdrive.services import portable
from ghostdrive.services.portable import (
    PortableVaultError,
    export_portable_vault,
    import_portable_vault,
    inspect_portable_vault,
)
from ghostdrive.web.state import state
from tests.conftest import FAST_ARGON2_PARAMS

PASS = b"portable-pass"
SLOW = {"time_cost": 1, "memory_cost": 8_192, "parallelism": 1, "hash_len": 32}


@pytest.fixture
def unlocked_vault(tmp_path):
    """Fresh unlocked keystore + open index DB wired into global state."""
    state.clean_shutdown()
    state.app_data_dir = tmp_path
    state.keystore_path = tmp_path / "keystore.json"
    state.db_path = tmp_path / "ghostdrive.db"

    km = KeystoreManager(state.keystore_path)
    seed = km.create_new(PASS, calibrate=False, argon2_params=FAST_ARGON2_PARAMS)
    km.verify_and_save(seed)
    state.km = km

    db = GhostDriveDB(
        path=state.db_path,
        ledger_key=derive_index_mac_key(bytes(km.master_key), km.hkdf_salt),
        genesis_seed=km._genesis_seed,
        master_key=bytes(km.master_key),
    )
    db.open()
    db._conn.execute(
        """INSERT INTO files (id, name, path, size, mime_type, tier, created_at, modified_at)
           VALUES ('f1', 'doc.txt', '/doc.txt', 5, 'text/plain', 'IMPORTANT', '2026-01-01', '2026-01-01')"""
    )
    db._conn.commit()
    state.db = db

    yield state

    state.clean_shutdown()


class TestEnvelope:
    def test_export_writes_sealed_file(self, unlocked_vault, tmp_path):
        out = tmp_path / "move.gdvault"
        res = export_portable_vault(
            out, PASS, unlocked_vault.keystore_path,
            db=unlocked_vault.db, argon2_params=SLOW, label="laptop move",
        )
        assert res["status"] == "success"
        assert res["has_index"] is True
        blob = out.read_bytes()
        assert blob[:8] == b"GDVAULT1"
        # The keystore JSON must not appear in cleartext inside the envelope.
        assert b"ciphertext" not in blob
        assert b"argon2_salt" not in blob

    def test_export_without_index(self, unlocked_vault, tmp_path):
        out = tmp_path / "ks-only.gdvault"
        res = export_portable_vault(
            out, PASS, unlocked_vault.keystore_path,
            include_index=False, argon2_params=SLOW,
        )
        assert res["has_index"] is False
        assert res["path"] == str(out)

    def test_export_requires_keystore(self, tmp_path):
        with pytest.raises(PortableVaultError, match="No keystore"):
            export_portable_vault(
                tmp_path / "x.gdvault", PASS, tmp_path / "missing.json",
                include_index=False, argon2_params=SLOW,
            )

    def test_inspect_wrong_passphrase_fails(self, unlocked_vault, tmp_path):
        out = tmp_path / "v.gdvault"
        export_portable_vault(
            out, PASS, unlocked_vault.keystore_path,
            include_index=False, argon2_params=SLOW,
        )
        with pytest.raises(PortableVaultError, match="wrong passphrase"):
            inspect_portable_vault(out, b"nope")

    def test_inspect_not_a_vault(self, tmp_path):
        bogus = tmp_path / "bogus.bin"
        bogus.write_bytes(b"just some data")
        with pytest.raises(PortableVaultError, match="bad magic"):
            inspect_portable_vault(bogus, PASS)

    def test_inspect_returns_metadata_only(self, unlocked_vault, tmp_path):
        out = tmp_path / "v.gdvault"
        export_portable_vault(
            out, PASS, unlocked_vault.keystore_path,
            db=unlocked_vault.db, argon2_params=SLOW, label="my label",
        )
        info = inspect_portable_vault(out, PASS)
        assert info["status"] == "success"
        assert info["label"] == "my label"
        assert info["has_snapshot"] is True
        assert "keystore.json" in info["members"]
        assert "manifest.json" not in info["members"]  # not returned as content
        # The inspect result must not expose any member bytes.
        assert isinstance(info["manifest"]["members"], dict)
        for meta in info["manifest"]["members"].values():
            assert set(meta) == {"size", "blake3"}


class TestRoundtrip:
    def test_import_keystore_roundtrip(self, unlocked_vault, tmp_path):
        out = tmp_path / "v.gdvault"
        export_portable_vault(
            out, PASS, unlocked_vault.keystore_path,
            include_index=False, argon2_params=SLOW,
        )
        dest = tmp_path / "elsewhere" / "keystore.json"
        res = import_portable_vault(out, PASS, dest)
        assert res["status"] == "success"
        assert dest.exists()
        # Byte-identical keystore restores identical unlock behavior.
        assert dest.read_bytes() == unlocked_vault.keystore_path.read_bytes()

        km2 = KeystoreManager(dest)
        km2.unlock(PASS)
        assert bytes(km2.master_key) == bytes(unlocked_vault.km.master_key)

    def test_import_refuses_overwrite(self, unlocked_vault, tmp_path):
        out = tmp_path / "v.gdvault"
        export_portable_vault(
            out, PASS, unlocked_vault.keystore_path,
            include_index=False, argon2_params=SLOW,
        )
        dest = tmp_path / "keystore.json"  # already exists
        with pytest.raises(PortableVaultError, match="already exists"):
            import_portable_vault(out, PASS, dest)
        res = import_portable_vault(out, PASS, dest, overwrite=True)
        assert res["status"] == "success"

    def test_import_wrong_passphrase(self, unlocked_vault, tmp_path):
        out = tmp_path / "v.gdvault"
        export_portable_vault(
            out, PASS, unlocked_vault.keystore_path,
            include_index=False, argon2_params=SLOW,
        )
        with pytest.raises(PortableVaultError, match="wrong passphrase"):
            import_portable_vault(out, b"bad", tmp_path / "ks.json")

    def test_import_index_restores_db_bytes(self, unlocked_vault, tmp_path):
        """Snapshot in → decrypted index out, byte-identical to the source."""
        out = tmp_path / "v.gdvault"
        export_portable_vault(
            out, PASS, unlocked_vault.keystore_path,
            db=unlocked_vault.db, argon2_params=SLOW,
        )
        src_db = (tmp_path / "ghostdrive.db").read_bytes()

        index_dest = tmp_path / "restored" / "ghostdrive.db"
        res = import_portable_vault(
            out, PASS, tmp_path / "ks2.json", index_destination=index_dest
        )
        assert res["index_written"] == str(index_dest)
        # WAL checkpoint means restored bytes == the checkpointed source file.
        assert index_dest.read_bytes() == src_db

    def test_import_tampered_file_rejected(self, unlocked_vault, tmp_path):
        out = tmp_path / "v.gdvault"
        export_portable_vault(
            out, PASS, unlocked_vault.keystore_path,
            include_index=False, argon2_params=SLOW,
        )
        blob = bytearray(out.read_bytes())
        blob[-1] ^= 0xFF  # flip a ciphertext bit
        out.write_bytes(bytes(blob))
        with pytest.raises(PortableVaultError):
            import_portable_vault(out, PASS, tmp_path / "ks.json")


class TestArchiveIntegrity:
    def test_member_checksum_mismatch_detected(self, unlocked_vault, tmp_path, monkeypatch):
        """If an inner member is swapped after sealing, parse must fail closed."""
        out = tmp_path / "v.gdvault"
        export_portable_vault(
            out, PASS, unlocked_vault.keystore_path,
            include_index=False, argon2_params=SLOW,
        )
        header, archive = portable._open_envelope(out.read_bytes(), PASS)
        parsed = portable._parse_archive(archive)
        assert parsed["manifest"]["format"] == portable.FORMAT

        # Rebuild a zip with a tampered keystore but the original manifest.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(portable.MANIFEST_NAME, json.dumps(parsed["manifest"]))
            zf.writestr(portable.KEYSTORE_NAME, b'{"tampered": true}')
        with pytest.raises(PortableVaultError, match="Checksum mismatch"):
            portable._parse_archive(buf.getvalue())

    def test_non_vault_zip_rejected(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", "hello")
        with pytest.raises(PortableVaultError, match="no manifest"):
            portable._parse_archive(buf.getvalue())
