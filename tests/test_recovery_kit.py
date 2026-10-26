"""
test_recovery_kit.py — Recovery kit export/combine + offline standalone restore.
"""

import json
import os
from pathlib import Path

import pytest

from ghostdrive.crypto.keystore import (
    KeystoreManager,
    entropy_to_mnemonic,
    mnemonic_to_entropy,
)
from ghostdrive.crypto.shamir import share_to_text, text_to_share
from ghostdrive.services.recovery_kit import (
    KIT_FILENAME,
    RecoveryKitError,
    combine_recovery_kit,
    collect_shares,
    export_recovery_kit,
    load_manifest,
    restore_keystore_from_key,
    share_summary,
)
from tests.conftest import FAST_ARGON2_PARAMS

KEY = os.urandom(32)


class TestExport:
    def test_export_writes_manifest_and_shares(self, tmp_path):
        manifest = export_recovery_kit(KEY, tmp_path, threshold=3, total=5)
        assert (tmp_path / KIT_FILENAME).exists()
        assert len(manifest["share_files"]) == 5
        for name in manifest["share_files"]:
            assert (tmp_path / name).exists()

    def test_manifest_contains_no_secret(self, tmp_path):
        manifest = export_recovery_kit(KEY, tmp_path)
        blob = json.dumps(manifest)
        assert manifest["commitment"]
        # Neither raw key nor derived mnemonic may leak into the manifest.
        assert entropy_to_mnemonic(KEY) not in blob
        b64key = __import__("base64").b64encode(KEY).decode()
        assert b64key not in blob
        hexkey = KEY.hex()
        assert hexkey not in blob

    def test_refuses_to_overwrite_existing_kit(self, tmp_path):
        export_recovery_kit(KEY, tmp_path)
        with pytest.raises(RecoveryKitError, match="already exists"):
            export_recovery_kit(KEY, tmp_path)

    def test_export_to_nested_new_directory(self, tmp_path):
        dest = tmp_path / "deep" / "nested" / "kit"
        manifest = export_recovery_kit(KEY, dest)
        assert (dest / KIT_FILENAME).exists()
        assert manifest["threshold"] == 3

    def test_invalid_parameters(self, tmp_path):
        with pytest.raises(RecoveryKitError):
            export_recovery_kit(KEY, tmp_path, threshold=6, total=5)


class TestCombine:
    def test_combine_from_files_with_commitment(self, tmp_path):
        manifest = export_recovery_kit(KEY, tmp_path, threshold=3, total=5)
        files = [tmp_path / n for n in manifest["share_files"]]
        shares = collect_shares(files[:3])
        secret = combine_recovery_kit(shares, commitment=manifest["commitment"])
        assert secret == KEY

    def test_combine_without_manifest_still_works(self, tmp_path):
        manifest = export_recovery_kit(KEY, tmp_path)
        files = [tmp_path / n for n in manifest["share_files"]]
        secret = combine_recovery_kit(collect_shares(files[2:]))
        assert secret == KEY

    def test_load_manifest_validates_format(self, tmp_path):
        export_recovery_kit(KEY, tmp_path)
        m = load_manifest(tmp_path)
        assert m["threshold"] == 3 and m["total"] == 5

        bad = tmp_path / "bad"
        bad.mkdir()
        (bad / KIT_FILENAME).write_text('{"format": "other"}', encoding="utf-8")
        with pytest.raises(RecoveryKitError, match="Not a GhostDrive"):
            load_manifest(bad)

        with pytest.raises(RecoveryKitError, match="No ghostdrive-recovery-kit"):
            load_manifest(tmp_path / "nonexistent")

    def test_mixed_kit_rejected_by_commitment(self, tmp_path):
        """Shares from kit A + commitment from kit B must fail closed."""
        ka = tmp_path / "a"
        kb = tmp_path / "b"
        ma = export_recovery_kit(os.urandom(32), ka)
        mb = export_recovery_kit(os.urandom(32), kb)
        shares = collect_shares([ka / n for n in ma["share_files"][:3]])
        with pytest.raises(RecoveryKitError, match="commitment"):
            combine_recovery_kit(shares, commitment=mb["commitment"])

    def test_threshold_enforced_from_manifest(self, tmp_path):
        manifest = export_recovery_kit(KEY, tmp_path, threshold=3, total=5)
        files = [tmp_path / n for n in manifest["share_files"]]
        shares = collect_shares(files[:2])
        with pytest.raises(RecoveryKitError, match="requires 3 shares"):
            combine_recovery_kit(shares, threshold=manifest["threshold"])

    def test_collect_shares_accepts_pasted_text(self, tmp_path):
        manifest = export_recovery_kit(KEY, tmp_path)
        first = (tmp_path / manifest["share_files"][0]).read_text(encoding="utf-8")
        rest = [tmp_path / n for n in manifest["share_files"][1:3]]
        shares = collect_shares([first.strip()] + rest)
        assert combine_recovery_kit(shares, commitment=manifest["commitment"]) == KEY

    def test_collect_shares_missing_file(self):
        with pytest.raises(RecoveryKitError, match="not found"):
            collect_shares(["/definitely/not/here.gdshare"])

    def test_share_summary(self, tmp_path):
        manifest = export_recovery_kit(KEY, tmp_path, threshold=3, total=5)
        shares = collect_shares([tmp_path / n for n in manifest["share_files"][:3]])
        summary = share_summary(shares)
        assert summary == {
            "provided": 3,
            "threshold": 3,
            "total": 5,
            "indexes": [1, 2, 3],
        }


class TestKeystoreRestore:
    def test_restore_roundtrip_unlocks_with_new_passphrase(self, tmp_path):
        """Kit -> shares -> Master Key -> new keystore.json -> unlock works,
        and the rebuilt keystore holds the SAME key material."""
        kit = tmp_path / "kit"
        manifest = export_recovery_kit(KEY, kit)
        shares = collect_shares([kit / n for n in manifest["share_files"][:3]])
        secret = combine_recovery_kit(shares, commitment=manifest["commitment"])

        out = tmp_path / "keystore.json"
        km = restore_keystore_from_key(
            secret, out, b"new-pass", argon2_params=FAST_ARGON2_PARAMS
        )
        assert out.exists()
        assert km.is_unlocked

        # Reopen fresh and unlock with the new passphrase only.
        km2 = KeystoreManager(out)
        km2.unlock(b"new-pass")
        assert bytes(km2.master_key) == KEY

    def test_wrong_passphrase_fails(self, tmp_path):
        kit = tmp_path / "kit"
        manifest = export_recovery_kit(KEY, kit)
        shares = collect_shares([kit / n for n in manifest["share_files"][:3]])
        secret = combine_recovery_kit(shares)
        out = tmp_path / "keystore.json"
        restore_keystore_from_key(secret, out, b"right", argon2_params=FAST_ARGON2_PARAMS)

        from ghostdrive.exceptions import AuthenticationError

        km = KeystoreManager(out)
        with pytest.raises(AuthenticationError):
            km.unlock(b"wrong")


class TestOfflineTool:
    """Exercise the standalone `python -m ghostdrive.cli.recovery_tool` CLI."""

    @staticmethod
    def _run(*argv: str) -> tuple[int, str]:
        from ghostdrive.cli.recovery_tool import main
        import contextlib
        import io

        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue() + err.getvalue()

    def test_verify_three_shares(self, tmp_path):
        manifest = export_recovery_kit(KEY, tmp_path)
        files = [str(tmp_path / n) for n in manifest["share_files"][:3]]
        code, out = self._run("verify", *files)
        assert code == 0
        assert "Shares are valid" in out
        assert "Commitment      : OK" in out

    def test_verify_insufficient_shares(self, tmp_path):
        manifest = export_recovery_kit(KEY, tmp_path)
        files = [str(tmp_path / n) for n in manifest["share_files"][:2]]
        code, out = self._run("verify", *files)
        assert code == 2
        assert "NOT ENOUGH SHARES" in out

    def test_verify_kit_directory(self, tmp_path):
        export_recovery_kit(KEY, tmp_path)
        code, out = self._run("verify", str(tmp_path))
        assert code == 0

    def test_restore_from_kit_directory(self, tmp_path):
        export_recovery_kit(KEY, tmp_path)
        out_ks = tmp_path / "restored_keystore.json"
        code, out = self._run(
            "restore", str(tmp_path),
            "--keystore", str(out_ks),
            "--passphrase", "np",
            "--fast",
        )
        assert code == 0, out
        assert out_ks.exists()

        km = KeystoreManager(out_ks)
        km.unlock(b"np")
        assert bytes(km.master_key) == KEY

    def test_restore_refuses_overwrite_without_force(self, tmp_path):
        manifest = export_recovery_kit(KEY, tmp_path)
        out_ks = tmp_path / "ks.json"
        out_ks.write_text("{}", encoding="utf-8")
        files = [str(tmp_path / n) for n in manifest["share_files"][:3]]
        code, out = self._run(
            "restore", *files, "--keystore", str(out_ks), "--passphrase", "np", "--fast"
        )
        assert code != 0
        assert "already exists" in out

        code, out = self._run(
            "restore", *files, "--keystore", str(out_ks),
            "--passphrase", "np", "--fast", "--force",
        )
        assert code == 0, out

    def test_export_command(self, tmp_path):
        """Offline export from an existing keystore.json."""
        ks = tmp_path / "keystore.json"
        km = KeystoreManager(ks)
        # NOTE: use freshly-allocated passphrase bytes per call — the keystore
        # deliberately zeroes passphrase buffers in place, which would corrupt
        # a shared module-level constant like b"pp".
        seed = km.create_new(
            "pp".encode(), calibrate=False, argon2_params=FAST_ARGON2_PARAMS
        )
        km.verify_and_save(seed)
        km.lock()

        kit_dir = tmp_path / "kit2"
        code, out = self._run(
            "export",
            "--keystore", str(ks),
            "--out", str(kit_dir),
            "--passphrase", "pp",
        )
        assert code == 0, out
        assert (kit_dir / KIT_FILENAME).exists()

        # And it round-trips to the same master key.
        manifest = load_manifest(kit_dir)
        shares = collect_shares([kit_dir / n for n in manifest["share_files"][:3]])
        secret = combine_recovery_kit(shares, commitment=manifest["commitment"])
        assert mnemonic_to_entropy(entropy_to_mnemonic(secret)) == secret
        km2 = KeystoreManager(ks)
        km2.unlock("pp".encode())
        assert secret == bytes(km2.master_key)

    def test_check_stdin(self, tmp_path, monkeypatch):
        import io

        manifest = export_recovery_kit(KEY, tmp_path)
        text = (tmp_path / manifest["share_files"][0]).read_text(encoding="utf-8")
        monkeypatch.setattr("sys.stdin", io.StringIO(text))
        code, out = self._run("check-stdin")
        assert code == 0
        assert "Shares provided : 1" in out
