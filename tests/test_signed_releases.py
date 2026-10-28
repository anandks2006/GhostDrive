"""
test_signed_releases.py -- Reproducible builds + Ed25519-signed releases.

Covers: keygen (PKCS#8 no-passphrase keypair, fingerprint correctness,
overwrite refusal), release.py against the real git tree (artifact +
.sha256 + .sig + SHA256SUMS.txt, the internal double-build determinism
guard, and cross-run byte-identity), tamper and wrong-key rejection via
verify_release.py's library entry point, the updater's
GHOSTDRIVE_RELEASE_PUBKEY wiring (good/tampered/malformed/absent .sig,
legacy sha256-only path untouched when the env var is unset), and that
docs/REPRODUCIBLE_BUILDS.md states SOURCE_DATE_EPOCH and
GHOSTDRIVE_RELEASE_PUBKEY.

Hermetic: everything writes to tmp_path and the release build reads only
the local git index — no network anywhere. The build tests skip cleanly
when git is unavailable.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ghostdrive.platform import updater

ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str):
    """Import scripts/<name>.py as a module (scripts/ is not a package)."""
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"ghostdrive_script_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


keygen = _load_script("keygen_release_key")
release = _load_script("release")
verify_release = _load_script("verify_release")

INSTALLER_URL = "https://example.invalid/GhostDrive-0.2.0-setup.exe"


@pytest.fixture(autouse=True)
def _clean_release_pubkey_env(monkeypatch):
    """The signature switch must never leak in from the outer environment."""
    monkeypatch.delenv(updater.RELEASE_PUBKEY_ENV, raising=False)


@pytest.fixture
def keypair(tmp_path):
    """Fresh throwaway keypair written by keygen into tmp_path."""
    result = keygen.write_keypair(tmp_path / "keys")
    return {
        "priv_path": Path(result["private_key"]),
        "pub_path": Path(result["public_key"]),
        "priv_pem": Path(result["private_key"]).read_bytes(),
        "pub_pem": Path(result["public_key"]).read_bytes(),
        "fingerprint": result["fingerprint"],
    }


def _git_available() -> bool:
    if shutil.which("git") is None:
        return False
    proc = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=ROOT, capture_output=True,
    )
    return proc.returncode == 0


@pytest.fixture(scope="module")
def require_git():
    if not _git_available():
        pytest.skip("git not available — cannot build the source archive here")


@pytest.fixture(scope="module")
def built_release(tmp_path_factory, require_git):
    """One real release build against the actual repo git tree."""
    work = tmp_path_factory.mktemp("signed-release")
    keys = keygen.write_keypair(work / "keys")
    dist = work / "dist"
    rc = release.main([
        "--private-key", str(keys["private_key"]),
        "--out", str(dist),
    ])
    assert rc == 0
    version = release.read_source_version(ROOT)
    artifact = dist / f"ghostdrive-{version}-src.zip"
    assert artifact.is_file(), f"expected {artifact.name} in {list(dist.iterdir())}"
    return {
        "dist": dist,
        "artifact": artifact,
        "pub_pem": Path(keys["public_key"]).read_bytes(),
    }


# ── keygen ──────────────────────────────────────────────────────────────────

class TestKeygen:
    def test_writes_keypair_and_correct_fingerprint(self, tmp_path):
        out = tmp_path / "keys"
        result = keygen.write_keypair(out)
        priv = Path(result["private_key"])
        pub = Path(result["public_key"])
        assert priv.name == "release_private.pem"
        assert pub.name == "release_public.pem"
        assert priv.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")  # PKCS#8
        assert pub.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----")

        # Fingerprint = colon-grouped sha256 of the raw 32-byte public key.
        raw = serialization.load_pem_public_key(
            pub.read_bytes()
        ).public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        assert len(raw) == 32
        recomputed = ":".join(f"{b:02x}" for b in hashlib.sha256(raw).digest())
        assert result["fingerprint"] == recomputed
        # The updater's own computation must agree (one fingerprint, everywhere).
        assert updater.release_pubkey_fingerprint(pub.read_bytes()) == recomputed

    def test_private_key_loads_without_passphrase(self, keypair):
        """The written key is unencrypted Ed25519 — the automation contract."""
        key = serialization.load_pem_private_key(keypair["priv_pem"], password=None)
        assert isinstance(key, Ed25519PrivateKey)

    def test_refuses_overwrite_without_force(self, tmp_path, capsys):
        out = tmp_path / "keys"
        first = keygen.write_keypair(out)
        # Library form refuses...
        with pytest.raises(FileExistsError):
            keygen.write_keypair(out)
        # ...and the CLI reports it with a nonzero exit instead of a traceback.
        assert keygen.main(["--out-dir", str(out)]) == 1
        assert "refusing to overwrite" in capsys.readouterr().err
        # The original key must be untouched by the refused run.
        assert Path(first["private_key"]).read_bytes().startswith(b"-----BEGIN")
        # --force rotates: succeeds and produces a different fingerprint.
        second = keygen.write_keypair(out, force=True)
        assert second["fingerprint"] != first["fingerprint"]


# ── release.py against the real git tree ────────────────────────────────────

class TestReleaseBuild:
    def test_outputs_artifact_sig_sums_and_verifies(self, built_release, keypair):
        dist = built_release["dist"]
        artifact = built_release["artifact"]
        assert artifact.with_name(artifact.name + ".sha256").is_file()
        assert artifact.with_name(artifact.name + ".sig").is_file()
        assert (dist / "SHA256SUMS.txt").is_file()
        assert (dist / "SHA256SUMS.txt.sig").is_file()

        # The .sha256 sidecar matches the bytes on disk.
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        sidecar = artifact.with_name(artifact.name + ".sha256").read_text()
        assert sidecar.split()[0] == digest
        # SHA256SUMS.txt covers every other file in dist, hashes correct.
        sums_lines = (dist / "SHA256SUMS.txt").read_text().splitlines()
        listed = {line.split()[1]: line.split()[0] for line in sums_lines}
        assert set(listed) == {
            artifact.name, artifact.name + ".sha256", artifact.name + ".sig",
        }
        for name, expected in listed.items():
            assert hashlib.sha256((dist / name).read_bytes()).hexdigest() == expected

        # The .sig document has the documented shape and the right key id.
        meta = json.loads((dist / (artifact.name + ".sig")).read_text())
        assert meta["algo"] == "ed25519"
        assert len(base64.b64decode(meta["sig"])) == 64
        assert meta["pubkey_sha256"] == updater.release_pubkey_sha256_hex(
            built_release["pub_pem"]
        )

        # Library verification against the matching key passes.
        res = verify_release.verify_artifact(artifact, built_release["pub_pem"])
        assert res["ok"] is True, res["error"]
        assert res["sha256"] == digest
        assert res["sha256_ok"] is True
        assert res["signature_ok"] is True
        assert res["error"] is None
        # And against an unrelated key it fails.
        res_bad = verify_release.verify_artifact(artifact, keypair["pub_pem"])
        assert res_bad["ok"] is False
        assert res_bad["signature_ok"] is False
        assert "different key" in res_bad["error"]

    def test_zip_entries_are_deterministic_metadata(self, built_release):
        """Fixed timestamp / pinned create_system on every entry."""
        import zipfile

        with zipfile.ZipFile(built_release["artifact"]) as zf:
            infos = zf.infolist()
            assert infos, "empty source archive"
            assert all(i.date_time == (1980, 1, 1, 0, 0, 0) for i in infos)
            assert all(i.create_system == 3 for i in infos)
            names = [i.filename for i in infos]
            assert names == sorted(names)
            assert all(n.startswith("ghostdrive-") for n in names)
            # Tracked source only — no .git, no __pycache__.
            assert not any(".git/" in n or "__pycache__" in n for n in names)

    def test_build_is_byte_identical_across_runs(self, tmp_path, require_git):
        """The in-script double-build guard plus a genuine second invocation."""
        keys = keygen.write_keypair(tmp_path / "keys")
        run_a, run_b = tmp_path / "a", tmp_path / "b"
        args = ["--private-key", str(keys["private_key"])]
        assert release.main(args + ["--out", str(run_a)]) == 0
        assert release.main(args + ["--out", str(run_b)]) == 0
        version = release.read_source_version(ROOT)
        name = f"ghostdrive-{version}-src.zip"
        hash_a = hashlib.sha256((run_a / name).read_bytes()).hexdigest()
        hash_b = hashlib.sha256((run_b / name).read_bytes()).hexdigest()
        assert hash_a == hash_b  # byte-identical across separate builds

    def test_version_resolution(self, require_git):
        # explicit > exact tag > ghostdrive/__init__.py (single source).
        assert release.determine_version("9.9.9") == "9.9.9"
        assert release.determine_version(None) == release.read_source_version(ROOT)
        # The version string is the actual package constant.
        from ghostdrive import __version__
        assert release.read_source_version(ROOT) == __version__


# ── Tampering and wrong keys ────────────────────────────────────────────────

class TestTamperAndWrongKey:
    def test_flipped_byte_fails_verification(self, built_release, tmp_path):
        artifact = built_release["artifact"]
        # Copy artifact + sidecars to a scratch dir, then flip one byte.
        for suffix in ("", ".sha256", ".sig"):
            shutil.copyfile(
                artifact.with_name(artifact.name + suffix),
                tmp_path / (artifact.name + suffix),
            )
        tampered = tmp_path / artifact.name
        data = bytearray(tampered.read_bytes())
        data[len(data) // 2] ^= 0xFF
        tampered.write_bytes(bytes(data))

        res = verify_release.verify_artifact(tampered, built_release["pub_pem"])
        assert res["ok"] is False
        assert res["signature_ok"] is False
        assert res["sha256_ok"] is False
        assert "sha256 mismatch" in res["error"]
        # The reported hash is of the bytes actually on disk (the tampered ones).
        assert res["sha256"] == hashlib.sha256(bytes(data)).hexdigest()

    def test_missing_sig_is_a_failure(self, built_release, tmp_path):
        artifact = built_release["artifact"]
        lone = tmp_path / artifact.name
        shutil.copyfile(artifact, lone)
        res = verify_release.verify_artifact(lone, built_release["pub_pem"])
        assert res["ok"] is False
        assert "no " + artifact.name + ".sig" in res["error"]

    def test_wrong_key_trips_fingerprint_guard(self, keypair):
        """Sign with A, verify with B — fails before the crypto, by design."""
        other = keygen.write_keypair(keypair["priv_path"].parent / "other")
        other_pub = Path(other["public_key"]).read_bytes()
        payload = b"some release artifact bytes"
        meta = release.sign_payload(payload, keypair["priv_pem"], "artifact.bin")
        with pytest.raises(updater.SignatureError, match="different key"):
            updater.verify_release_signature(payload, meta, other_pub)

    def test_signature_over_tampered_bytes_raises(self, keypair):
        meta = release.sign_payload(b"original", keypair["priv_pem"], "a.bin")
        with pytest.raises(updater.SignatureError, match="does not match"):
            updater.verify_release_signature(b"tampered", meta, keypair["pub_pem"])


# ── updater wiring (GHOSTDRIVE_RELEASE_PUBKEY) ──────────────────────────────

class TestUpdaterWiring:
    def test_verify_release_signature_good(self, keypair):
        payload = b"installer bytes " * 100
        meta = release.sign_payload(payload, keypair["priv_pem"], "GhostDrive.exe")
        assert updater.verify_release_signature(
            payload, meta, keypair["pub_pem"]
        ) is None

    def test_verify_release_signature_rejects_bad_inputs(self, keypair):
        payload = b"payload"
        good = release.sign_payload(payload, keypair["priv_pem"], "a.bin")
        # Wrong algorithm is refused, never ignored.
        with pytest.raises(updater.SignatureError, match="algorithm"):
            updater.verify_release_signature(payload, dict(good, algo="rsa"), keypair["pub_pem"])
        # Non-object metadata.
        with pytest.raises(updater.SignatureError, match="not a JSON object"):
            updater.verify_release_signature(payload, ["sig"], keypair["pub_pem"])
        # Signature not raw 64 bytes.
        short = dict(good, sig=base64.b64encode(b"nope").decode())
        with pytest.raises(updater.SignatureError, match="64 raw"):
            updater.verify_release_signature(payload, short, keypair["pub_pem"])
        # Fingerprint claim tampered with (same key, wrong claim).
        forged = dict(good, pubkey_sha256="00" * 32)
        with pytest.raises(updater.SignatureError, match="different key"):
            updater.verify_release_signature(payload, forged, keypair["pub_pem"])

    def test_verify_release_signature_file_roundtrip(self, keypair, tmp_path):
        payload = b"artifact bytes"
        artifact = tmp_path / "GhostDrive-x-setup.exe"
        artifact.write_bytes(payload)
        sig = tmp_path / "GhostDrive-x-setup.exe.sig"
        sig.write_text(json.dumps(
            release.sign_payload(payload, keypair["priv_pem"], artifact.name)
        ))
        updater.verify_release_signature_file(artifact, sig, keypair["pub_pem"])
        # Missing .sig file raises rather than passing silently.
        with pytest.raises(updater.SignatureError, match="not found"):
            updater.verify_release_signature_file(
                artifact, tmp_path / "absent.sig", keypair["pub_pem"]
            )

    def test_legacy_path_unchanged_without_env(self, tmp_path):
        """Env unset (the default): no .sig fetch, sha256-only, as before."""
        payload = b"installer bytes " * 100
        urls = []

        def fetch(url):
            urls.append(url)
            return payload

        expected = hashlib.sha256(payload).hexdigest()
        res = updater.stage_download(INSTALLER_URL, expected, tmp_path / "d",
                                     fetch=fetch)
        assert urls == [INSTALLER_URL]  # the .sig was never even requested
        assert Path(res["path"]).read_bytes() == payload
        assert res["sha256"] == expected

    def test_legacy_checksum_mismatch_still_aborts(self, tmp_path):
        """Without the env var the old failure mode is byte-for-byte intact."""
        def fetch(url):
            return b"not the installer we were promised"

        with pytest.raises(RuntimeError, match="checksum mismatch"):
            updater.stage_download(INSTALLER_URL, "0" * 64, tmp_path / "d",
                                   fetch=fetch)
        assert not list((tmp_path / "d").iterdir())

    def test_env_set_good_sig_stages(self, tmp_path, keypair, monkeypatch):
        payload = b"signed installer bytes " * 50
        meta = release.sign_payload(payload, keypair["priv_pem"], "GhostDrive.exe")
        fetched = []

        def fetch(url):
            fetched.append(url)
            return json.dumps(meta).encode() if url.endswith(".sig") else payload

        monkeypatch.setenv(updater.RELEASE_PUBKEY_ENV, str(keypair["pub_path"]))
        expected = hashlib.sha256(payload).hexdigest()
        res = updater.stage_download(INSTALLER_URL, expected, tmp_path / "d",
                                     fetch=fetch)
        assert Path(res["path"]).read_bytes() == payload
        assert INSTALLER_URL + ".sig" in fetched

    def test_env_set_tampered_bytes_abort_and_clean_up(self, tmp_path, keypair,
                                                       monkeypatch):
        """sha256 matches the feed, but the signature does not — abort."""
        payload = b"signed installer bytes " * 50
        evil = payload + b"!"
        meta = release.sign_payload(payload, keypair["priv_pem"], "GhostDrive.exe")

        def fetch(url):
            return json.dumps(meta).encode() if url.endswith(".sig") else evil

        monkeypatch.setenv(updater.RELEASE_PUBKEY_ENV, str(keypair["pub_path"]))
        expected = hashlib.sha256(evil).hexdigest()  # feed agrees on the evil bytes
        dest = tmp_path / "d"
        with pytest.raises(updater.SignatureError, match="does not match"):
            updater.stage_download(INSTALLER_URL, expected, dest, fetch=fetch)
        # Neither the final nor the partial file may survive.
        assert not list(dest.iterdir())

    def test_env_set_malformed_sig_aborts(self, tmp_path, keypair, monkeypatch):
        payload = b"installer bytes"

        def fetch(url):
            return b"<html>not json</html>" if url.endswith(".sig") else payload

        monkeypatch.setenv(updater.RELEASE_PUBKEY_ENV, str(keypair["pub_path"]))
        expected = hashlib.sha256(payload).hexdigest()
        dest = tmp_path / "d"
        with pytest.raises(updater.SignatureError, match="malformed"):
            updater.stage_download(INSTALLER_URL, expected, dest, fetch=fetch)
        assert not list(dest.iterdir())

    def test_env_set_without_sig_falls_back_to_sha256(self, tmp_path, keypair,
                                                      monkeypatch):
        """Honest fallback today: no .sig accompanies → sha256-only + warning."""
        payload = b"installer bytes"

        def fetch(url):
            if url.endswith(".sig"):
                raise OSError("404 not found")
            return payload

        monkeypatch.setenv(updater.RELEASE_PUBKEY_ENV, str(keypair["pub_path"]))
        expected = hashlib.sha256(payload).hexdigest()
        res = updater.stage_download(INSTALLER_URL, expected, tmp_path / "d",
                                     fetch=fetch)
        assert Path(res["path"]).read_bytes() == payload

    def test_env_pointing_at_missing_key_aborts(self, tmp_path, keypair,
                                                monkeypatch):
        """A configured-but-unreadable key is a config error — never a silent
        downgrade to sha256-only."""
        payload = b"installer bytes"
        monkeypatch.setenv(
            updater.RELEASE_PUBKEY_ENV, str(tmp_path / "does-not-exist.pem")
        )
        expected = hashlib.sha256(payload).hexdigest()
        dest = tmp_path / "d"
        with pytest.raises(updater.SignatureError, match="cannot be read"):
            updater.stage_download(INSTALLER_URL, expected, dest,
                                   fetch=lambda url: payload)
        assert not list(dest.iterdir())

    def test_sig_meta_parameter_is_honoured(self, tmp_path, keypair, monkeypatch):
        """A pre-fetched sig document short-circuits the .sig fetch."""
        payload = b"installer bytes"
        meta = release.sign_payload(payload, keypair["priv_pem"], "GhostDrive.exe")
        urls = []

        def fetch(url):
            urls.append(url)
            return payload

        monkeypatch.setenv(updater.RELEASE_PUBKEY_ENV, str(keypair["pub_path"]))
        expected = hashlib.sha256(payload).hexdigest()
        res = updater.stage_download(INSTALLER_URL, expected, tmp_path / "d",
                                     fetch=fetch, sig_meta=meta)
        assert Path(res["path"]).exists()
        assert urls == [INSTALLER_URL]  # no .sig fetch needed


# ── The operator doc ────────────────────────────────────────────────────────

def test_doc_documents_the_switches_and_epoch():
    doc = ROOT / "docs" / "REPRODUCIBLE_BUILDS.md"
    assert doc.is_file(), "docs/REPRODUCIBLE_BUILDS.md is part of the deliverable"
    text = doc.read_text(encoding="utf-8")
    assert "SOURCE_DATE_EPOCH" in text
    assert "GHOSTDRIVE_RELEASE_PUBKEY" in text
    assert "Ed25519" in text
    lowered = text.lower()
    assert "trust model" in lowered
    assert "offline" in lowered
