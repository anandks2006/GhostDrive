"""
portable.py — Portable vault export/import (Spec: single-file vault moves).

A *portable vault* (``.gdvault``) is one self-contained encrypted file that
can move a GhostDrive installation between machines without any backend,
network, or OS keyring access:

    manifest.json     non-secret counts + BLAKE3 checksums (inside)
    keystore.json     passphrase-encrypted keystore (already safe at rest)
    index.snapshot    encrypted index snapshot (same format as backends hold)
    settings.json     non-secret app settings

The whole archive is then wrapped in an outer envelope::

    "GDVAULT1"            magic (8 bytes)
    uint32                header length (big-endian)
    header JSON           kdf parameters, salt, nonce, metadata (plaintext)
    ciphertext            AES-256-GCM(Argon2id(passphrase), zip bytes)

so the file is protected end-to-end by the vault passphrase alone — losing
the machine, the keyring and the backends still leaves the archive readable
with just the passphrase (or, independently, the recovery key shares).

Import writes the keystore and (optionally) replaces the local index with the
snapshot, after which the normal cold-start path applies.
"""

from __future__ import annotations

import io
import json
import struct
import time
import zipfile
from pathlib import Path
from typing import Any, Optional

import blake3
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ghostdrive.crypto.keystore import KEYSTORE_VERSION
from ghostdrive.exceptions import CryptoError

MAGIC = b"GDVAULT1"
FORMAT = "ghostdrive-portable-vault"
FORMAT_VERSION = 1
SALT_BYTES = 32
NONCE_BYTES = 12

MANIFEST_NAME = "manifest.json"
KEYSTORE_NAME = "keystore.json"
SNAPSHOT_NAME = "index.snapshot"
SETTINGS_NAME = "settings.json"

# Same defaults as the keystore (keystore.py::_DEFAULT_ARGON2_PARAMS).
_DEFAULT_ARGON2 = {
    "time_cost": 3,
    "memory_cost": 65_536,
    "parallelism": 4,
    "hash_len": 32,
}


class PortableVaultError(CryptoError):
    """Raised for invalid portable vault export/import operations."""


# ─── Inner archive (zip) ──────────────────────────────────────────────────────

def _build_archive(
    keystore_raw: bytes,
    snapshot_blob: Optional[bytes],
    settings: Optional[dict],
    extra: Optional[dict] = None,
) -> bytes:
    """Assemble the inner zip: manifest + keystore + optional snapshot/settings."""
    members: dict[str, bytes] = {KEYSTORE_NAME: keystore_raw}
    if snapshot_blob is not None:
        members[SNAPSHOT_NAME] = snapshot_blob
    if settings is not None:
        members[SETTINGS_NAME] = json.dumps(settings, indent=2).encode("utf-8")

    manifest = {
        "format": FORMAT,
        "version": FORMAT_VERSION,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "keystore_version": KEYSTORE_VERSION,
        "members": {
            name: {
                "size": len(data),
                "blake3": blake3.blake3(data).hexdigest(),
            }
            for name, data in members.items()
        },
        "has_snapshot": snapshot_blob is not None,
    }
    if extra:
        manifest.update(extra)

    buf = io.BytesIO()
    # ZIP_DEFLATED keeps the (already encrypted) snapshot from bloating the
    # file; compression happens before the outer encryption layer.
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2))
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _parse_archive(blob: bytes) -> dict:
    """Open the inner zip and verify every member against the manifest."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile as exc:
        raise PortableVaultError(f"Archive is not a valid zip: {exc}") from exc

    with zf:
        names = set(zf.namelist())
        if MANIFEST_NAME not in names:
            raise PortableVaultError("Archive has no manifest.json.")
        try:
            manifest = json.loads(zf.read(MANIFEST_NAME).decode("utf-8"))
        except (KeyError, ValueError) as exc:
            raise PortableVaultError(f"Unreadable manifest: {exc}") from exc
        if manifest.get("format") != FORMAT:
            raise PortableVaultError("Not a GhostDrive portable vault.")
        if manifest.get("version") != FORMAT_VERSION:
            raise PortableVaultError(
                f"Unsupported portable vault version {manifest.get('version')}."
            )

        members: dict[str, bytes] = {}
        for name, meta in (manifest.get("members") or {}).items():
            if name not in names:
                raise PortableVaultError(f"Archive member missing: {name}.")
            data = zf.read(name)
            digest = blake3.blake3(data).hexdigest()
            if digest != meta.get("blake3"):
                raise PortableVaultError(f"Checksum mismatch for {name}.")
            members[name] = data

        if KEYSTORE_NAME not in members:
            raise PortableVaultError("Archive does not contain keystore.json.")
    return {"manifest": manifest, "members": members}


# ─── Outer envelope (passphrase encryption) ──────────────────────────────────

def _derive(passphrase: bytes, salt: bytes, params: dict) -> bytes:
    return hash_secret_raw(
        secret=passphrase,
        salt=salt,
        time_cost=params["time_cost"],
        memory_cost=params["memory_cost"],
        parallelism=params["parallelism"],
        hash_len=params.get("hash_len", 32),
        type=Type.ID,
    )


def _seal(archive: bytes, passphrase: bytes, argon2_params: Optional[dict],
          metadata: Optional[dict] = None) -> bytes:
    import os

    params = dict(argon2_params or _DEFAULT_ARGON2)
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    key = _derive(passphrase, salt, params)
    ct = AESGCM(key).encrypt(nonce, archive, MAGIC)  # AAD binds the format

    header = {
        "format": FORMAT,
        "version": FORMAT_VERSION,
        "kdf": "argon2id",
        "argon2": {
            "time_cost": params["time_cost"],
            "memory_cost": params["memory_cost"],
            "parallelism": params["parallelism"],
            "hash_len": params.get("hash_len", 32),
        },
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if metadata:
        header["metadata"] = metadata
    raw_header = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return MAGIC + struct.pack(">I", len(raw_header)) + raw_header + ct


def _open_envelope(blob: bytes, passphrase: bytes) -> tuple[dict, bytes]:
    if len(blob) < len(MAGIC) + 4 or blob[: len(MAGIC)] != MAGIC:
        raise PortableVaultError("Not a GhostDrive portable vault (bad magic).")
    (header_len,) = struct.unpack(">I", blob[len(MAGIC): len(MAGIC) + 4])
    if header_len <= 0 or header_len > 64 * 1024:
        raise PortableVaultError("Corrupt vault header.")
    start = len(MAGIC) + 4
    try:
        header = json.loads(blob[start: start + header_len].decode("utf-8"))
        ct = blob[start + header_len:]
    except (ValueError, UnicodeDecodeError) as exc:
        raise PortableVaultError(f"Corrupt vault header: {exc}") from exc
    if header.get("format") != FORMAT:
        raise PortableVaultError("Not a GhostDrive portable vault.")

    try:
        salt = bytes.fromhex(header["salt"])
        nonce = bytes.fromhex(header["nonce"])
        params = header["argon2"]
    except (KeyError, ValueError) as exc:
        raise PortableVaultError(f"Incomplete vault header: {exc}") from exc

    key = _derive(passphrase, salt, params)
    try:
        archive = AESGCM(key).decrypt(nonce, ct, MAGIC)
    except Exception as exc:
        raise PortableVaultError(
            "Vault decryption failed: wrong passphrase or corrupted file."
        ) from exc
    return header, archive


# ─── Public API ──────────────────────────────────────────────────────────────

def export_portable_vault(
    destination: Path | str,
    passphrase: bytes,
    keystore_path: Path | str,
    db: Any = None,
    settings: Optional[dict] = None,
    include_index: bool = True,
    argon2_params: Optional[dict] = None,
    label: str = "",
) -> dict:
    """
    Write a passphrase-encrypted ``.gdvault`` file containing the keystore,
    (optionally) an encrypted index snapshot, and non-secret settings.

    Args:
        destination:    Output file path (overwritten if present).
        passphrase:     Outer-envelope passphrase (normally the vault one).
        keystore_path:  Source ``keystore.json`` (read as bytes, never parsed).
        db:             Open :class:`GhostDriveDB` for the index snapshot
                        (required when ``include_index`` is true).
        settings:       Optional non-secret settings dict to embed.
        include_index:  Include a fresh encrypted index snapshot.
        argon2_params:  Override KDF cost (tests only).
        label:          Free-form label stored in the outer header.

    Returns:
        Manifest dict with size/checksum of the written file.
    """
    keystore_path = Path(keystore_path)
    if not keystore_path.exists():
        raise PortableVaultError(f"No keystore found at {keystore_path}.")
    keystore_raw = keystore_path.read_bytes()
    if not keystore_raw:
        raise PortableVaultError("Keystore file is empty.")

    snapshot_blob: Optional[bytes] = None
    snapshot_info: Optional[dict] = None
    if include_index:
        if db is None:
            from ghostdrive.services.context import require_db
            db = require_db()
        snapshot_info = _snapshot_blob_for_export(db)
        snapshot_blob = snapshot_info["blob"]

    archive = _build_archive(
        keystore_raw,
        snapshot_blob,
        settings,
        extra={"snapshot": {k: v for k, v in (snapshot_info or {}).items() if k != "blob"}},
    )
    blob = _seal(
        archive,
        passphrase,
        argon2_params,
        metadata={"label": (label or "").strip(), "app": "ghostdrive"},
    )

    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        dest.write_bytes(blob)
    except OSError as exc:
        raise PortableVaultError(f"Cannot write {dest}: {exc}") from exc

    return {
        "status": "success",
        "path": str(dest),
        "size": len(blob),
        "blake3": blake3.blake3(blob).hexdigest(),
        "has_index": snapshot_blob is not None,
        "snapshot": {k: v for k, v in (snapshot_info or {}).items() if k != "blob"},
    }


def _snapshot_blob_for_export(db: Any) -> dict:
    """
    Build the encrypted index snapshot without touching any backend.

    Mirrors ``snapshots.create_snapshot`` up to the upload step: WAL
    checkpoint, read the index file, encrypt with the derived backup key.
    """
    import os
    import uuid

    from ghostdrive.crypto.hkdf import derive_index_backup_enc_key
    from ghostdrive.services.context import get_master_key, hkdf_salt
    from ghostdrive.services.snapshots import _encode_snapshot

    master_key = get_master_key()
    salt = hkdf_salt()
    db.wal_checkpoint()
    raw = Path(db._path).read_bytes()
    if not raw:
        raise PortableVaultError("Index database is empty; snapshot aborted.")

    snapshot_id = str(uuid.uuid4())
    snapshot_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    key = derive_index_backup_enc_key(master_key, salt)
    blob = _encode_snapshot(raw, key, snapshot_id, snapshot_at)
    del raw, key, master_key, salt
    return {
        "blob": blob,
        "snapshot_id": snapshot_id,
        "snapshot_at": snapshot_at,
        "size": len(blob),
        "blake3": blake3.blake3(blob).hexdigest(),
    }


def inspect_portable_vault(path: Path | str, passphrase: bytes) -> dict:
    """Decrypt enough to validate the envelope + manifest. Returns metadata only."""
    blob = Path(path).read_bytes()
    header, archive = _open_envelope(blob, passphrase)
    parsed = _parse_archive(archive)
    manifest = parsed["manifest"]
    return {
        "status": "success",
        "created_at": header.get("created_at"),
        "label": (header.get("metadata") or {}).get("label", ""),
        "manifest": manifest,
        "members": sorted(parsed["members"].keys()),
        "has_snapshot": manifest.get("has_snapshot", False),
    }


def import_portable_vault(
    path: Path | str,
    passphrase: bytes,
    keystore_destination: Path | str,
    index_destination: Optional[Path | str] = None,
    overwrite: bool = False,
    master_key: Optional[bytes] = None,
    hkdf_salt: Optional[bytes] = None,
) -> dict:
    """
    Decrypt a ``.gdvault`` and unpack it.

    * ``keystore_destination`` always receives ``keystore.json``.
    * ``index_destination`` receives the decrypted index bytes when the archive
      carries a snapshot AND a destination is given.

    Snapshot decryption needs the Master Key: pass ``master_key`` +
    ``hkdf_salt`` explicitly, otherwise the unlocked application context is
    consulted. Callers on a fresh machine should therefore (1) import without
      ``index_destination``, (2) unlock the written keystore, then (3) re-run
      the import with the now-available key material and ``index_destination``.

    Returns a dict with what was written plus the verified manifest.
    """
    blob = Path(path).read_bytes()
    header, archive = _open_envelope(blob, passphrase)
    parsed = _parse_archive(archive)
    members = parsed["members"]

    ks_dest = Path(keystore_destination)
    if ks_dest.exists() and not overwrite:
        raise PortableVaultError(
            f"{ks_dest} already exists. Pass overwrite=True to replace it."
        )

    written: list[str] = []
    ks_dest.parent.mkdir(parents=True, exist_ok=True)
    ks_dest.write_bytes(members[KEYSTORE_NAME])
    written.append(str(ks_dest))

    index_written: Optional[str] = None
    settings: Optional[dict] = None
    if index_destination is not None and SNAPSHOT_NAME in members:
        from ghostdrive.services.snapshots import decode_snapshot
        from ghostdrive.crypto.hkdf import derive_index_backup_enc_key

        if master_key is None or hkdf_salt is None:
            from ghostdrive.services.context import get_master_key, hkdf_salt as _salt

            master_key = master_key or get_master_key()
            hkdf_salt = hkdf_salt or _salt()

        # Decryption needs the Master Key — only available when the keystore
        # is unlocked (same machine / post-unlock phase of a fresh import).
        try:
            key = derive_index_backup_enc_key(master_key, hkdf_salt)
            raw, meta = decode_snapshot(members[SNAPSHOT_NAME], key)
        except Exception as exc:
            raise PortableVaultError(
                "Snapshot present but could not be decrypted "
                f"(unlock the restored keystore first): {exc}"
            ) from exc
        dest = Path(index_destination)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        index_written = str(dest)
        written.append(index_written)
        del raw, key

    if SETTINGS_NAME in members:
        try:
            settings = json.loads(members[SETTINGS_NAME].decode("utf-8"))
        except ValueError:
            settings = None

    return {
        "status": "success",
        "written": written,
        "index_written": index_written,
        "settings": settings,
        "manifest": parsed["manifest"],
        "created_at": header.get("created_at"),
    }
