"""Password-protected, expiring web share links backed by SQLite.

Zero-knowledge envelope links (additive to the classic /s/{token} flow)
========================================================================
Classic links stream *server-decrypted* plaintext.  Envelope links
(/e/{token}) never do: the server stores one contiguous ciphertext "envelope"
and the recipient's browser decrypts it with WebCrypto after the user types a
share passphrase.  The server only ever sees ciphertext.

Envelope byte layout (receive.js reads exactly this)::

    Offset   Size   Content
    0        8      magic b"GDSHARE1"
    8        4      header length (uint32, big-endian)
    12       H      canonical JSON header (UTF-8, sorted keys, compact)
    12+H     ...    segment payloads, concatenated in index order

Each segment payload is ``ciphertext || tag`` — AES-256-GCM with the 16-byte
tag at the END (the NIST/WebCrypto convention, so neither Python's AESGCM nor
``crypto.subtle.decrypt`` has to reorder bytes).  The last segment may be
shorter than ``seg_size`` (64 KiB).

Per segment:  nonce = nonce_prefix (4 bytes) || segment_index (8 bytes BE)
              AAD   = segment_index (8 bytes BE)

Binding the AAD to the segment index means a re-ordered, dropped or
duplicated segment fails authentication in the browser instead of silently
producing a corrupted file.

Two-layer key split (why the server generates the envelope key):
the file is encrypted with a random 32-byte key directly — stretching the
passphrase over hundreds of megabytes with PBKDF2 (not memory-hard anyway)
would be slow and still weak, so the server picks a uniformly random key.
The share passphrase only has to protect those 32 bytes, so it is stretched
with PBKDF2-HMAC-SHA256 / 600 000 iterations (OWASP 2023 guidance) to wrap
the key.  The passphrase is shown ONCE at creation, out-of-band, like a
recovery phrase; the recipient's browser unwraps the key client-side.

Storage: the share row lives in ``share_links`` with
``recipient_alias = "envelope"`` as the marker (schema.py is owned elsewhere
this wave), while the envelope's backend location + canonical header live
under the settings key ``envelope_links`` (JSON ``{token: {...}}``) because
share_links has no column for a backend reference.

Burn-after-read (opt-in, ``burn_after_read=True``): the stored ciphertext is
DESTROYED on the backend after the first completed fetch of the blob route.
Threat model: this cannot un-screenshot what the first recipient saw — it
removes the *server-side copy*, so a leaked or forwarded link has no second
fetch in it.  The settings meta entry is RETAINED and rewritten as burned so
later lookups can distinguish burned (410 Gone) from unknown (404); burn wins
over ``max_downloads`` (see :func:`burn_envelope`).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import mimetypes
import secrets
import struct
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ghostdrive.services import files as files_service
from ghostdrive.services.context import (
    active_backends,
    build_backend,
    require_db,
)

logger = logging.getLogger("ghostdrive.services.sharing")

_PBKDF2_ITERATIONS = 200_000
_SALT_BYTES = 16


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now_dt().isoformat()


def _hash_passcode(passcode: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", passcode.encode("utf-8"), salt, _PBKDF2_ITERATIONS
    ).hex()


def _link_view(row) -> dict:
    return {
        "link_id": row["token"],
        "token": row["token"],
        "file_id": row["file_id"],
        "filename": row["filename"],
        "size": row["file_size"],
        "recipient_alias": row["recipient_alias"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "access_count": row["download_count"],
        "max_downloads": row["max_downloads"],
        "last_accessed": row["last_accessed"],
        "revoked": bool(row["revoked"]),
        "passcode_required": bool(row["passcode_hash"]),
    }


def create_link(
    file_id: str,
    recipient_alias: str = "public",
    ttl_hours: int = 72,
    require_passcode: bool = False,
    passcode: Optional[str] = None,
    max_downloads: Optional[int] = None,
) -> dict:
    db = require_db()
    if db.get_file(file_id) is None:
        raise FileNotFoundError(f"File {file_id} not found.")

    ttl_hours = max(1, min(int(ttl_hours or 72), 24 * 365))
    expires_at = (_now_dt() + timedelta(hours=ttl_hours)).isoformat()

    passcode_hash = None
    passcode_salt = None
    if require_passcode and passcode:
        salt = secrets.token_bytes(_SALT_BYTES)
        passcode_salt = salt.hex()
        passcode_hash = _hash_passcode(passcode, salt)

    token = secrets.token_urlsafe(24)
    with db.transaction():
        db.insert_share_link({
            "token": token,
            "file_id": file_id,
            "recipient_alias": recipient_alias or "public",
            "passcode_hash": passcode_hash,
            "passcode_salt": passcode_salt,
            "created_at": _now_iso(),
            "expires_at": expires_at,
            "max_downloads": max_downloads,
        })

    row = db.get_share_link(token)
    view = _link_view(row)
    view.update({"ttl_hours": ttl_hours, "status": "success"})
    return view


def list_links() -> dict:
    db = require_db()
    return {"shared_links": [_link_view(row) for row in db.list_share_links()]}


def revoke_link(token: str) -> dict:
    db = require_db()
    if not db.revoke_share_link(token):
        raise FileNotFoundError(f"Share link {token} not found.")
    return {"status": "success", "link_id": token, "message": f"Share link {token} revoked."}


def open_link(token: str, passcode: Optional[str] = None):
    """Validate a share token/passcode and return the share row."""
    db = require_db()
    row = db.get_share_link(token)
    if row is None:
        raise FileNotFoundError("Share link not found.")
    if row["revoked"]:
        raise PermissionError("This share link has been revoked.")
    if row["expires_at"]:
        try:
            if datetime.fromisoformat(row["expires_at"]) < _now_dt():
                raise PermissionError("This share link has expired.")
        except ValueError:
            logger.warning("Invalid expiry stored for token %s", token)
    if row["max_downloads"] is not None and row["download_count"] >= row["max_downloads"]:
        raise PermissionError("This share link has reached its download limit.")
    if row["passcode_hash"]:
        if not passcode:
            raise PermissionError("A passcode is required for this share link.")
        salt = bytes.fromhex(row["passcode_salt"])
        if not hmac.compare_digest(_hash_passcode(passcode, salt), row["passcode_hash"]):
            raise PermissionError("Incorrect share passcode.")
    return row


def register_download(token: str) -> None:
    require_db().register_share_download(token)


# ─── Zero-knowledge envelope links ───────────────────────────────────────────

# Byte-layout constants — keep in sync with receive.js (web/static/js/receive.js).
ENVELOPE_MAGIC = b"GDSHARE1"

BURNED_MESSAGE = "This link has been burned: it was already viewed once."


class EnvelopeBurnedError(PermissionError):
    """Terminal burn-after-read state: the envelope was already fetched once.

    Subclasses ``PermissionError`` so pre-burn call sites keep treating it as
    a recipient-access refusal, but routes MUST check for it FIRST and map it
    to HTTP 410 Gone — a burned link is not merely revoked, it is finished,
    and "410 + burned" is how a recipient (and receive.js) tells it apart
    from an expired/revoked (403) or unknown (404) token.
    """
ENVELOPE_SETTINGS_KEY = "envelope_links"   # settings JSON: {token: envelope meta}
ENVELOPE_RECIPIENT_ALIAS = "envelope"      # marker in share_links.recipient_alias

# OWASP 2023 guidance: PBKDF2-HMAC-SHA256 >= 600 000 iterations.
# (The classic /s/ passcode hash above predates that guidance and is
# untouched so existing links keep verifying.)
ENVELOPE_PBKDF2_ITERATIONS = 600_000
ENVELOPE_WRAP_SALT_BYTES = 16
ENVELOPE_WRAP_NONCE_BYTES = 12            # 96-bit nonce required by AES-GCM
ENVELOPE_KEY_BYTES = 32                   # AES-256 envelope key
ENVELOPE_NONCE_PREFIX_BYTES = 4           # per-segment nonce = prefix || index(BE8)
ENVELOPE_SEG_SIZE = 64 * 1024             # 64 KiB streaming segments
ENVELOPE_TAG_BYTES = 16                   # GCM tag appended after each ciphertext


def _generate_envelope_passphrase() -> str:
    """5 random BIP-39 English words (~55 bits) as a share passphrase.

    The project already ships the ``mnemonic`` wordlist (keystore.py), so we
    reuse it: the phrase is readable enough to relay out-of-band while still
    being unguessable.  Shown ONCE at creation — like a recovery phrase it is
    never stored server-side.
    """
    from mnemonic import Mnemonic

    wordlist = Mnemonic("english").wordlist
    rng = secrets.SystemRandom()
    return " ".join(rng.choice(wordlist) for _ in range(5))


def _load_envelope_meta(db, token: str) -> Optional[dict]:
    """Read the envelope metadata blob for a token from settings (or None)."""
    raw = db.get_setting(ENVELOPE_SETTINGS_KEY, "{}") or "{}"
    try:
        links = json.loads(raw)
    except ValueError:
        logger.warning("envelope_links setting is not valid JSON")
        return None
    return links.get(token)


async def create_envelope_link(
    file_id: str,
    ttl_hours: int = 72,
    max_downloads: int | None = None,
    passphrase: str | None = None,
    burn_after_read: bool = False,
    db=None,
    objects=None,
    master_key=None,
    salt=None,
) -> dict:
    """Create a zero-knowledge envelope share link.

    Assembles and decrypts the file server-side (same path /s/{token} uses),
    encrypts it into a GDSHARE1 envelope whose key is wrapped by ``passphrase``
    (PBKDF2 600k), uploads the contiguous ciphertext to a backend, and records
    a ``share_links`` row so TTL / max_downloads / revocation behave exactly
    like classic links.

    ``burn_after_read`` opts the link into burn-after-read semantics: after
    the FIRST completed fetch of the ciphertext blob the stored envelope is
    destroyed on the backend, the meta entry is marked burned, and the share
    row is revoked — every later access answers 410 Gone.  Burn WINS over
    ``max_downloads``: even a link created with max_downloads=5 dies after one
    fetch, because the rationale is "no second fetch exists" (recipient-side
    screenshot risk is out of our control; server-side re-fetch is not).

    ``master_key``/``salt`` are accepted for signature symmetry with the other
    service helpers but deliberately unused: the envelope key is random and
    never derived from vault material (see module docstring).

    Returns the token, relative URL path, and the passphrase (generated when
    not supplied — shown ONCE, out-of-band).
    """
    db = db or require_db()
    row = db.get_file(file_id)
    if row is None:
        raise FileNotFoundError(f"File {file_id} not found.")

    ttl_hours = max(1, min(int(ttl_hours or 72), 24 * 365))
    expires_at = (_now_dt() + timedelta(hours=ttl_hours)).isoformat()
    if not passphrase:
        passphrase = _generate_envelope_passphrase()

    # Assemble + decrypt with the SAME service path the classic share flow
    # streams, so the envelope holds identical plaintext to a /s/ download.
    plaintext = await files_service.download_bytes(file_id)

    # Two-layer split: random envelope key protects the file; the passphrase
    # (PBKDF2-stretched) protects only the 32-byte key — see module docstring.
    envelope_key = secrets.token_bytes(ENVELOPE_KEY_BYTES)
    nonce_prefix = secrets.token_bytes(ENVELOPE_NONCE_PREFIX_BYTES)
    wrap_salt = secrets.token_bytes(ENVELOPE_WRAP_SALT_BYTES)
    wrap_nonce = secrets.token_bytes(ENVELOPE_WRAP_NONCE_BYTES)
    wrap_key = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        wrap_salt,
        ENVELOPE_PBKDF2_ITERATIONS,
    )
    # AAD binds the wrapped key to the envelope format so it cannot be moved
    # into another container unnoticed (mirrors portable.py's MAGIC-as-AAD).
    wrapped_key = AESGCM(wrap_key).encrypt(wrap_nonce, envelope_key, ENVELOPE_MAGIC)

    # 64 KiB AES-256-GCM segments; per-segment AAD = index so a reordered or
    # truncated stream fails to authenticate in the browser.
    segments: list[bytes] = []
    segment_count = (len(plaintext) + ENVELOPE_SEG_SIZE - 1) // ENVELOPE_SEG_SIZE
    for index in range(segment_count):
        piece = plaintext[index * ENVELOPE_SEG_SIZE:(index + 1) * ENVELOPE_SEG_SIZE]
        nonce = nonce_prefix + index.to_bytes(8, "big")
        aad = index.to_bytes(8, "big")
        segments.append(AESGCM(envelope_key).encrypt(nonce, piece, aad))  # ct || tag
    body = b"".join(segments)

    header = {
        "v": 1,
        "alg": "A256GCM",
        "kdf": "PBKDF2-SHA256",
        "iterations": ENVELOPE_PBKDF2_ITERATIONS,
        "wrap_salt": base64.b64encode(wrap_salt).decode("ascii"),
        "wrap_nonce": base64.b64encode(wrap_nonce).decode("ascii"),
        "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
        "segments": segment_count,
        "seg_size": ENVELOPE_SEG_SIZE,
        "size": len(plaintext),
        "nonce_prefix": base64.b64encode(nonce_prefix).decode("ascii"),
        "mime_type": (
            row["mime_type"]
            or mimetypes.guess_type(row["name"])[0]
            or "application/octet-stream"
        ),
        "filename": row["name"],
    }
    header_json = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    envelope = ENVELOPE_MAGIC + struct.pack(">I", len(header_json)) + header_json + body

    # Persist the contiguous ciphertext on a backend (prefer the local vault so
    # link creation never depends on an unreachable remote).
    if objects is None:
        _, objects = await active_backends(connect_remote=False)
    rows = db.list_backends()
    target_row = next(
        (r for r in rows if r["type"] in ("local", "local_fs") and str(r["id"]) in objects),
        None,
    ) or next((r for r in rows if str(r["id"]) in objects), None)
    if target_row is None:
        raise RuntimeError("No usable storage backend is available for the envelope.")

    # Reuse snapshots.py's blob-upload helper: one contiguous stream in,
    # one backend reference id out (no chunk/shard bookkeeping needed here).
    from ghostdrive.services.snapshots import _upload_blob

    token = secrets.token_urlsafe(24)
    reference_id = await _upload_blob(
        objects[str(target_row["id"])], target_row, envelope, f"env_{token}"
    )

    created_at = _now_iso()
    with db.transaction():
        db.insert_share_link({
            "token": token,
            "file_id": file_id,
            # Marker in an existing TEXT column (schema.py owned elsewhere):
            # distinguishes envelope links from classic /s/ links in listings.
            "recipient_alias": ENVELOPE_RECIPIENT_ALIAS,
            "passcode_hash": None,
            "passcode_salt": None,
            "created_at": created_at,
            "expires_at": expires_at,
            "max_downloads": max_downloads,
        })
        # share_links has no column for a backend reference, so the envelope
        # location + canonical header live in a settings JSON blob instead.
        links = json.loads(db.get_setting(ENVELOPE_SETTINGS_KEY, "{}") or "{}")
        entry = {
            "backend_id": str(target_row["id"]),
            "reference_id": reference_id,
            "envelope_size": len(envelope),
            "header": header,
            "created_at": created_at,
        }
        if burn_after_read:
            # Opt-in marker read by the blob route: schedule destruction for
            # after the last byte reaches the recipient.
            entry["burn"] = True
        links[token] = entry
        db.set_setting(
            ENVELOPE_SETTINGS_KEY, json.dumps(links, separators=(",", ":"))
        )

    logger.info(
        "Envelope share created for %s (%d plaintext bytes, %d segments)",
        file_id, len(plaintext), segment_count,
    )
    return {
        "status": "success",
        "token": token,
        "url": f"/e/{token}",        # relative path; routes format the absolute URL
        "passphrase": passphrase,    # shown ONCE, out-of-band — never stored
        "expires_at": expires_at,
        "max_downloads": max_downloads,
        "burn_after_read": burn_after_read,
        "size": len(plaintext),
        "envelope_size": len(envelope),
        "filename": header["filename"],
        "mime_type": header["mime_type"],
    }


def verify_envelope_access(token: str, db=None, now=None) -> dict:
    """TTL + max_downloads + revocation + burn checks for an envelope link.

    Delegates to :func:`open_link` so envelope links raise exactly the same
    errors (FileNotFoundError / PermissionError) and messages as classic
    links, then confirms an envelope is actually recorded for the token.
    ``now`` optionally pins the clock for the expiry check (tests); when
    omitted the wall clock is used, same as ``open_link``.

    Burned links are checked BEFORE ``open_link``: burning also revokes the
    share row, so checking the row first would misreport a finished link as
    a merely-revoked 403.  A burned link is terminal and must answer 410 even
    if it would otherwise be expired or over its download limit.
    """
    db = db or require_db()
    meta = _load_envelope_meta(db, token)
    if meta is None:
        # Classic /s/ token (or unknown token): no envelope behind it.
        raise FileNotFoundError("Envelope share link not found.")
    if meta.get("burned"):
        raise EnvelopeBurnedError(BURNED_MESSAGE)
    row = open_link(token)  # missing / revoked / expired / limit / passcode
    if now is not None and row["expires_at"]:
        try:
            if datetime.fromisoformat(row["expires_at"]) < now:
                raise PermissionError("This share link has expired.")
        except ValueError:
            logger.warning("Invalid expiry stored for token %s", token)
    return {
        "token": token,
        "file_id": row["file_id"],
        "filename": row["filename"],
        "mime_type": row["mime_type"],
        "file_size": row["file_size"],
        "expires_at": row["expires_at"],
        "max_downloads": row["max_downloads"],
        "download_count": row["download_count"],
        "envelope": meta,
        "header": meta["header"],
    }


async def load_envelope_blob(info: dict, db=None, objects=None) -> bytes:
    """Download the stored envelope ciphertext for an already-verified link.

    Returns the raw GDSHARE1 blob — still fully encrypted; this process
    cannot read it without the recipient's passphrase.
    """
    db = db or require_db()
    meta = info["envelope"]
    backend_id = meta["backend_id"]
    if objects is None:
        _, objects = await active_backends(connect_remote=False)
    obj = objects.get(backend_id)
    if obj is None:
        row = db.get_backend(backend_id)
        if row is None:
            raise FileNotFoundError(
                "The storage backend holding this envelope no longer exists."
            )
        obj = build_backend(row)
    parts: list[bytes] = []
    async for block in obj.download(meta["reference_id"]):
        parts.append(block)
    envelope = b"".join(parts)
    if not envelope.startswith(ENVELOPE_MAGIC):
        raise RuntimeError("Stored envelope is corrupt (bad magic).")
    return envelope


async def burn_envelope(token: str, db=None, objects=None) -> dict:
    """Burn an envelope link: destroy the ciphertext, tombstone the link.

    Called by the blob route as a ``BackgroundTask`` AFTER the last byte of
    the envelope has been handed to the recipient (a completed transfer —
    TestClient runs it synchronously on response close).  Rationale: burn
    after read is about removing the *server-side copy* so there is never a
    second fetch; the recipient-side screenshot/mirror risk is out of our
    control, but keeping a re-downloadable ciphertext around is not.

    Order matters and is deliberate:

    1. delete the backend object — best-effort; a failed delete is LOGGED
       but does NOT abort the burn, because leaving a "burned" link able to
       serve again would defeat the whole feature;
    2. rewrite the settings meta entry as burned (retained — not deleted —
       so later lookups distinguish burned (410) from unknown (404), and
       backend_id/reference_id remain for forensics);
    3. revoke the share row (belt-and-braces with step 2).

    Burn wins over ``max_downloads``: the route registers this fetch (if it
    counts at all) before scheduling the burn, and the burned meta check in
    :func:`verify_envelope_access` runs before the row's limit/revocation
    checks, so any later access answers 410 regardless of the remaining
    download budget.  Idempotent: a second burn of an already-burned token
    reports ``already_burned`` without touching storage again.
    """
    db = db or require_db()
    meta = _load_envelope_meta(db, token)
    if meta is None:
        raise FileNotFoundError("Envelope share link not found.")
    if meta.get("burned"):
        return {"status": "burned", "token": token, "already_burned": True,
                "ciphertext_destroyed": False}

    destroyed = False
    if objects is None:
        _, objects = await active_backends(connect_remote=False)
    try:
        obj = objects.get(meta["backend_id"])
        if obj is None:
            row = db.get_backend(meta["backend_id"])
            if row is not None:
                obj = build_backend(row)
        if obj is not None:
            destroyed = bool(await obj.delete(meta["reference_id"]))
        else:
            logger.warning(
                "Burn of envelope %s: backend %s unavailable; marking burned "
                "without confirmed ciphertext deletion.",
                token, meta["backend_id"],
            )
    except Exception as exc:
        logger.warning(
            "Burn of envelope %s: backend delete failed (%s); marking burned "
            "anyway so the link cannot be fetched again.", token, exc,
        )

    with db.transaction():
        links = json.loads(db.get_setting(ENVELOPE_SETTINGS_KEY, "{}") or "{}")
        entry = links.get(token) or meta
        entry["burned"] = True
        entry["burned_at"] = _now_iso()
        entry["destroyed"] = destroyed
        links[token] = entry
        db.set_setting(
            ENVELOPE_SETTINGS_KEY, json.dumps(links, separators=(",", ":"))
        )
        db.revoke_share_link(token)

    logger.info(
        "Envelope %s burned after read (ciphertext destroyed=%s)",
        token, destroyed,
    )
    return {"status": "burned", "token": token, "already_burned": False,
            "ciphertext_destroyed": destroyed}
