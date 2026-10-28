"""
ghostdrive/platform/updater.py -- Safe-by-default release update checking.

GhostDrive ships as an Inno Setup installer (installer/GhostDrive.iss) built
on top of a PyInstaller bundle (scripts/build_windows.ps1), but nothing in
the app could previously discover that a newer release exists. This module
adds an *opt-in* checker with three safety properties:

* OFF by default. An app whose pitch is "do not phone home" must not touch
  the network until the user — or a vendor/operator packaging GhostDrive —
  points ``update_feed_url`` at a feed (typically the GitHub Releases API
  URL ``https://api.github.com/repos/<owner>/<repo>/releases/latest``) AND
  sets ``update_check_enabled`` to "true". Both keys are empty/off out of
  the box, so a fresh install never makes a request.
* Verifiable downloads. An update is only reported as ``update_available``
  when a sha256 for the Windows installer could be extracted from the feed;
  otherwise the status is ``unverified`` and the download route refuses to
  fetch it. We never claim a download is verified without a hash.
* Never auto-installs. ``run_installer`` refuses to spawn a process unless
  ``confirm=True``; the UI asks the user first and the Inno Setup wizard
  (``CloseApplications=yes``) performs the actual replace. In-place
  self-replacement of the running exe is deliberately NOT implemented —
  Windows cannot overwrite a running image — ``launch_installer`` only
  reports readiness.
* Signed releases (opt-in via ``GHOSTDRIVE_RELEASE_PUBKEY``). The sha256
  checks above prove the bytes match the hash the *feed* served — a
  compromised feed can serve a matching hash for malicious bytes. When the
  env var points at a PEM-encoded Ed25519 public key, a staged download
  must additionally be accompanied by a detached ``.sig`` JSON document
  (``{"algo": "ed25519", "sig": <b64>, "pubkey_sha256": <hex>}``) that
  verifies against that key; any failure raises ``SignatureError`` and the
  partial file is deleted. With the env var unset (the default today) the
  behaviour is exactly the sha256-only path it always was. This is
  deliberately OPT-IN today and will be enforced by default once release-
  key distribution is established — see ``docs/REPRODUCIBLE_BUILDS.md``.

Two feed shapes are accepted (plain JSON, no SDK):

* GitHub Releases API (``releases/latest``): ``tag_name``, ``html_url``,
  ``body``, ``published_at`` and ``assets[]`` with ``name`` /
  ``browser_download_url`` and — since GitHub added them — a ``digest``
  like ``"sha256:abcd..."``. A ``SHA256SUMS``-style asset is preferred
  over the per-asset digest when present.
* Custom/simple feed for self-hosters:
  ``{"version": ..., "url": ..., "sha256": ..., "notes": ...}``
  (``published_at`` optional).

The feed checker itself needs nothing beyond stdlib ``urllib``,
``hashlib``, ``hmac``, ``json``; the optional signature check adds
``cryptography`` (already a core dependency of the crypto stack).
Every failure mode (network, bad JSON, unexpected shape, garbage version)
becomes ``{"status": "error", "detail": ...}`` — the check must never
break the app.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

logger = logging.getLogger("ghostdrive.platform.updater")

# ── Persisted settings keys (db.set_setting / db.get_setting) ──────────────

# Empty by default: pointing this at a feed IS the act of enabling network
# contact, so vendors/operators (or the user) must opt in explicitly —
# normally with the GitHub Releases `releases/latest` API URL above.
UPDATE_FEED_URL = "update_feed_url"

# Second opt-in switch. Both this flag AND a non-empty feed URL are required
# before check_for_update() does anything; the defaults are OFF.
UPDATE_CHECK_ENABLED = "update_check_enabled"

# JSON blob of the last *successful* check (includes ``checked_at``).
# Errors are never cached so a transient failure can be retried immediately.
UPDATE_LAST_CHECK = "update_last_check"

DEFAULT_FEED_URL = ""
DEFAULT_CHECK_ENABLED = "false"

# Cheap politeness to the feed: the UI may call GET /api/update/check on
# every page load, so a successful result is reused for 6 hours before the
# network is touched again. ``now`` is injected so tests can step past it.
_RECHECK_HOURS = 6

# urllib is synchronous, so the default fetcher runs it on a worker thread
# (asyncio.to_thread) — a slow feed must never block the event loop. The
# timeout applies to each socket operation; 10s is plenty for a small JSON
# document and keeps a hung host from stalling callers.
_FETCH_TIMEOUT_S = 10.0
# Installers are tens of MB, so the download gets a more generous per-read
# timeout than the feed probe.
_DOWNLOAD_TIMEOUT_S = 60.0
_CHUNK = 1 << 20  # 1 MiB — streamed so the installer is never held in RAM

# Staged download layout: hash into ``.part`` first, rename only on match,
# so a partial/corrupt file can never be mistaken for a verified installer.
UPDATE_BINARY_NAME = "GhostDrive-update.exe"
UPDATE_PART_NAME = UPDATE_BINARY_NAME + ".part"

# PEP 440 subset we support:
#   * optional "v" prefix (GitHub tags are usually "v1.2.3")
#   * dotted numbers, at least major.minor.patch (shorter inputs are
#     zero-padded: "0.1" == (0, 1, 0))
#   * optional pre-release suffix separated by "-", "_" or nothing:
#     -alpha / -beta / -rc.N / -rcN / rc1 / a1 / b2 / dev ...
#     (case-insensitive) — treated as a pre-release, which sorts BELOW the
#     same numeric release (0.1.0-alpha < 0.1.0)
#   * optional "+local" label, stripped and ignored for ordering
# Anything else (numeric-only suffixes like "1.0.0-1", unknown words,
# dates) is rejected with ValueError: we would rather report an error than
# silently mis-order versions we do not understand.
_VERSION_RE = re.compile(
    r"^v?(?P<numeric>\d+(?:\.\d+)*)"
    r"(?:[._-]?(?P<stage>alpha|beta|rc|pre|preview|dev|a|b|c)(?:[._-]?\d+)?)?"
    r"(?:\+[A-Za-z0-9._-]+)?$",
    re.IGNORECASE,
)

# Asset names that conventionally carry per-file sha256 sums.
_SUMS_NAMES = {"sha256sums", "sha256sums.txt", "checksums.txt", "checksums.sha256", "sha256.txt"}


# ── Version handling ────────────────────────────────────────────────────────

def current_version() -> str:
    """Return the version of the running GhostDrive.

    Fallback chain (first hit wins), documented because each environment
    resolves it differently:

    1. ``importlib.metadata.version("ghostdrive")`` — correct for pip/
       poetry installs and for the PyInstaller bundle when the dist-info
       is collected alongside the app.
    2. ``ghostdrive.__version__`` — the source constant (pyproject.toml
       carries the same value); used when no distribution metadata exists
       on disk, e.g. a frozen bundle without dist-info.
    3. ``"0.1.0"`` — pyproject's version literal as an absolute last
       resort so a bare environment still yields a comparable string.
    """
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version("ghostdrive")
        except PackageNotFoundError:
            pass
    except Exception:  # pragma: no cover - import machinery differences
        pass
    try:
        from ghostdrive import __version__

        return str(__version__)
    except Exception:  # pragma: no cover - never let version probing raise
        return "0.1.0"


def parse_version(v: str) -> tuple[int, ...]:
    """Parse ``v`` into a comparable numeric tuple.

    ``"0.1.0"`` / ``"0.1.0-alpha"`` / ``"v0.1.0"`` → ``(0, 1, 0)``. The
    pre-release suffix is stripped here; *ordering* of pre-releases below
    the same numeric release is applied by :func:`is_newer` via
    :func:`is_prerelease`, because a plain tuple of ints cannot express
    "equal numbers, but earlier". Short inputs are zero-padded to three
    components (``"0.1"`` → ``(0, 1, 0)``, so 0.1 == 0.1.0 as in PEP 440).

    Raises:
        ValueError: the string is outside the documented PEP 440 subset
            (garbage, unknown suffixes, empty input).
    """
    if not isinstance(v, str) or not v.strip():
        raise ValueError(f"Invalid version: {v!r}")
    m = _VERSION_RE.match(v.strip())
    if not m:
        raise ValueError(f"Invalid version: {v!r} (unsupported format)")
    parts = [int(p) for p in m.group("numeric").split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def is_prerelease(v: str) -> bool:
    """True when ``v`` carries a pre-release suffix (``-alpha``/``-rc.N``/...).

    Raises ValueError for strings :func:`parse_version` would reject.
    """
    if not isinstance(v, str) or not v.strip():
        raise ValueError(f"Invalid version: {v!r}")
    m = _VERSION_RE.match(v.strip())
    if not m:
        raise ValueError(f"Invalid version: {v!r} (unsupported format)")
    return m.group("stage") is not None


def is_newer(candidate: str, current: str) -> bool:
    """True when ``candidate`` is strictly newer than ``current``.

    Ordering rules (PEP 440 subset):

    * numeric components compare first (both sides are zero-padded to the
      same width so ``1.2.3`` == ``1.2.3.0``);
    * when the numbers tie, a final release is newer than its own
      pre-release — ``0.1.0-alpha < 0.1.0``;
    * two pre-releases of the same numbers are NOT ordered against each
      other (``rc.2`` vs ``beta.1`` is outside the supported subset), and
      a tie never triggers an upgrade: safe by default.

    Raises ValueError when either side is unparseable.
    """
    cand = parse_version(candidate)
    cur = parse_version(current)
    width = max(len(cand), len(cur))
    cand = cand + (0,) * (width - len(cand))
    cur = cur + (0,) * (width - len(cur))
    if cand != cur:
        return cand > cur
    # Equal numbers: only a final release outranks its own pre-release.
    return not is_prerelease(candidate) and is_prerelease(current)


# ── Settings / cache helpers ────────────────────────────────────────────────

def _load_check_settings(db=None) -> tuple[str, bool]:
    """Read ``update_feed_url`` / ``update_check_enabled`` with safe defaults.

    ``db=None`` (locked vault, not wired up yet) and a failing read both
    fall back to the defaults — empty feed and disabled — so a missing
    database can never switch the checker ON.
    """
    feed_url = DEFAULT_FEED_URL
    enabled_raw = DEFAULT_CHECK_ENABLED
    if db is not None:
        try:
            feed_url = db.get_setting(UPDATE_FEED_URL, DEFAULT_FEED_URL)
            enabled_raw = db.get_setting(UPDATE_CHECK_ENABLED, DEFAULT_CHECK_ENABLED)
        except Exception as exc:  # locked/closed db — treat as defaults
            logger.debug("Could not read update settings: %s", exc)
            feed_url, enabled_raw = DEFAULT_FEED_URL, DEFAULT_CHECK_ENABLED
    enabled = str(enabled_raw).strip().lower() in ("1", "true", "yes", "on")
    return str(feed_url or "").strip(), enabled


def _last_check(db) -> Optional[dict]:
    """Return the raw cached last-check result, or None (no freshness filter)."""
    if db is None:
        return None
    try:
        raw = db.get_setting(UPDATE_LAST_CHECK, "")
    except Exception as exc:
        logger.debug("Could not read update check cache: %s", exc)
        return None
    if not raw:
        return None
    try:
        cached = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    return cached if isinstance(cached, dict) else None


def _as_utc(dt: datetime) -> datetime:
    """Normalize to an aware UTC datetime so naive/aware values never clash."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _read_cache(db, now: datetime) -> Optional[dict]:
    """Return the cached result when it is fresher than ``_RECHECK_HOURS``.

    This is a cheap politeness rule toward the feed (and toward GitHub's
    rate limits): the UI polls, the network should not be hit every time.
    A cache timestamp in the future (clock moved backwards) counts as stale
    so we re-check rather than trusting a timestamp we cannot believe.
    """
    cached = _last_check(db)
    if not cached:
        return None
    try:
        checked = _as_utc(datetime.fromisoformat(str(cached["checked_at"])))
    except (KeyError, TypeError, ValueError):
        return None
    age = _as_utc(now) - checked
    if timedelta(0) <= age < timedelta(hours=_RECHECK_HOURS):
        return cached
    return None


def _write_cache(db, result: dict) -> None:
    """Persist a successful check result; best-effort (a locked db is fine)."""
    if db is None:
        return
    try:
        db.set_setting(UPDATE_LAST_CHECK, json.dumps(result))
    except Exception as exc:
        logger.debug("Could not persist update check cache: %s", exc)


# ── Feed fetching ───────────────────────────────────────────────────────────

def _urllib_fetch(url: str) -> bytes:  # sync worker-thread helper
    """Blocking stdlib fetch; GitHub's API requires a User-Agent header."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"GhostDrive/{current_version()} (+update-check)",
            "Accept": "application/json, */*;q=0.1",
        },
    )
    with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT_S) as resp:
        return resp.read()


async def _default_fetch(url: str) -> bytes:
    """Default ``fetch`` for :func:`check_for_update`.

    urllib is synchronous, so it runs via ``asyncio.to_thread`` — otherwise
    a slow feed would block the whole event loop for up to the timeout.
    """
    return await asyncio.to_thread(_urllib_fetch, url)


# ── Feed evaluation ─────────────────────────────────────────────────────────

def _normalize_sha(value: Any) -> Optional[str]:
    """Return a lower-case 64-hex sha256, or None when the value is unusable.

    GitHub serves ``digest`` as ``"sha256:<hex>"``; custom feeds may send
    bare hex (either case). Anything malformed becomes None so the update
    degrades to ``unverified`` — a bad hash must never reach the downloader.
    """
    if not isinstance(value, str):
        return None
    raw = value.strip().lower()
    if raw.startswith("sha256:"):
        raw = raw[len("sha256:"):].strip()
    if len(raw) != 64 or any(c not in "0123456789abcdef" for c in raw):
        return None
    return raw


def _pick_installer_asset(assets: list) -> Optional[dict]:
    """Pick the Windows installer asset (what the Inno Setup build produces).

    Prefers a ``.exe`` whose name contains "setup"/"install" (the
    ``GhostDrive-<version>-setup.exe`` artifact), then any other ``.exe``.
    """
    exes = [a for a in assets if isinstance(a, dict)
            and str(a.get("name") or "").lower().endswith(".exe")]
    if not exes:
        return None
    for asset in exes:
        name = str(asset.get("name") or "").lower()
        if "setup" in name or "install" in name:
            return asset
    return exes[0]


async def _sha256_from_sums(
    assets: list,
    installer: Optional[dict],
    fetch: Callable[[str], Awaitable[bytes]],
) -> Optional[str]:
    """Match the installer's sha256 inside a ``SHA256SUMS``-style asset.

    Returns None — never an error — when there is no sums file, no
    installer filename to match, or the lookup fails; the caller then falls
    back to the per-asset ``digest`` and finally to ``unverified``. A
    secondary lookup must not fail the whole check.
    """
    if installer is None:
        return None
    sums_asset = None
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name") or "").lower()
        if name.startswith("sha256sums") or name in _SUMS_NAMES:
            sums_asset = asset
            break
    if sums_asset is None:
        return None
    sums_url = str(sums_asset.get("browser_download_url") or "")
    installer_name = str(installer.get("name") or "")
    if not sums_url or not installer_name:
        return None
    try:
        raw = await fetch(sums_url)
    except Exception as exc:
        logger.debug("SHA256SUMS lookup failed (%s); falling back", exc)
        return None
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    target = installer_name.lower()
    for line in text.splitlines():
        parts = line.split()
        # GNU coreutils style: "<sha256>  <filename>" (or "hash *filename").
        if len(parts) < 2:
            continue
        digest, name = parts[0], parts[1].lstrip("*")
        if name.lower() == target:
            normalized = _normalize_sha(digest)
            if normalized:
                return normalized
    return None


async def _evaluate_payload(
    raw: bytes,
    current: str,
    fetch: Callable[[str], Awaitable[bytes]],
) -> dict:
    """Turn one feed document into a check result (no ``checked_at`` yet).

    Accepts both documented shapes (see module docstring). Raises ValueError
    / json errors for anything we cannot evaluate — the caller converts
    those into ``{"status": "error"}``.
    """
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("feed payload is not a JSON object")

    if "version" in payload:
        shape = "custom"
    elif "tag_name" in payload:
        shape = "github"
    else:
        raise ValueError(
            "unrecognized feed format (expected GitHub release JSON with "
            "tag_name, or a custom {'version','url','sha256'} object)"
        )

    latest_raw = payload.get("version") if shape == "custom" else payload.get("tag_name")
    latest = str(latest_raw or "").strip()
    if not latest:
        raise ValueError("feed entry has no version/tag")
    notes = str(payload.get("notes") or "") if shape == "custom" else str(payload.get("body") or "")
    published = payload.get("published_at")

    # Raises ValueError for a tag outside the supported subset → surfaces
    # as status "error": refuse to compare versions we cannot parse.
    if not is_newer(latest, current):
        return {"status": "up_to_date", "current": current}

    # There IS an update — now find something actionable (url) and, if we
    # can, proof that it is authentic (sha256).
    if shape == "custom":
        url = str(payload.get("url") or "").strip()
        sha256 = _normalize_sha(payload.get("sha256"))
    else:
        assets = payload.get("assets")
        assets = assets if isinstance(assets, list) else []
        installer = _pick_installer_asset(assets)
        url = str((installer or {}).get("browser_download_url") or "").strip()
        if not url:
            url = str(payload.get("html_url") or "").strip()
        # Preference order: SHA256SUMS asset (explicitly published sums) →
        # per-asset digest GitHub now serves → unverified. We never claim a
        # download is verified without a hash.
        sha256 = await _sha256_from_sums(assets, installer, fetch)
        if sha256 is None and installer is not None:
            sha256 = _normalize_sha(installer.get("digest"))

    if not url:
        raise ValueError("feed entry has no download url")

    return {
        "status": "update_available" if sha256 else "unverified",
        "current": current,
        "latest": latest,
        "url": url,
        "sha256": sha256,
        "notes": notes,
        "published_at": published,
    }


# ── Public check API ────────────────────────────────────────────────────────

async def check_for_update(
    db=None,
    now: Optional[datetime] = None,
    fetch: Optional[Callable[[str], Awaitable[bytes]]] = None,
) -> dict:
    """Check the configured feed for a newer release.

    Never raises: network failures, malformed JSON and unexpected shapes
    all come back as ``{"status": "error", "detail": ...}`` because an
    update probe must never break the app.

    Returns one of:

    * ``{"status": "disabled"}`` — no feed configured or the check switch
      is off (the default; also the result when ``db is None``, so a
      locked/missing database can never enable networking).
    * ``{"status": "up_to_date", "current", "checked_at"}``
    * ``{"status": "update_available"|"unverified", "current", "latest",
      "url", "sha256"|None, "notes", "published_at", "checked_at"}`` —
      ``unverified`` means no hash could be extracted; callers must not
      download in that state.
    * ``{"status": "error", "detail"}``

    Args:
        db: open GhostDriveDB to read settings/cache from (pass
            ``require_db()``); None means "no database" → defaults → off.
        now: injected clock for the 6h cache (tests); aware or naive UTC.
        fetch: injectable async ``(url) -> bytes`` fetcher; defaults to
            stdlib urllib on a worker thread.
    """
    feed_url, enabled = _load_check_settings(db)
    if not enabled or not feed_url:
        # Default configuration: no request is made at all.
        return {"status": "disabled"}

    if now is None:
        now = datetime.now(timezone.utc)
    now = _as_utc(now)

    cached = _read_cache(db, now)
    if cached is not None:
        # Politeness: reused for <6h so polling the UI does not hammer the feed.
        return cached

    if fetch is None:
        fetch = _default_fetch

    current = current_version()
    checked_at = now.isoformat()
    try:
        raw = await fetch(feed_url)
        result = await _evaluate_payload(raw, current, fetch)
    except Exception as exc:
        # The update check must never break the app — report, don't raise.
        logger.warning("Update check failed: %s", exc)
        return {"status": "error", "detail": str(exc) or exc.__class__.__name__}

    result["checked_at"] = checked_at
    # Only successful results are cached; errors stay retryable immediately.
    _write_cache(db, result)
    return result


def status(db=None) -> dict:
    """Settings + last-check cache for the UI (GET /api/update/status)."""
    feed_url, enabled = _load_check_settings(db)
    return {
        "enabled": enabled,
        "feed_url": feed_url,
        "last_check": _last_check(db),
        "current": current_version(),
    }


# ── Release signatures (Ed25519, opt-in) ────────────────────────────────────
#
# WHY: the sha256 checks in this module only prove that the bytes match
# whatever hash the feed served — a compromised or hostile feed can supply a
# matching hash for malicious bytes. A detached Ed25519 signature binds the
# artifact to the release key, which lives on an offline signing machine
# (scripts/keygen_release_key.py, scripts/release.py; operator doc:
# docs/REPRODUCIBLE_BUILDS.md).
#
# Trust is switched on by pointing the GHOSTDRIVE_RELEASE_PUBKEY env var at
# a PEM public key file. Env var, not a settings key: update verification
# must work before (and without) an unlocked vault, and an operator
# packaging GhostDrive can set it system-wide for every user of the machine.

# Path to the trusted PEM public key. Unset (the default) means "sha256
# only" — byte-for-byte the pre-signing behaviour.
RELEASE_PUBKEY_ENV = "GHOSTDRIVE_RELEASE_PUBKEY"

# The only algorithm accepted. A future rotation scheme may add more;
# unknown values are refused, never ignored.
SIG_ALGO = "ed25519"
_SIG_RAW_LEN = 64  # Ed25519 signatures are exactly 64 bytes
_SIG_FILE_SUFFIX = ".sig"  # detached metadata lives next to the artifact URL


class SignatureError(RuntimeError):
    """A release failed Ed25519 signature verification.

    Subclasses RuntimeError so existing callers that treat update failures
    as runtime errors (web/routes/update.py::_http_error) keep working — a
    failed verification surfaces as an aborted download, never as a staged
    installer.
    """


def _load_ed25519_public_key(public_key_pem: bytes) -> Ed25519PublicKey:
    """Load a PEM public key; raise SignatureError for anything untrusted."""
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError) as exc:
        raise SignatureError(f"unusable release public key: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SignatureError("release public key is not Ed25519")
    return key


def release_pubkey_sha256_hex(public_key_pem: bytes) -> str:
    """Lower-case hex sha256 over the raw 32 bytes of the Ed25519 key.

    This is the value carried in ``.sig`` documents as ``pubkey_sha256``
    and the thing to compare out-of-band when the key is first distributed.
    """
    raw = _load_ed25519_public_key(public_key_pem).public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return hashlib.sha256(raw).hexdigest()


def release_pubkey_fingerprint(public_key_pem: bytes) -> str:
    """Display form of :func:`release_pubkey_sha256_hex` — colon-grouped hex."""
    digest = release_pubkey_sha256_hex(public_key_pem)
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def verify_release_signature(
    artifact_bytes: bytes,
    sig_meta: dict,
    public_key_pem: bytes,
) -> None:
    """Verify a detached Ed25519 release signature over ``artifact_bytes``.

    ``sig_meta`` is the decoded ``.sig`` JSON document produced by
    ``scripts/release.py``::

        {"algo": "ed25519",
         "sig": "<base64 of the raw 64-byte signature>",
         "pubkey_sha256": "<hex sha256 of the raw 32-byte public key>",
         # optional, informational only:
         "artifact": "<filename>", "sha256": "<hex>"}

    Checks, in order: algorithm is ``ed25519``; ``pubkey_sha256`` matches
    the provided trusted key (the key-rotation guard — a signature made by
    a *different* key fails here, before any crypto); the base64 decodes
    to exactly 64 bytes; and ``Ed25519PublicKey.verify`` accepts the
    signature over the exact artifact bytes.

    Returns None on success.

    Raises:
        SignatureError: on any mismatch or malformed input. Callers that
            are staging a download must treat this as fatal — delete the
            partial file and abort the update.
    """
    if not isinstance(sig_meta, dict):
        raise SignatureError("signature metadata is not a JSON object")
    algo = str(sig_meta.get("algo") or "").strip().lower()
    if algo != SIG_ALGO:
        raise SignatureError(f"unsupported signature algorithm: {algo!r}")
    claimed = str(sig_meta.get("pubkey_sha256") or "").strip().lower()
    if claimed != release_pubkey_sha256_hex(public_key_pem):
        # Key-rotation guard: the signature was made by a key other than
        # the one we were told to trust. Fail before the crypto step.
        raise SignatureError("release signing key mismatch (different key)")
    try:
        signature = base64.b64decode(str(sig_meta.get("sig") or ""), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SignatureError(f"signature is not valid base64: {exc}") from exc
    if len(signature) != _SIG_RAW_LEN:
        raise SignatureError(
            f"signature must be {_SIG_RAW_LEN} raw Ed25519 bytes, got {len(signature)}"
        )
    try:
        _load_ed25519_public_key(public_key_pem).verify(signature, artifact_bytes)
    except InvalidSignature as exc:
        raise SignatureError(
            "release signature does not match the artifact"
        ) from exc


def verify_release_signature_file(
    artifact_path: Path,
    sig_path: Path,
    public_key_pem: bytes,
) -> None:
    """Path-based wrapper around :func:`verify_release_signature`.

    Reads the artifact bytes and the ``.sig`` JSON document from disk and
    verifies them against ``public_key_pem``. Same failure contract: raises
    SignatureError on anything wrong, returns None on success.
    """
    sig_path = Path(sig_path)
    try:
        meta = json.loads(sig_path.read_bytes())
    except FileNotFoundError as exc:
        raise SignatureError(f"signature file not found: {sig_path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise SignatureError(f"unreadable signature file {sig_path}: {exc}") from exc
    verify_release_signature(Path(artifact_path).read_bytes(), meta, public_key_pem)


def _load_release_pubkey_from_env() -> Optional[bytes]:
    """Trusted public key from ``GHOSTDRIVE_RELEASE_PUBKEY``, or None.

    None means "signature checking off" (env unset — the default, and the
    legacy sha256-only path). The env var being *set* is the operator's
    explicit intent to verify, so a key file that exists but cannot be read
    raises SignatureError rather than silently downgrading to sha256-only:
    a typo in the key path must never disable verification.
    """
    raw = os.environ.get(RELEASE_PUBKEY_ENV, "").strip()
    if not raw:
        return None
    path = Path(raw)
    try:
        pem = path.read_bytes()
    except OSError as exc:
        raise SignatureError(
            f"{RELEASE_PUBKEY_ENV} points at {path} but it cannot be read: {exc}"
        ) from exc
    return pem


def _fetch_sig_meta(
    url: str,
    fetch: Optional[Callable[[str], bytes]] = None,
) -> Optional[dict]:
    """Fetch ``<url>.sig`` alongside the download; None when it is absent.

    A *missing* .sig (network error, 404) returns None so the caller can
    fall back to the sha256-only path with a loud warning. A .sig that is
    fetched but is not a JSON object raises SignatureError: a present-but-
    unusable signature is tampering, not absence.
    """
    sig_url = url + _SIG_FILE_SUFFIX
    try:
        raw = fetch(sig_url) if fetch is not None else _urllib_fetch(sig_url)
    except Exception as exc:
        logger.debug("No signature accompanies the download (%s)", exc)
        return None
    try:
        meta = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SignatureError(
            f"malformed signature document at {sig_url}: {exc}"
        ) from exc
    if not isinstance(meta, dict):
        raise SignatureError(
            f"malformed signature metadata at {sig_url}: not a JSON object"
        )
    return meta


# ── Download staging ────────────────────────────────────────────────────────

def stage_download(
    url: str,
    expected_sha256: str,
    dest_dir: Path,
    fetch: Optional[Callable[[str], bytes]] = None,
    *,
    sig_meta: Optional[dict] = None,
) -> dict:
    """Download the installer to ``dest_dir`` and verify it against sha256.

    Streams into ``GhostDrive-update.exe.part`` while hashing, renames to
    ``GhostDrive-update.exe`` only on a match, and deletes the partial file
    on any mismatch — an unverified installer never survives on disk.

    When the ``GHOSTDRIVE_RELEASE_PUBKEY`` env var points at a trusted
    PEM public key, the sha256 check is followed by an Ed25519 signature
    check (:func:`verify_release_signature`); failure raises
    SignatureError, deletes the partial file, and aborts the update. With
    the env var unset (the default today) this function behaves exactly as
    it always has — sha256 only. Signature checking is OPT-IN today and
    will be enforced by default once release-key distribution is
    established (docs/REPRODUCIBLE_BUILDS.md).

    Args:
        url: where to fetch the installer from.
        expected_sha256: hex sha256 from the (verified) feed.
        dest_dir: created if missing; typically
            ``state.app_data_dir / "updates"``.
        fetch: injectable sync ``(url) -> bytes`` for tests; the default
            streams from urllib in 1 MiB chunks so a large installer is
            never held in memory.
        sig_meta: optional pre-fetched ``.sig`` JSON document (shape in
            :func:`verify_release_signature`). Only honoured when
            ``GHOSTDRIVE_RELEASE_PUBKEY`` is set; when it is None and the
            env var is set, ``<url>.sig`` is fetched alongside the
            installer using the same ``fetch`` mechanism.

    Returns:
        ``{"path", "sha256", "size"}`` with path as a string.

    Raises:
        RuntimeError: missing/invalid expected checksum, download failure,
            or checksum mismatch (the partial file is removed first).
        SignatureError: GHOSTDRIVE_RELEASE_PUBKEY is set and either the
            env var points at an unreadable key file, a present ``.sig``
            document is malformed, or the signature does not verify —
            the partial file is removed first.
    """
    expected = _normalize_sha(expected_sha256)
    if expected is None:
        raise RuntimeError(
            "no valid expected checksum — refusing to stage an unverified download"
        )

    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    part = dest_dir / UPDATE_PART_NAME
    final = dest_dir / UPDATE_BINARY_NAME

    digest = hashlib.sha256()
    size = 0
    try:
        if fetch is None:
            # Stream to disk while hashing: keeps memory flat for a ~100 MB
            # installer. urllib is sync — stage_download itself is called
            # from a worker thread by the route.
            req = urllib.request.Request(
                url,
                headers={"User-Agent": f"GhostDrive/{current_version()} (+update-check)"},
            )
            with urllib.request.urlopen(req, timeout=_DOWNLOAD_TIMEOUT_S) as resp:
                with open(part, "wb") as fh:
                    while True:
                        chunk = resp.read(_CHUNK)
                        if not chunk:
                            break
                        fh.write(chunk)
                        digest.update(chunk)
                        size += len(chunk)
        else:
            # Test seam: the fake fetcher hands over the whole body at once.
            data = fetch(url)
            part.write_bytes(data)
            digest.update(data)
            size = len(data)
    except Exception as exc:
        part.unlink(missing_ok=True)
        raise RuntimeError(f"download failed: {exc}") from exc

    actual = digest.hexdigest()
    # Constant-time compare: public sha256 values don't need timing safety,
    # but doing it anyway keeps the habit (and the code path) in place.
    if not hmac.compare_digest(actual, expected):
        part.unlink(missing_ok=True)  # never leave an unverified installer
        raise RuntimeError("checksum mismatch")

    # Ed25519 release signature — OPT-IN via GHOSTDRIVE_RELEASE_PUBKEY.
    # The sha256 above only proves the bytes match the hash the feed
    # served; the signature binds them to the offline release key. The
    # env var being unset (the default) means exactly the sha256-only
    # behaviour above; enforcement by default follows once release-key
    # distribution is established (docs/REPRODUCIBLE_BUILDS.md).
    try:
        pubkey_pem = _load_release_pubkey_from_env()
        if pubkey_pem is not None:
            meta = sig_meta if sig_meta is not None else _fetch_sig_meta(url, fetch)
            if meta is None:
                # No .sig accompanies this download: fall through on the
                # sha256-only path (the pre-signing behaviour) — but loudly:
                # an operator who configured a trusted key should also be
                # publishing signatures next to the artifacts.
                logger.warning(
                    "GHOSTDRIVE_RELEASE_PUBKEY is set but no %s accompanies %s — "
                    "accepting the download on sha256 alone",
                    _SIG_FILE_SUFFIX, url,
                )
            else:
                verify_release_signature(part.read_bytes(), meta, pubkey_pem)
    except SignatureError:
        part.unlink(missing_ok=True)  # never leave an unverified installer
        raise

    final.unlink(missing_ok=True)  # replace any previously staged download
    part.rename(final)
    return {"path": str(final), "sha256": actual, "size": size}


# ── Installer hand-off ──────────────────────────────────────────────────────

def launch_installer(path: Path) -> dict:
    """Report that a staged installer is ready — does NOT spawn anything.

    Self-replacement is deliberately unimplemented: Windows cannot overwrite
    a running exe, and GhostDrive must never restart or replace itself
    without the user confirming in the UI. The route calls
    :func:`run_installer` with ``confirm=True`` only after that
    confirmation; Inno Setup's ``CloseApplications=yes`` then handles
    closing the running app before overwriting it.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"installer not found: {p}")
    return {"status": "ready", "path": str(p)}


def run_installer(path: Path, confirm: bool = False) -> dict:
    """Spawn the staged installer — only after explicit user confirmation.

    Args:
        path: the verified, staged ``GhostDrive-update.exe``.
        confirm: must be True; the route only sets it after the user
            clicks through the confirmation prompt.

    Returns:
        ``{"status": "started", "path": str(path)}``

    Raises:
        RuntimeError: ``confirm`` is False — never spawn without the user
            clicking through first.
        FileNotFoundError: the staged file is missing.
    """
    if not confirm:
        raise RuntimeError("confirmation required")
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"installer not found: {p}")
    if sys.platform == "win32":
        # os.startfile hands the file to its shell association with no
        # console window; the Inno wizard runs detached and closes us itself.
        os.startfile(str(p))  # type: ignore[attr-defined]  # Windows-only API
    else:
        # No shell involved (no interpretation of metacharacters); other
        # platforms have no Inno installer, but the gate still behaves.
        subprocess.Popen([str(p)])
    return {"status": "started", "path": str(p)}
