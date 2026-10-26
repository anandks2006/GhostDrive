"""
s3_backend.py -- S3-compatible object storage backend plugin for GhostDrive.

Talks plain REST + AWS Signature Version 4 to any S3-compatible endpoint:
Backblaze B2, Wasabi, MinIO, or AWS S3 itself.  SigV4 is implemented with the
standard library only (hmac/hashlib/datetime) so this backend adds zero new
dependencies -- a hard project constraint.  HTTP goes through httpx, which is
already a core dependency (pyproject.toml: "All backends, SOCKS5, streaming").

Why this backend exists: users without a NAS get a cheap *true offsite*
failure domain.  Storage on Backblaze B2 / Wasabi (~$6/TB/month) satisfies the
durability contract's requires_offsite flag, which local folders and LAN NAS
devices can never satisfy.  Offsite classification lives in
ghostdrive/services/durability.py and keys off the backend type "s3".

Two design notes worth documenting:

* Path-style addressing (endpoint/bucket/key) is the default and the
  recommended mode.  Virtual-host-style (bucket as subdomain) breaks with
  IP/localhost endpoints (the common MinIO quickstart) and with buckets whose
  names contain dots or that lack wildcard DNS -- B2 and MinIO both work
  reliably with path style, so we default to it and only support virtual-host
  style for DNS-named endpoints.

* SigV4 signs the real SHA-256 of the request body (not UNSIGNED-PAYLOAD).
  Streaming/unsigned STREAMING-AWS4-HMAC-SHA256-PAYLOAD is out of scope: the
  upload pipeline already hands upload() one sub-block at a time (<=
  sub_block_bytes), so buffering a sub-block in memory to hash it costs
  nothing we were not already paying, exactly like NASBackend does.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import logging
import time
from datetime import datetime, timezone
from typing import AsyncGenerator, Mapping, Optional, Tuple
from urllib.parse import quote, urlparse

import httpx

from ghostdrive.backends.base import BackendBase, HealthResult
from ghostdrive.exceptions import (
    BackendAuthError,
    BackendConnectionError,
    BackendError,
    BackendNotFoundError,
)

logger = logging.getLogger(__name__)

# SHA-256 of the empty string -- the required x-amz-content-sha256 value for
# bodyless requests (HEAD/GET/DELETE) per the SigV4 spec.
_EMPTY_PAYLOAD_SHA256 = hashlib.sha256(b"").hexdigest()

# Download read size: big enough to keep syscall overhead negligible, small
# enough that throttle_generator sees regular yields.
_DOWNLOAD_READ_SIZE = 64 * 1024

# Sentinel free-space value: B2/Wasabi/MinIO are effectively unlimited (no
# hard per-bucket quota is reported by the S3 API without extra permissions),
# so report an astronomically large value rather than lying with a small fake
# number that could make the upload planner skip this backend.
_UNLIMITED_SPACE_SENTINEL = 2**60


def _uri_encode(value: str, keep_slash: bool = False) -> str:
    """SigV4 UriEncode: percent-encode every byte except RFC 3986 unreserved.

    Uses uppercase hex and UTF-8 bytes (Python's quote() default) and encodes
    spaces as %20, never '+'.  '/' is preserved only inside object keys --
    S3 canonical URIs keep the key's own slashes unencoded.
    """
    return quote(value, safe="/" if keep_slash else "")


class S3Backend(BackendBase):
    """S3-compatible storage backend (Backblaze B2 / Wasabi / MinIO / AWS S3)."""

    # ── Capability flags (Spec 6.1) ─────────────────────────────────────────
    # Hot storage with real DELETE support.  It IS offsite, but offsite
    # classification is a durability concern keyed off the backend type, not a
    # capability flag (see services/durability.py backend_failure_domain).
    supports_range_requests: bool = False
    supports_streaming:      bool = True
    supports_deletion:       bool = True
    is_cold_storage:         bool = False
    is_ephemeral_url:        bool = False
    tier:                    str  = "IMPORTANT"

    def __init__(
        self,
        endpoint_url: str,
        region: str,
        bucket: str,
        access_key: str,
        secret_key: str,
        path_style: bool = True,
        prefix: str = "ghostdrive/",
    ) -> None:
        if not endpoint_url:
            raise ValueError("S3 backend requires an endpoint_url (e.g. https://s3.us-west-004.backblazeb2.com).")
        if not region:
            raise ValueError("S3 backend requires a region (e.g. us-east-1, us-west-004, auto).")
        if not bucket:
            raise ValueError("S3 backend requires a bucket name.")
        if not access_key or not secret_key:
            raise ValueError("S3 backend requires an access_key and secret_key.")

        parsed = urlparse(endpoint_url if "//" in endpoint_url else f"https://{endpoint_url}")
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"Invalid S3 endpoint_url: {endpoint_url!r}")

        self.endpoint_url = endpoint_url.rstrip("/")
        self._scheme = parsed.scheme
        # netloc keeps any ':port' so the signing Host header matches what
        # httpx actually sends for MinIO-style http://127.0.0.1:9000 endpoints.
        self._netloc = parsed.netloc
        self.region = region
        self.bucket = bucket
        self.access_key = access_key
        self.secret_key = secret_key
        self.path_style = bool(path_style)
        # Normalise prefix so callers may pass "backups/2026" or "backups/2026/".
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        self.prefix = prefix

        if not self.path_style:
            # Virtual-host style puts the bucket in DNS -- an IP or localhost
            # endpoint (typical MinIO) can never satisfy that.
            if not parsed.hostname or parsed.hostname.replace(".", "").isdigit():
                raise ValueError(
                    "path_style=False (virtual-host addressing) requires a DNS hostname "
                    "endpoint; MinIO on IP/localhost and B2 path-style endpoints need "
                    "path_style=True."
                )

        self._client: Optional[httpx.AsyncClient] = None

    # ── SigV4 signing (stdlib only) ────────────────────────────────────────

    @staticmethod
    def _sign(key: bytes, msg: str) -> bytes:
        """One HMAC-SHA256 step of the SigV4 chain."""
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def _derive_signing_key(self, date_stamp: str) -> bytes:
        """Derive the scoped signing key: AWS4+secret -> date -> region -> s3 -> aws4_request."""
        key = self._sign(b"AWS4" + self.secret_key.encode("utf-8"), date_stamp)
        key = self._sign(key, self.region)
        key = self._sign(key, "s3")
        return self._sign(key, "aws4_request")

    def _authorization_header(
        self,
        method: str,
        canonical_uri: str,
        signed_headers: Mapping[str, str],
        payload_hash: str,
        amz_date: str,
        canonical_query: str = "",
    ) -> str:
        """Build the SigV4 Authorization header value for one request.

        ``signed_headers`` maps already-lowercase header names to values; it
        must contain 'host' and the x-amz-* headers being sent.  Header names
        are sorted alphabetically for the canonical request, which is what
        makes the signature deterministic.
        """
        names = sorted(signed_headers)
        # Each canonical header line ends with \n, so the canonical request
        # gets a blank line before SignedHeaders exactly as AWS documents it.
        canonical_headers = "".join(
            f"{name}:{str(signed_headers[name]).strip()}\n" for name in names
        )
        signed_header_list = ";".join(names)
        canonical_request = (
            f"{method}\n{canonical_uri}\n{canonical_query}\n"
            f"{canonical_headers}\n{signed_header_list}\n{payload_hash}"
        )

        date_stamp = amz_date[:8]
        scope = f"{date_stamp}/{self.region}/s3/aws4_request"
        canonical_hash = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        string_to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canonical_hash}"

        signature = hmac.new(
            self._derive_signing_key(date_stamp),
            string_to_sign.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return (
            f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope},"
            f"SignedHeaders={signed_header_list},Signature={signature}"
        )

    # ── URL / path construction ────────────────────────────────────────────

    def _canonical_uri(self, key: str) -> str:
        """URI-encoded absolute path; shared by the wire URL and the signature."""
        uri = "/" + _uri_encode(self.bucket) if self.path_style else ""
        if key:
            uri += "/" + _uri_encode(key, keep_slash=True)
        return uri or "/"

    def _url_for(self, canonical_uri: str) -> str:
        if self.path_style:
            return f"{self.endpoint_url}{canonical_uri}"
        # Virtual-host style: bucket becomes the leading DNS label.
        return f"{self._scheme}://{self.bucket}.{self._netloc}{canonical_uri}"

    def _signing_host(self) -> str:
        return self._netloc if self.path_style else f"{self.bucket}.{self._netloc}"

    def _request(
        self, method: str, key: str, payload: bytes = b""
    ) -> Tuple[str, dict[str, str]]:
        """Return (url, signed headers) for one object-level request."""
        amz_date = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        payload_hash = hashlib.sha256(payload).hexdigest() if payload else _EMPTY_PAYLOAD_SHA256
        canonical_uri = self._canonical_uri(key)
        headers: dict[str, str] = {
            "host": self._signing_host(),
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        # Authorization itself is never a signed header, so it is attached
        # only after the canonical request is computed.
        headers["authorization"] = self._authorization_header(
            method, canonical_uri, headers, payload_hash, amz_date
        )
        return self._url_for(canonical_uri), headers

    def _require_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            raise BackendConnectionError("S3 backend is not connected; call connect() first.")
        return self._client

    # ── Connection Management ──

    async def connect(self) -> None:
        """Create the shared HTTP session and verify the bucket with HEAD."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0),
                follow_redirects=False,
            )
        status, error = await self._head_bucket()
        if status == 403:
            raise BackendAuthError(
                f"S3 access denied for bucket {self.bucket!r} at {self.endpoint_url} "
                f"(HTTP 403 -- check the access key permissions for this bucket)."
            )
        if status == 404:
            raise BackendConnectionError(
                f"S3 bucket {self.bucket!r} not found at {self.endpoint_url} (HTTP 404)."
            )
        if status != 200:
            raise BackendConnectionError(
                f"S3 HEAD bucket failed for {self.bucket!r} at {self.endpoint_url}: {error}"
            )
        logger.info("Connected to S3 bucket %s at %s", self.bucket, self.endpoint_url)

    async def close(self) -> None:
        """Close the shared HTTP session (base class defines no close hook)."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None

    async def _head_bucket(self) -> Tuple[Optional[int], Optional[str]]:
        """HEAD the bucket. Returns (status_code, error_message); status None on transport error."""
        client = self._require_client()
        url, headers = self._request("HEAD", "")
        try:
            resp = await client.head(url, headers=headers)
        except httpx.HTTPError as exc:
            return None, f"transport error: {exc}"
        if resp.status_code == 200:
            return 200, None
        detail = f"HTTP {resp.status_code}"
        return resp.status_code, detail

    # ── BAL Interface ──

    async def upload(
        self,
        stream: AsyncGenerator[bytes, None],
        chunk_id: str,
        sub_block_index: int,
    ) -> str:
        # Buffer the sub-block in memory: SigV4 needs the payload SHA-256 up
        # front (no streaming signing), and the pipeline already passes
        # sub-block-sized pieces, exactly like NASBackend.
        buf = io.BytesIO()
        async for block in stream:
            buf.write(block)
        data = buf.getvalue()

        key = f"{self.prefix}{chunk_id}/{sub_block_index}"
        client = self._require_client()
        url, headers = self._request("PUT", key, data)
        try:
            resp = await client.put(url, headers=headers, content=data)
        except httpx.HTTPError as exc:
            raise BackendConnectionError(f"S3 upload of {key!r} failed: {exc}") from exc

        if resp.status_code in (401, 403):
            raise BackendAuthError(f"S3 upload of {key!r} denied (HTTP {resp.status_code}).")
        if resp.status_code not in (200, 201):
            raise BackendConnectionError(
                f"S3 upload of {key!r} failed: HTTP {resp.status_code}"
            )
        # reference_id is the bare object key: opaque to the pipeline, valid
        # regardless of which endpoint serves it.
        return key

    async def download(self, reference_id: str) -> AsyncGenerator[bytes, None]:
        client = self._require_client()
        url, headers = self._request("GET", reference_id)
        try:
            async with client.stream("GET", url, headers=headers) as resp:
                if resp.status_code == 404:
                    raise BackendNotFoundError(f"S3 object not found: {reference_id!r}")
                if resp.status_code in (401, 403):
                    raise BackendAuthError(
                        f"S3 download of {reference_id!r} denied (HTTP {resp.status_code})."
                    )
                if resp.status_code != 200:
                    raise BackendConnectionError(
                        f"S3 download of {reference_id!r} failed: HTTP {resp.status_code}"
                    )
                async for chunk in resp.aiter_bytes(_DOWNLOAD_READ_SIZE):
                    yield chunk
        except httpx.HTTPError as exc:
            raise BackendConnectionError(f"S3 download of {reference_id!r} failed: {exc}") from exc

    async def delete(self, reference_id: str) -> bool:
        client = self._require_client()
        url, headers = self._request("DELETE", reference_id)
        try:
            resp = await client.delete(url, headers=headers)
        except httpx.HTTPError as exc:
            raise BackendConnectionError(f"S3 delete of {reference_id!r} failed: {exc}") from exc
        # 404 counts as success: the object is gone, which is the state delete()
        # is asked to guarantee.  This keeps tombstone cleanup idempotent when
        # it is retried across restarts.
        if resp.status_code in (204, 200, 404):
            return True
        raise BackendError(f"S3 delete of {reference_id!r} failed: HTTP {resp.status_code}")

    async def health_check(self) -> HealthResult:
        t0 = time.perf_counter()
        status, error = await self._head_bucket()
        latency_ms = (time.perf_counter() - t0) * 1000
        if status == 200:
            # The S3 API reports no bucket quota without extra ListBucket
            # permissions, so quota_remaining is left unset (None).
            return HealthResult(reachable=True, latency_ms=latency_ms)
        if status == 403:
            return HealthResult(reachable=False, error="S3 access denied (HTTP 403)", latency_ms=latency_ms)
        if status == 404:
            return HealthResult(
                reachable=False,
                error=f"S3 bucket {self.bucket!r} not found (HTTP 404)",
                latency_ms=latency_ms,
            )
        return HealthResult(reachable=False, error=error or "unknown S3 error", latency_ms=latency_ms)

    async def available_space(self) -> int:
        # B2/Wasabi/MinIO report no usable free-space figure through the S3
        # API and are effectively unlimited; return a large sentinel so the
        # upload planner treats this backend as always eligible.
        return _UNLIMITED_SPACE_SENTINEL
