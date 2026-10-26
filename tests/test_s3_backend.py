"""
tests/test_s3_backend.py -- Unit tests for S3Backend (hermetic, no network).

Spins up a minimal in-process S3-compatible stub with stdlib
http.server.ThreadingHTTPServer and points S3Backend at it over loopback.
The stub stores objects in a dict and only checks that an Authorization
header is present -- it does not validate SigV4 signatures server-side
beyond that (correctness of the signing chain is covered by the AWS
documented test vector below).
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import unquote, urlsplit

import pytest

from ghostdrive.backends.s3_backend import S3Backend
from ghostdrive.exceptions import (
    BackendAuthError,
    BackendConnectionError,
    BackendNotFoundError,
)


# ─── Minimal in-process S3 stub (stdlib only) ────────────────────────────────

class _StubHandler(BaseHTTPRequestHandler):
    """Implements HEAD /{bucket}, PUT|GET|DELETE /{bucket}/{key} on a dict store.

    Magic switch: set ``server.stub.fail_all = True`` and every request
    answers 500, which is how the unhealthy-health-check test works.
    """

    protocol_version = "HTTP/1.1"  # keep-alive: every response needs Content-Length

    def log_message(self, fmt, *args):  # keep pytest output clean
        pass

    @property
    def stub(self) -> SimpleNamespace:
        return self.server.stub  # type: ignore[attr-defined]

    def _parts(self) -> tuple[str, str]:
        raw = urlsplit(self.path)
        segments = raw.path.lstrip("/").split("/", 1)
        bucket = segments[0]
        key = unquote(segments[1]) if len(segments) > 1 else ""
        return bucket, key

    def _respond(self, status: int, body: bytes = b"") -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _authorized(self) -> bool:
        # Do NOT validate the signature; just require a SigV4 Authorization.
        return self.headers.get("Authorization", "").startswith("AWS4-HMAC-SHA256 ")

    def do_HEAD(self):  # noqa: N802 (http.server naming)
        if self.stub.fail_all:
            self._respond(500)
            return
        if not self._authorized():
            self._respond(403)
            return
        bucket, _ = self._parts()
        self.stub.last_authorization = self.headers.get("Authorization", "")
        self._respond(200 if bucket in self.stub.buckets else 404)

    def do_PUT(self):  # noqa: N802
        if self.stub.fail_all or not self._authorized():
            self._respond(500 if self.stub.fail_all else 403)
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        bucket, key = self._parts()
        if not key or bucket not in self.stub.buckets:
            self._respond(404)
            return
        self.stub.objects[key] = body
        self._respond(200)

    def do_GET(self):  # noqa: N802
        if self.stub.fail_all or not self._authorized():
            self._respond(500 if self.stub.fail_all else 403)
            return
        _, key = self._parts()
        if key in self.stub.objects:
            self._respond(200, self.stub.objects[key])
        else:
            self._respond(404)

    def do_DELETE(self):  # noqa: N802
        if self.stub.fail_all or not self._authorized():
            self._respond(500 if self.stub.fail_all else 403)
            return
        _, key = self._parts()
        self.stub.objects.pop(key, None)
        self._respond(204)


@pytest.fixture
def s3_stub():
    """Yield (stub_state, port) with a ThreadingHTTPServer running in a daemon thread."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
    server.stub = SimpleNamespace(  # type: ignore[attr-defined]
        objects={},
        buckets={"testbucket"},
        fail_all=False,
        last_authorization="",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.stub, server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _make_backend(port: int, **overrides) -> S3Backend:
    kwargs = dict(
        endpoint_url=f"http://127.0.0.1:{port}",
        region="us-east-1",
        bucket="testbucket",
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        path_style=True,
        prefix="ghostdrive/",
    )
    kwargs.update(overrides)
    return S3Backend(**kwargs)


async def _stream(data: bytes, split: int = 7):
    """Async bytes generator, split like the real pipeline does."""
    for i in range(0, len(data), split):
        yield data[i : i + split]


# ─── SigV4 signing: AWS documented test vector ───────────────────────────────

def test_sign_is_hmac_sha256():
    # RFC 4231 test case 2 ("key" / "The quick brown fox jumps over the lazy dog").
    digest = S3Backend._sign(b"key", "The quick brown fox jumps over the lazy dog").hex()
    assert digest == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"


def test_authorization_header_matches_aws_documented_vector():
    """Reproduce AWS's "Example: GET Object" signature (sig-v4-header-based-auth).

    This is the documented end-to-end vector for GET /test.txt on
    examplebucket with a Range header, timestamp 20130524T000000Z.  It
    catches canonicalization bugs: header sorting, signed-header list,
    the blank line before SignedHeaders, and the credential scope.
    """
    backend = S3Backend(
        endpoint_url="https://examplebucket.s3.amazonaws.com",
        region="us-east-1",
        bucket="examplebucket",
        access_key="AKIAIOSFODNN7EXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )
    empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    header = backend._authorization_header(
        "GET",
        "/test.txt",
        {
            "host": "examplebucket.s3.amazonaws.com",
            "range": "bytes=0-9",
            "x-amz-content-sha256": empty,
            "x-amz-date": "20130524T000000Z",
        },
        payload_hash=empty,
        amz_date="20130524T000000Z",
    )
    assert header == (
        "AWS4-HMAC-SHA256 "
        "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"
        "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,"
        "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    )


def test_authorization_header_sorts_headers_regardless_of_input_order():
    """Canonical headers must be sorted alphabetically, not insertion-ordered."""
    backend = S3Backend(
        endpoint_url="https://examplebucket.s3.amazonaws.com",
        region="us-east-1",
        bucket="examplebucket",
        access_key="AKIAIOSFODNN7EXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )
    empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ordered = backend._authorization_header(
        "GET",
        "/test.txt",
        {
            "host": "examplebucket.s3.amazonaws.com",
            "range": "bytes=0-9",
            "x-amz-content-sha256": empty,
            "x-amz-date": "20130524T000000Z",
        },
        payload_hash=empty,
        amz_date="20130524T000000Z",
    )
    shuffled = backend._authorization_header(
        "GET",
        "/test.txt",
        {
            "x-amz-date": "20130524T000000Z",
            "range": "bytes=0-9",
            "host": "examplebucket.s3.amazonaws.com",
            "x-amz-content-sha256": empty,
        },
        payload_hash=empty,
        amz_date="20130524T000000Z",
    )
    assert ordered == shuffled
    assert "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date" in ordered


# ─── Capability flags / constructor ──────────────────────────────────────────

def test_capability_flags(s3_stub):
    stub, port = s3_stub
    backend = _make_backend(port)
    assert backend.is_ephemeral_url is False
    assert backend.is_cold_storage is False
    assert backend.supports_range_requests is False
    assert backend.supports_streaming is True
    assert backend.supports_deletion is True
    assert backend.tier == "IMPORTANT"


def test_constructor_validates_required_fields():
    with pytest.raises(ValueError):
        S3Backend(endpoint_url="", region="us-east-1", bucket="b", access_key="a", secret_key="s")
    with pytest.raises(ValueError):
        S3Backend(endpoint_url="https://x.example.com", region="", bucket="b", access_key="a", secret_key="s")
    with pytest.raises(ValueError):
        S3Backend(endpoint_url="https://x.example.com", region="us-east-1", bucket="", access_key="a", secret_key="s")
    with pytest.raises(ValueError):
        S3Backend(endpoint_url="https://x.example.com", region="us-east-1", bucket="b", access_key="", secret_key="s")
    # Virtual-host style against an IP endpoint cannot work (MinIO quickstart).
    with pytest.raises(ValueError):
        S3Backend(
            endpoint_url="http://127.0.0.1:9000",
            region="us-east-1",
            bucket="b",
            access_key="a",
            secret_key="s",
            path_style=False,
        )


# ─── Lifecycle against the stub ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_connect_ok(s3_stub):
    stub, port = s3_stub
    backend = _make_backend(port)
    try:
        await backend.connect()
        # The stub only answers HEAD 200 to requests carrying SigV4 auth.
        assert stub.last_authorization.startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
    finally:
        await backend.close()


@pytest.mark.asyncio
async def test_connect_missing_bucket_raises(s3_stub):
    stub, port = s3_stub
    backend = _make_backend(port, bucket="no-such-bucket")
    try:
        with pytest.raises(BackendConnectionError, match="not found"):
            await backend.connect()
    finally:
        await backend.close()


@pytest.mark.asyncio
async def test_upload_download_roundtrip(s3_stub):
    stub, port = s3_stub
    backend = _make_backend(port)
    payload = b"encrypted sub-block bytes" * 100
    try:
        await backend.connect()
        ref_id = await backend.upload(_stream(payload), "chunk-abc", 3)

        # Key layout: {prefix}{chunk_id}/{sub_block_index}
        assert ref_id == "ghostdrive/chunk-abc/3"
        assert stub.objects[ref_id] == payload

        blocks = []
        async for block in backend.download(ref_id):
            blocks.append(block)
        assert b"".join(blocks) == payload
    finally:
        await backend.close()


@pytest.mark.asyncio
async def test_download_missing_key_raises_clean_error(s3_stub):
    stub, port = s3_stub
    backend = _make_backend(port)
    try:
        await backend.connect()
        with pytest.raises(BackendNotFoundError):
            async for _ in backend.download("ghostdrive/missing/0"):
                pass
    finally:
        await backend.close()


@pytest.mark.asyncio
async def test_delete_is_idempotent(s3_stub):
    stub, port = s3_stub
    backend = _make_backend(port)
    try:
        await backend.connect()
        ref_id = await backend.upload(_stream(b"doomed"), "chunk-del", 0)
        assert await backend.delete(ref_id) is True
        assert ref_id not in stub.objects
        # Deleting again succeeds: the object is already in the desired state.
        assert await backend.delete(ref_id) is True
    finally:
        await backend.close()


@pytest.mark.asyncio
async def test_health_check_healthy_with_latency(s3_stub):
    stub, port = s3_stub
    backend = _make_backend(port)
    try:
        await backend.connect()
        health = await backend.health_check()
        assert health.reachable is True
        assert health.error is None
        assert health.latency_ms is not None and health.latency_ms > 0
    finally:
        await backend.close()


@pytest.mark.asyncio
async def test_health_check_unhealthy_on_500(s3_stub):
    stub, port = s3_stub
    backend = _make_backend(port)
    try:
        await backend.connect()
        stub.fail_all = True  # magic switch: every request answers 500
        health = await backend.health_check()
        assert health.reachable is False
        assert "500" in (health.error or "")
    finally:
        await backend.close()


@pytest.mark.asyncio
async def test_unicode_and_space_in_chunk_id_roundtrips(s3_stub):
    stub, port = s3_stub
    backend = _make_backend(port)
    payload = b"unicode payload \xf0\x9f\x94\x92"
    try:
        await backend.connect()
        ref_id = await backend.upload(_stream(payload), "sp\xe4ce ch\xfcnken id", 1)
        assert ref_id == "ghostdrive/sp\xe4ce ch\xfcnken id/1"
        # The stub unquotes the wire path, so the decoded key must round-trip.
        assert stub.objects[ref_id] == payload

        blocks = []
        async for block in backend.download(ref_id):
            blocks.append(block)
        assert b"".join(blocks) == payload

        assert await backend.delete(ref_id) is True
        assert ref_id not in stub.objects
    finally:
        await backend.close()


@pytest.mark.asyncio
async def test_prefix_is_respected(s3_stub):
    stub, port = s3_stub
    backend = _make_backend(port, prefix="backups/2026")  # no trailing slash on purpose
    try:
        await backend.connect()
        ref_id = await backend.upload(_stream(b"prefixed"), "chunk-1", 0)
        assert ref_id == "backups/2026/chunk-1/0"
        assert "backups/2026/chunk-1/0" in stub.objects
    finally:
        await backend.close()


@pytest.mark.asyncio
async def test_available_space_is_large_sentinel(s3_stub):
    stub, port = s3_stub
    backend = _make_backend(port)
    space = await backend.available_space()
    assert space == 2**60
