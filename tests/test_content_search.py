"""
test_content_search.py -- Client-side content search (decrypt-at-query-time).

Covers the successor to the deleted plaintext-FTS module: file texts are
decrypted per query into a bounded, wipeable in-memory cache — never an
index on disk.  Tests: phrase match with snippet + exact result shape, cache
reuse (from_cache) and clear_search_cache(), binary (NUL) skip, per-call
max_file_bytes truncation, empty query (ValueError at service level, 400 at
the route), locked vault (RuntimeError -> route 401), and tombstoned files
excluded from candidates.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ghostdrive.services import content_search as search_service
from ghostdrive.web.state import state

PASSPHRASE = "correct horse battery staple"

RESULT_KEYS = {
    "file_id", "name", "path", "size", "mime_type", "truncated", "snippets",
}
RESPONSE_KEYS = {
    "query", "results", "scanned", "matched", "truncated_files",
    "duration_ms", "from_cache",
}


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def client(tmp_path):
    """Fresh unlocked vault + a local app with auth/files/search routers."""
    state.clean_shutdown()
    state.app_data_dir = tmp_path
    state.keystore_path = tmp_path / "keystore.json"
    state.db_path = tmp_path / "ghostdrive.db"

    from ghostdrive.web.routes.auth import router as auth_router
    from ghostdrive.web.routes.files import router as files_router
    from ghostdrive.web.routes.search import router as search_router

    app = FastAPI()
    app.include_router(auth_router)
    app.include_router(files_router)
    app.include_router(search_router)

    client = TestClient(app)
    res = client.post("/api/auth/setup", json={"passphrase": PASSPHRASE})
    assert res.status_code == 200, res.text

    yield client

    state.clean_shutdown()


@pytest.fixture(autouse=True)
def isolated_cache():
    """Every test starts (and ends) with an empty plaintext cache."""
    search_service.clear_search_cache()
    yield
    search_service.clear_search_cache()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _seed(client, payload: bytes, name: str) -> str:
    res = client.post(
        "/api/files/upload",
        files={"file": (name, payload, "text/plain")},
        data={"tier": "DISPOSABLE", "destination_path": "/"},
    )
    assert res.status_code == 200, res.text
    return res.json()["file_id"]


def _search(client, query: str, **extra) -> dict:
    res = client.post("/api/search/content", json={"query": query, **extra})
    assert res.status_code == 200, res.text
    return res.json()


def _service_search(query: str, **kwargs) -> dict:
    return asyncio.run(search_service.search_content(query, **kwargs))


# ── Matching ─────────────────────────────────────────────────────────────────

def test_content_search_finds_only_matching_file_with_snippet(client):
    notes = _seed(
        client,
        b"The vault rot13 mystery widget is documented here.",
        "notes.txt",
    )
    other = _seed(
        client,
        b"Unrelated content with entirely different words.",
        "other.txt",
    )

    body = _search(client, "rot13 mystery")
    assert set(body.keys()) == RESPONSE_KEYS
    assert body["query"] == "rot13 mystery"
    assert body["scanned"] == 2
    assert body["matched"] == 1
    assert body["truncated_files"] == 0
    assert body["from_cache"] == 0
    assert isinstance(body["duration_ms"], int)

    (result,) = body["results"]
    assert set(result.keys()) == RESULT_KEYS
    assert result["file_id"] == notes
    assert result["name"] == "notes.txt"
    assert result["truncated"] is False
    assert result["size"] == len(b"The vault rot13 mystery widget is documented here.")
    assert any("rot13 mystery" in s for s in result["snippets"])
    assert other not in [r["file_id"] for r in body["results"]]

    # AND semantics: both tokens required, so a token nobody contains misses.
    assert _search(client, "rot13 nonexistenttoken")["matched"] == 0


def test_tombstoned_file_excluded_from_search(client):
    keep = _seed(client, b"needleword stays in the vault", "keep.txt")
    gone = _seed(client, b"needleword leaves the vault", "gone.txt")

    res = client.request(
        "DELETE", "/api/files/delete", json={"file_id": gone}
    )
    assert res.status_code == 200, res.text

    body = _search(client, "needleword")
    assert [r["file_id"] for r in body["results"]] == [keep]
    assert body["scanned"] == 1  # tombstoned rows never become candidates


# ── Cache lifecycle ──────────────────────────────────────────────────────────

def test_second_query_from_cache_and_clear_empties(client):
    _seed(client, b"needleword one", "a.txt")
    _seed(client, b"needleword two", "b.txt")

    first = _search(client, "needleword")
    assert first["from_cache"] == 0

    # Identical second query reuses both decrypted texts.
    second = _search(client, "needleword")
    assert second["from_cache"] >= 1
    assert second["from_cache"] == second["scanned"]
    assert second["matched"] == 2
    assert {r["file_id"] for r in second["results"]} == {
        r["file_id"] for r in first["results"]
    }

    stats = client.get("/api/search/content/cache").json()
    assert stats["cached_files"] == 2
    assert stats["cached_bytes"] > 0

    assert search_service.clear_search_cache() == {"cleared": 2}
    assert client.get("/api/search/content/cache").json() == {
        "cached_files": 0, "cached_bytes": 0,
    }
    # Empty cache: the next query decrypts again, and matches the same files.
    third = _search(client, "needleword")
    assert third["from_cache"] == 0
    assert third["matched"] == 2


# ── Binary + truncation ──────────────────────────────────────────────────────

def test_binary_file_with_nul_bytes_is_skipped(client):
    blob_id = _seed(
        client, b"\x00\x01\x02junk" + bytes(range(256)), "image.bin"
    )
    text_id = _seed(client, b"text with needleword inside", "text.txt")

    body = _search(client, "needleword")
    ids = [r["file_id"] for r in body["results"]]
    assert ids == [text_id]
    assert blob_id not in ids
    # The binary was scanned but never cached as text.
    assert client.get("/api/search/content/cache").json()["cached_files"] == 1


def test_max_file_bytes_truncation_marks_truncated(client):
    payload = b"needleword at the start " + b"filler text " * 600  # ~7 KB
    _seed(client, payload, "big.txt")

    body = _service_search("needleword", max_file_bytes=1000)
    (result,) = body["results"]
    assert result["truncated"] is True
    assert body["truncated_files"] == 1
    # Truncated reads are NOT cached (partial text would poison later queries).
    assert search_service.search_cache_stats() == {
        "cached_files": 0, "cached_bytes": 0,
    }


# ── Errors ───────────────────────────────────────────────────────────────────

def test_empty_query_value_error_service_400_route(client):
    with pytest.raises(ValueError):
        _service_search("")
    with pytest.raises(ValueError):
        _service_search("   ---   ")

    res = client.post("/api/search/content", json={"query": "   "})
    assert res.status_code == 400


def test_locked_vault_raises_runtime_error(client):
    _seed(client, b"needleword data", "note.txt")
    state.clean_shutdown()  # locks the vault (closes db, zeroes keys)

    with pytest.raises(RuntimeError, match="locked"):
        _service_search("needleword")
