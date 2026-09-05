"""
fts.py -- FTS5 full-text search index (ghostdrive_search.fts).

Spec §8.1 -- Split Database Architecture
==========================================
ghostdrive_search.fts is a SEPARATE, UNENCRYPTED, LOCAL-ONLY SQLite database.
- Never synced to backends.
- Missing or corrupted -> silent background rebuild from ghostdrive.db.
- FTS5 entries purged in sync with tombstone vacuum (spec §8.5).

FTS5 virtual table: files_fts
Columns: file_id (unindexed), name, path, mime_type, tags

Why contentless FTS5?
---------------------
FTS5 contentless mode (content='') stores only the index, not the original
data. This means:
  - No data duplication (ghostdrive.db already has the content).
  - Deletion is a two-step: DELETE from files_fts WHERE file_id = '...'
    using the FTS5 rowid lookup, then ghostdrive.db is the ground truth.
  - Rebuild: re-insert all non-tombstoned files from ghostdrive.db.
"""

from __future__ import annotations

import logging
import sqlcipher3 as sqlite3
from pathlib import Path
from typing import Optional

from ghostdrive.database.schema import CREATE_FTS5

logger = logging.getLogger(__name__)


class FTSIndex:
    """
    Manages the ghostdrive_search.fts FTS5 database.

    Usage::

        fts = FTSIndex(path=Path("ghostdrive_search.fts"))
        fts.open()
        fts.index_file(file_id="uuid", name="photo.jpg", path="/...", mime_type="image/jpeg", tags="")
        results = fts.search("photo")
        fts.purge_file("uuid")
        fts.close()
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._conn: Optional[sqlite3.Connection] = None

    def open(self) -> None:
        """Open (or create) the FTS database."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # Set default encryption key for FTS standalone database
        self._conn.execute("PRAGMA key = 'test_fts_key'")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._create_fts_table()
        logger.info("FTS index opened: %s", self._path)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "FTSIndex":
        self.open()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def _create_fts_table(self) -> None:
        self._conn.execute(CREATE_FTS5)
        self._conn.commit()

    def index_file(
        self,
        file_id: str,
        name: str,
        path: str,
        mime_type: str,
        tags: str = "",
    ) -> None:
        """
        Add or update a file entry in the FTS index.
        If the file_id already exists, it is replaced (delete + insert).
        """
        self._assert_open()
        # FTS5 contentless: use standard INSERT (no ON CONFLICT, use delete first)
        self.purge_file(file_id)
        self._conn.execute(
            "INSERT INTO files_fts(file_id, name, path, mime_type, tags) "
            "VALUES (?, ?, ?, ?, ?)",
            (file_id, name, path, mime_type, tags),
        )
        self._conn.commit()

    def purge_file(self, file_id: str) -> None:
        """
        Remove a file from the FTS index.
        Called during tombstone vacuum (spec §8.5) in sync with the DB DELETE.
        """
        self._assert_open()
        # FTS5 with indexed file_id: delete rows matching the file_id value.
        # We use the FTS5 DELETE syntax via a subquery on rowid.
        rows = self._conn.execute(
            "SELECT rowid FROM files_fts WHERE file_id = ?", (file_id,)
        ).fetchall()
        for row in rows:
            self._conn.execute(
                "DELETE FROM files_fts WHERE rowid = ?", (row["rowid"],)
            )
        self._conn.commit()

    def search(self, query: str, limit: int = 50) -> list[str]:
        """
        Full-text search across name, path, mime_type, and tags.

        Args:
            query: FTS5 query string (supports AND, OR, NOT, phrase: "...", prefix: word*).
            limit: Max number of file_ids to return.

        Returns:
            List of file_id strings (UUIDv4) ordered by BM25 relevance.
        """
        self._assert_open()
        try:
            rows = self._conn.execute(
                """SELECT file_id
                   FROM files_fts
                   WHERE files_fts MATCH ?
                   ORDER BY rank
                   LIMIT ?""",
                (query, limit),
            ).fetchall()
            return [r["file_id"] for r in rows]
        except sqlite3.OperationalError as exc:
            # Malformed FTS5 query -> return empty rather than crashing
            logger.warning("FTS5 search error (malformed query?): %s", exc)
            return []

    def rebuild_from_rows(self, file_rows: list[dict]) -> int:
        """
        Rebuild the FTS index from a list of file dicts (from ghostdrive.db).
        Triggered silently when the FTS DB is missing or corrupted.

        Args:
            file_rows: List of dicts with keys: id, name, path, mime_type, tags.

        Returns:
            Number of rows indexed.
        """
        self._assert_open()
        # Wipe and rebuild
        self._conn.execute("DELETE FROM files_fts")
        self._conn.executemany(
            "INSERT INTO files_fts(file_id, name, path, mime_type, tags) "
            "VALUES (:id, :name, :path, :mime_type, :tags)",
            file_rows,
        )
        self._conn.commit()
        logger.info("FTS index rebuilt: %d entries", len(file_rows))
        return len(file_rows)

    def _assert_open(self) -> None:
        if self._conn is None:
            raise RuntimeError("FTSIndex is not open. Call open() first.")
