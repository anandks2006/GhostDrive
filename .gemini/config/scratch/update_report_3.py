import os
from pathlib import Path

report_path = Path(r"C:\Users\Anand\.gemini\antigravity-ide\brain\f6135499-d349-4e87-bf11-5c681b577d96\codebase_audit_report.md")

with open(report_path, "r", encoding="utf-8") as f:
    content = f.read()

lines = content.splitlines()

# 1. Locate the summary table
table_start_idx = -1
table_end_idx = -1
for i, line in enumerate(lines):
    if "| ID | Finding Title |" in line:
        table_start_idx = i
    elif table_start_idx != -1 and not line.startswith("|"):
        table_end_idx = i
        break

table_rows = lines[table_start_idx+2:table_end_idx]

parsed_rows = []
for row in table_rows:
    if not row.strip():
        continue
    parts = [p.strip() for p in row.split("|")[1:-1]]
    if len(parts) < 5:
        continue
    fid = parts[0].replace("**", "")
    title = parts[1]
    category = parts[2]
    sev_text = parts[3].replace("**", "")
    files = parts[4]
    parsed_rows.append({
        "id": fid,
        "title": title,
        "category": category,
        "severity": sev_text,
        "files": files
    })

# Define the new findings to add
new_findings = [
    {
        "id": "GD-AUDIT-37",
        "title": "Blocking Database Queries and Non-Atomic Writes in Startup Index Synchronization",
        "category": "Concurrency / Durability",
        "severity": "High",
        "files": "[main_view.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/main_view.py)"
    },
    {
        "id": "GD-AUDIT-38",
        "title": "Unsafe Raw Database Reads During Live Backup",
        "category": "Data Integrity / Backup",
        "severity": "High",
        "files": "[main_view.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/main_view.py)"
    },
    {
        "id": "GD-AUDIT-39",
        "title": "Insecure Last-Write-Wins Index Synchronization Overwrite Leading to Data Loss",
        "category": "Data Loss",
        "severity": "Critical",
        "files": "[main_view.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/main_view.py)"
    },
    {
        "id": "GD-AUDIT-40",
        "title": "Incomplete Log Sanitization and Secret Credential Leakage",
        "category": "Security",
        "severity": "Low/Medium",
        "files": "[log_sanitizer.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/utils/log_sanitizer.py)"
    },
    {
        "id": "GD-AUDIT-41",
        "title": "Widespread Codebase-Wide Violation of Section 9.6: Silent Exception Swallowing",
        "category": "Codebase-Wide / Reliability",
        "severity": "Medium-Low",
        "files": "[external_drive_backend.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/backends/external_drive_backend.py)<br>[nas_backend.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/backends/nas_backend.py)<br>[telegram_backend.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/backends/telegram_backend.py)<br>[credential_store.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/crypto/credential_store.py)<br>[backend_settings.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/backend_settings.py)<br>[unlock_view.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/unlock_view.py)<br>[drive_registration.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/drive_registration.py)<br>[artifact_cleaner.py (Linux/macOS)](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/platform/linux/artifact_cleaner.py)<br>[drive_monitor.py (Linux/Windows)](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/platform/linux/drive_monitor.py)<br>[screen_lock.py (Linux/macOS)](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/platform/linux/screen_lock.py)<br>[smart_monitor.py (Windows)](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/platform/windows/smart_monitor.py)"
    },
    {
        "id": "GD-AUDIT-42",
        "title": "Catastrophic Thread Safety Violation on Shared Database Connection",
        "category": "Concurrency / Thread Safety",
        "severity": "High",
        "files": "[db.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/database/db.py)<br>[file_browser.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/file_browser.py)"
    },
    {
        "id": "GD-AUDIT-43",
        "title": "Missing BLAKE3 Integrity Verification on Received P2P Chunks",
        "category": "Security / Data Integrity",
        "severity": "High",
        "files": "[sharing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/sharing.py)"
    },
    {
        "id": "GD-AUDIT-44",
        "title": "Unbounded P2P Cache Growth and Disk Space Exhaustion",
        "category": "Performance / Disk Leak",
        "severity": "Medium",
        "files": "[sharing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/sharing.py)"
    }
]

# Add to parsed rows (avoiding duplicates)
existing_ids = {r["id"] for r in parsed_rows}
for nf in new_findings:
    if nf["id"] not in existing_ids:
        parsed_rows.append(nf)

# Sort: first by severity, then by ID
def sort_key(r):
    sev = r["severity"]
    if "Critical" in sev:
        s_val = 0
    elif "High" in sev:
        s_val = 1
    elif "Medium-Low" in sev:
        s_val = 3
    elif "Medium" in sev:
        s_val = 2
    elif "Low/Medium" in sev:
        s_val = 4
    elif "Low" in sev:
        s_val = 5
    else:
        s_val = 6
    return (s_val, r["id"])

parsed_rows.sort(key=sort_key)

# Reformat rows
formatted_rows = []
for r in parsed_rows:
    sev_bold = f"**{r['severity']}**"
    row_str = f"| **{r['id']}** | {r['title']} | {r['category']} | {sev_bold} | {r['files']} |"
    formatted_rows.append(row_str)

# Replace table in lines
new_lines = lines[:table_start_idx+2] + formatted_rows + lines[table_end_idx:]
full_text = "\n".join(new_lines)

# 2. Add Detailed Descriptions before the "## Conclusion and Next Steps" section
detailed_descriptions = """
### GD-AUDIT-37: Blocking Database Queries and Non-Atomic Writes in Startup Index Synchronization
* **Severity**: **High**
* **Category**: Concurrency / Durability
* **Files**: [main_view.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/main_view.py)

#### Description
The method `sync_index_on_startup()` in `main_view.py` is invoked during application boot to synchronize local index metadata with remote storage snapshots. However, it performs multiple synchronous and blocking operations directly on the main event loop thread:
1. It queries the local Lamport clock using a synchronous SQLite transaction: `self.db._conn.execute("SELECT logical_clock FROM hmac_ledger WHERE id = 1")`.
2. For each remote backend, it downloads snapshot data, writes it to a temporary file via `tempfile.NamedTemporaryFile`, opens a new synchronous SQLite connection to the temporary file, queries its clock, and closes it.
3. If a newer remote snapshot is found, it closes the local database connection, deletes the active database file, and overwrites it using a standard blocking file write:
   ```python
   with open(db_path, "wb") as f:
       f.write(newest_snapshot_bytes)
   ```

#### Impact
1. **Event Loop Starvation**: Spawning synchronous SQLite connections and executing blocking disk writes on the main thread freezes the Qt GUI, causing the application to stop responding for several seconds on startup.
2. **Data Durability Hazard**: Overwriting the active `ghostdrive.db` file using a non-atomic write risks leaving the database in a partially written or corrupted state if the application crashes, the system loses power, or the process is terminated mid-write, resulting in total loss of local index metadata.

#### Recommendation
Wrap all database operations, tempfile writes, remote clock queries, and file updates in `asyncio.to_thread` to run them on the background thread pool. Furthermore, use the pre-built `atomic_write` utility from `ghostdrive.utils.fsync` (which writes to a temporary file, calls `fsync`, and renames the file) to replace the database file atomically.

---

### GD-AUDIT-38: Unsafe Raw Database Reads During Live Backup
* **Severity**: **High**
* **Category**: Data Integrity / Backup
* **Files**: [main_view.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/main_view.py)

#### Description
The background backup daemon in `backup_index_and_credentials()` performs a WAL checkpoint (`self.db.wal_checkpoint()`) and then reads the database file directly via standard Python file I/O:
```python
with open(db_path, "rb") as f:
    db_bytes = f.read()
```
This byte array is then encrypted and uploaded to remote backends.

#### Impact
Reading the active `ghostdrive.db` file directly via standard file I/O while the database connection remains open and active is highly unsafe. Even though a WAL checkpoint is executed beforehand, SQLite is actively writing to the database file or its WAL log on other threads/tasks. Reading the database file concurrently with active SQLite writes bypasses SQLite's internal page locking mechanisms, leading to inconsistent or corrupted database snapshots being backed up to the cloud.

#### Recommendation
Migrate the backup flow to use SQLite's Online Backup API (`sqlite3.Connection.backup` or equivalent). This safely locks the source database, copies the pages to a temporary database file in a transaction-safe manner, and ensures the backup is 100% consistent and uncorrupted, even under heavy concurrent write loads.

---

### GD-AUDIT-39: Insecure Last-Write-Wins Index Synchronization Overwrite Leading to Data Loss
* **Severity**: **Critical**
* **Category**: Data Loss
* **Files**: [main_view.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/main_view.py)

#### Description
During the startup index synchronization in `sync_index_on_startup()`, the local database's Lamport logical clock is compared against the clocks of remote database snapshots retrieved from Telegram, Discord, and NAS backends. If a remote snapshot has a higher logical clock, the local database is closed and completely overwritten by the remote database bytes:
```python
if newest_snapshot_bytes:
    self.db.close()
    with open(db_path, "wb") as f:
        f.write(newest_snapshot_bytes)
    self.db.open()
```

#### Impact
This "Last-Write-Wins" file-level overwrite strategy causes catastrophic data loss. If a user works offline and performs metadata actions (e.g., creating files, renaming directories, storing secrets), their changes are recorded locally. If they later connect to the internet, and another device has written to a remote backend (incrementing the remote logical clock higher than the local offline clock), the sync engine will completely overwrite the local database with the remote snapshot, permanently wiping out all of the user's un-synced offline local modifications.

#### Recommendation
Replace the file-level overwrite strategy with a row-level synchronization and reconciliation protocol. The sync engine should open the remote snapshot in a temporary database, compare the logical clocks and cryptographic hashes of individual rows in ledger-tracked tables, merge newer rows into the local database, and resolve conflicts based on defined merge rules, ensuring no local offline changes are lost.

---

### GD-AUDIT-40: Incomplete Log Sanitization and Secret Credential Leakage
* **Severity**: **Low/Medium**
* **Category**: Security
* **Files**: [log_sanitizer.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/utils/log_sanitizer.py)

#### Description
The `SanitizedFormatter` class in `log_sanitizer.py` uses pre-compiled regular expressions to redact credentials before writing to the log files. However, the regex targeting URL credentials:
```python
URL_CREDENTIALS_RE = re.compile(r'(?i)(://[^:]+:)[^@]+@')
```
strictly requires a colon `:` separating the username and password in the credentials section of the URI.

#### Impact
1. **Credential Leaks**: If a backend URI uses a single-token credential format without a colon (e.g., `http://api_token@host` or `sftp://private_key_blob@nas`), the regular expression fails to match, and the secret token is written in cleartext to the application logs.
2. **Lack of Generic Filtering**: The sanitizer lacks pattern matching for common JSON or key-value serialized credential formats, such as `"password": "value"`, `"secret": "value"`, or `"api_key": "value"`, which are frequently printed during network or database debugging.

#### Recommendation
Improve `URL_CREDENTIALS_RE` to match any credentials between `://` and `@` regardless of the presence of a colon: `r'(?i)(://)[^@]+@'`. Additionally, introduce generic key-value sanitization patterns to automatically redact values associated with sensitive keys like `password`, `secret`, `api_key`, and `private_key`.

---

### GD-AUDIT-41: Widespread Codebase-Wide Violation of Section 9.6: Silent Exception Swallowing
* **Severity**: **Medium-Low**
* **Category**: Codebase-Wide / Reliability
* **Files**: [external_drive_backend.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/backends/external_drive_backend.py)<br>[nas_backend.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/backends/nas_backend.py)<br>[telegram_backend.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/backends/telegram_backend.py)<br>[credential_store.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/crypto/credential_store.py)<br>[backend_settings.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/backend_settings.py)<br>[unlock_view.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/unlock_view.py)<br>[drive_registration.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/drive_registration.py)<br>[artifact_cleaner.py (Linux/macOS)](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/platform/linux/artifact_cleaner.py)<br>[drive_monitor.py (Linux/Windows)](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/platform/linux/drive_monitor.py)<br>[screen_lock.py (Linux/macOS)](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/platform/linux/screen_lock.py)<br>[smart_monitor.py (Windows)](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/platform/windows/smart_monitor.py)

#### Description
Spec §9.6 explicitly bans the silent swallowing of exceptions, stating that `"except Exception: pass"` is prohibited to ensure application reliability. However, a static analysis scan revealed dozens of instances of empty `except Exception: pass` blocks or generic exception handlers that log nothing and execute `pass` across the platform, backend, database, and GUI layers.

#### Impact
Critical operational failures (such as key storage deletion failures, SMB connection dropouts, registry cleaning errors, DBus listener crashes, and S.M.A.R.T. command execution errors) are masked and silently ignored. This makes diagnostic tracing and post-mortem debugging extremely difficult, leading to unpredictable application states and hidden failures.

#### Recommendation
Refactor all generic `except Exception: pass` blocks. Catch only specific, anticipated exceptions (e.g., `OSError`, `KeyError`, `sqlite3.Error`) and log them at an appropriate severity level (e.g., `logger.warning` or `logger.error`), ensuring full compliance with Spec §9.6.

---

### GD-AUDIT-42: Catastrophic Thread Safety Violation on Shared Database Connection
* **Severity**: **High**
* **Category**: Concurrency / Thread Safety
* **Files**: [db.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/database/db.py)<br>[file_browser.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/file_browser.py)

#### Description
To allow multi-threaded access, the database wrapper in `db.py` initializes the SQLite/SQLCipher connection with `check_same_thread=False`:
```python
self._conn = sqlite3.connect(
    str(self._path),
    check_same_thread=False,
    isolation_level=None,
)
```
However, the single connection instance `self.db._conn` is shared and accessed concurrently across the main GUI thread, background daemons (`HealthDaemon`, `HealingQueue`), and worker threads. Specifically, the drag-and-drop file export flow in `file_browser.py` spawns a dedicated OS thread (`run_async_in_thread`) that executes database queries (`self.db._conn.execute(...)`) on the shared connection concurrently with the main thread.

#### Impact
SQLite connections are fundamentally not thread-safe for concurrent query execution on a single connection. Executing SQL commands concurrently from multiple threads without external synchronization causes internal state race conditions in SQLCipher, leading to memory corruption, sudden segmentation faults, corrupted query results, or database lock errors.

#### Recommendation
1. Establish a database connection pool or require that each thread or background daemon instantiate its own dedicated `GhostDriveDB` connection, enforcing `check_same_thread=True`.
2. Alternatively, if a single connection is used, wrap all database executions in a thread-safe serialized queue or use a process/thread-level mutex lock to guarantee that only one thread can execute statements on the connection at any given time.

---

### GD-AUDIT-43: Missing BLAKE3 Integrity Verification on Received P2P Chunks
* **Severity**: **High**
* **Category**: Security / Data Integrity
* **Files**: [sharing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/sharing.py)

#### Description
In the P2P sharing receiver method `_handle_incoming_connection()` in `sharing.py`, the engine processes incoming `CMD_CHUNK_DATA` frames. The code contains a comment stating `# Verify integrity via BLAKE3`, but it immediately writes the raw payload bytes to disk without performing any hash calculation or verification:
```python
# Save chunk to local storage cache / local filesystem backend
cache_dir = Path(os.path.expanduser("~")) / ".ghostdrive" / "cache"
cache_dir.mkdir(parents=True, exist_ok=True)
chunk_path = cache_dir / chunk_id

# Verify integrity via BLAKE3
chunk_path.write_bytes(chunk_payload)
```

#### Impact
A severe data integrity and security vulnerability exists. A malicious peer or contact can transmit corrupted, tempered, or entirely arbitrary data payloads, and the client will accept them as valid chunks and write them directly into the cache. This bypasses the zero-knowledge security guarantees and can lead to corrupted file restores or cache poisoning.

#### Recommendation
Implement BLAKE3 hash verification on the received `chunk_payload`. Calculate its BLAKE3 hash and verify it against the expected hash in the shared metadata package prior to writing the bytes to disk. Reject the transfer and raise an error if the hashes do not match.

---

### GD-AUDIT-44: Unbounded P2P Cache Growth and Disk Space Exhaustion
* **Severity**: **Medium**
* **Category**: Performance / Disk Leak
* **Files**: [sharing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/sharing.py)

#### Description
When receiving shared files via the P2P engine, incoming chunk payloads are saved to a local cache directory in the user's home folder: `~/.ghostdrive/cache`. However, there is no code in `sharing.py` or the background daemons that monitors, limits, or prunes this cache directory.

#### Impact
As files are shared, chunks accumulate in the cache directory indefinitely. This unbounded disk consumption acts as a silent disk leak, eventually causing physical disk space exhaustion, slowing down system performance, and potentially crashing the OS or application.

#### Recommendation
Implement an automatic cache eviction mechanism. Define a maximum size limit for the P2P cache (e.g., 5 GB) and run a background pruning task (such as Least Recently Used (LRU) eviction) that deletes older cached chunks when the limit is exceeded.

---
"""

# Update GD-AUDIT-33 details to explain the ChaCha20 stream offset issue as well
old_audit_33_desc = """Both `HealthDaemon` (`verify_chunk_location()`) and `HealingQueue` (`_heal_chunk_record()`) verify chunk integrity by downloading a single sub-block location and checking its Poly1305 MAC tag.

However, a single Poly1305 MAC tag is only computed and appended at the very end of the *final* block of the entire chunk stream (i.e. at the end of the last sub-block). For chunks larger than 50 MB (multi-sub-block), non-final sub-blocks (like sub-block 0 of a 150 MB chunk) do not contain the Poly1305 tag.

Both `verify_chunk_location()` and `_heal_chunk_record()` query and download individual sub-blocks. When processing a non-final sub-block, the code extracts the last 16 bytes of that sub-block's ciphertext and treats them as the Poly1305 tag:
```python
all_ct = b"".join(blocks)
tag = all_ct[-16:]  # Falsely treats last 16 bytes of intermediate ciphertext as the tag
...
decryptor = ChunkDecryptor(key=chunk_key, nonce=nonce, expected_tag=tag)
```
This verification will ALWAYS fail with an `AuthenticationError` because the extracted bytes are random ciphertext, not the actual Poly1305 tag."""

new_audit_33_desc = """Both `HealthDaemon` (`verify_chunk_location()`) and `HealingQueue` (`_heal_chunk_record()`) verify chunk integrity by downloading a single sub-block location and checking its Poly1305 MAC tag.

However, there are two fundamental cryptographic flaws in this sub-block verification design:
1. **Poly1305 Tag Placement**: A single Poly1305 MAC tag is only computed and appended at the very end of the *final* block of the entire chunk stream (i.e. at the end of the last sub-block). For chunks larger than 50 MB (multi-sub-block), non-final sub-blocks (like sub-block 0 of a 150 MB chunk) do not contain the Poly1305 tag.
2. **ChaCha20 Stream Cipher Offset Mismatch**: Because ChaCha20 is a stream cipher, decrypting an intermediate sub-block (like sub-block 1 or 2 of a 150 MB chunk) requires either initializing the cipher and decrypting sequentially from the start of the logical chunk (sub-block 0), or seeking the cipher to the exact block counter offset corresponding to the sub-block's position. The current implementation tries to decrypt each sub-block independently from the beginning (using the base nonce counter and block counter 0), which results in complete plaintext garbage.

Both `verify_chunk_location()` and `_heal_chunk_record()` query and download individual sub-blocks. When processing a non-final sub-block, the code extracts the last 16 bytes of that sub-block's ciphertext and treats them as the Poly1305 tag:
```python
all_ct = b"".join(blocks)
tag = all_ct[-16:]  # Falsely treats last 16 bytes of intermediate ciphertext as the tag
...
decryptor = ChunkDecryptor(key=chunk_key, nonce=nonce, expected_tag=tag)
```
This verification will ALWAYS fail with an `AuthenticationError` because the extracted bytes are random ciphertext, not the actual Poly1305 tag. Even if the tag were ignored, the decryption would yield garbage due to the stream cipher offset mismatch."""

if old_audit_33_desc in full_text:
    full_text = full_text.replace(old_audit_33_desc, new_audit_33_desc)
else:
    # Try with minor formatting variation
    pass

target_header = "## Conclusion and Next Steps"

if target_header in full_text:
    parts = full_text.split(target_header)
    updated_text = parts[0] + detailed_descriptions + "\n" + target_header + parts[1]
else:
    updated_text = full_text + detailed_descriptions

# Update all finding counts from 36 to 44
updated_text = updated_text.replace("36 distinct findings", "44 distinct findings")
updated_text = updated_text.replace("36-point", "44-point")
updated_text = updated_text.replace("Addressing these 36 findings", "Addressing these 44 findings")

with open(report_path, "w", encoding="utf-8") as f:
    f.write(updated_text)

print("Report updated successfully with 8 new findings (total 44).")
