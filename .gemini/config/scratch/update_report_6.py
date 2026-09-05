import os
from pathlib import Path

report_md_path = Path(r"C:\Users\Anand\.gemini\antigravity-ide\brain\f6135499-d349-4e87-bf11-5c681b577d96\codebase_audit_report.md")

with open(report_md_path, "r", encoding="utf-8") as f:
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
        "id": "GD-AUDIT-58",
        "title": "Widespread Database Ledger Bypass: Unprotected Updates to Ledger-Tracked Tables",
        "category": "Cryptographic Security / Data Integrity",
        "severity": "Critical",
        "files": "[db.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/database/db.py)"
    },
    {
        "id": "GD-AUDIT-59",
        "title": "Hardcoded Sub-Block Index 0 in Background Healer Causes Multi-Sub-Block Chunk Corruption",
        "category": "Data Integrity / Background Healing",
        "severity": "Critical",
        "files": "[healing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/healing.py)"
    },
    {
        "id": "GD-AUDIT-60",
        "title": "Tor Onion Routing is Completely Non-Functional in sharing.py due to Hex Public Key Mapping",
        "category": "Cryptographic Security / Architecture",
        "severity": "High",
        "files": "[sharing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/sharing.py)"
    },
    {
        "id": "GD-AUDIT-61",
        "title": "In-Memory Concatenation and Buffering in verify_chunk_location Violates Zero-Copy Streaming Constraint",
        "category": "Performance / Memory Safety",
        "severity": "High",
        "files": "[healing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/healing.py)"
    },
    {
        "id": "GD-AUDIT-62",
        "title": "Discord Client Cache Failure on Upload leading to False Connection Errors",
        "category": "Usability / Reliability",
        "severity": "High",
        "files": "[discord_backend.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/backends/discord_backend.py)"
    },
    {
        "id": "GD-AUDIT-63",
        "title": "Spec Violation: Non-UUID Primary Key in sharing_audit_log Table",
        "category": "Spec Compliance",
        "severity": "Medium-Low",
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
### GD-AUDIT-58: Widespread Database Ledger Bypass: Unprotected Updates to Ledger-Tracked Tables
* **Severity**: **Critical**
* **Category**: Cryptographic Security / Data Integrity
* **Files**: [db.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/database/db.py)

#### Description
GhostDrive's core security model is built upon a cryptographically chained HMAC ledger (`hmac_ledger`). Spec §4.4 requires all writes to ledger-tracked tables (`files`, `chunks`, `chunk_locations`, etc.) to be chained using HMAC-SHA512 and to increment the Lamport clock atomically. This ensures that any modification to the database file by an attacker or a malicious local process breaks the chain and is immediately detected during audits or startup synchronization.

However, a manual codebase audit of [db.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/database/db.py) revealed multiple critical write operations on ledger-tracked tables that completely bypass both the HMAC chain generation and the Lamport clock increment:
1. **Thumbnail Updates**: `update_file_thumbnail()` updates the `thumbnail_blob` column in the `files` table directly via a raw SQL `UPDATE` query. It does not call `_chain_hmac()` nor does it increment the logical clock.
2. **Reference Count Modifications**: `increment_ref_count()` and `decrement_ref_count()` update the `ref_count` column of the `chunks` table directly without advancing the Lamport clock or writing a new link to the HMAC ledger.
3. **Chunk Re-association**: In `delete_file()`, when a chunk is shared and its ref_count is greater than 0, the chunk is re-associated with another active file by updating the `file_id` column of the `chunks` table. This write bypasses the HMAC ledger and the clock entirely.
4. **Version Linking Updates**: In `delete_file()`, the parent-version relationships are preserved by updating the `version_of` column of the `files` table for any child versions. This database write is performed without any ledger chaining or clock increments.

#### Impact
1. **Cryptographic Tamper-Evidence Defeat**: Because these database writes do not update the HMAC chain tip, an attacker with local database access can freely modify file thumbnails, hijack chunk file associations, alter reference counts, or rewrite version history trees, and the ledger audit will still report that the database is fully authentic. If a real row-level verification is eventually run, it will fail due to the unchained updates, leading to false corruption alerts.
2. **Lamport Clock Synchronization Failure**: Because these writes do not advance the Lamport clock, other clients synchronizing with the cloud backend will completely miss these updates (e.g. they will not see thumbnail changes or version restructuring), leading to silent split-brain database states and eventual metadata corruption.

#### Recommendation
Refactor `update_file_thumbnail()`, `increment_ref_count()`, `decrement_ref_count()`, and the chunk/version updates in `delete_file()` to:
1. Call `self._increment_clock()` atomically inside their transaction contexts.
2. Invoke `self._chain_hmac()` immediately after the update to record the modification details in the cryptographic chain ledger, ensuring complete security coverage.

---

### GD-AUDIT-59: Hardcoded Sub-Block Index 0 in Background Healer Causes Multi-Sub-Block Chunk Corruption
* **Severity**: **Critical**
* **Category**: Data Integrity / Background Healing
* **Files**: [healing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/healing.py)

#### Description
In [healing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/healing.py), the background `HealingQueue` monitors under-replicated chunks and executes trickle-healing by downloading them from a healthy source backend and uploading them to a target backend. 

However, the `_heal_chunk_record()` method contains a catastrophic logical error: it completely hardcodes `sub_block_index = 0` when registering the pending intent in the database and when executing the upload to the target backend:
```python
        with self.db.transaction():
            ...
            self.db._conn.execute(
                \"\"\"INSERT INTO chunk_locations
                   (chunk_id, sub_block_index, backend_id, reference_id, url_type,
                    upload_date, status, quota_reserved)
                   VALUES (?, 0, ?, '', 'permanent', ?, 'pending', ?)\"\"\",
                (chunk_id, target_id, _now_iso(), size)
            )
        ...
        ref_id = await target_obj.upload(
            stream=_stream_data(),
            chunk_id=chunk_id,
            sub_block_index=0
        )
```

#### Impact
When the background healer processes a multi-sub-block chunk (such as a 150 MB chunk on Telegram composed of three 50 MB sub-blocks), it heals each missing sub-block location independently. However, regardless of whether the source location being healed is sub-block index 1 or 2, the healer will always write and upload it as `sub_block_index = 0`. This causes two severe failures:
1. **Destructive Overwriting**: The newly healed sub-block will overwrite the target backend's actual sub-block 0, permanently destroying the first 50 MB of the chunk.
2. **Unrestorable Files**: The subsequent sub-block indexes (1, 2, etc.) are never written to the target backend, leaving the healed mirror completely corrupted and unrestorable. The recipient's download pipeline will fail with decryption/authentication errors due to the misaligned, duplicated, or missing sub-blocks.

#### Recommendation
Refactor `_heal_chunk_record()` to accept the active `sub_block_index` from the source location record. Replace the hardcoded `0` values in the SQL `INSERT` query and the `backend.upload()` call with the resolved `sub_block_index` parameter, ensuring that the healed sub-block is written to the correct logical position.

---

### GD-AUDIT-60: Tor Onion Routing is Completely Non-Functional in sharing.py due to Hex Public Key Mapping
* **Severity**: **High**
* **Category**: Cryptographic Security / Architecture
* **Files**: [sharing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/sharing.py)

#### Description
GhostDrive's P2P sharing engine in [sharing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/sharing.py) is designed to transmit share packages and file chunks securely using Tor Onion hidden services to protect user metadata and location privacy. 

When establishing a connection, `transmit_share()` attempts to retrieve the recipient's Tor onion address from their contact record:
```python
        onion_address = contact.get("public_key") # in this architecture, we map hidden onion address to public_key for routing
        if not onion_address or not onion_address.endswith(".onion"):
            # Fallback/mock if contact doesn't have a valid onion address yet
            onion_address = "mock-recipient-address.onion"
```
It then attempts to tunnel the connection through a local Tor SOCKS5 proxy:
```python
        try:
            reader, writer = await self.open_socks5_connection(onion_address, 80)
```

#### Impact
This implementation is fundamentally broken and renders Tor onion routing entirely non-functional:
1. **Type Mismatch**: The `public_key` column in the `contacts` table stores the contact's hex-encoded ML-KEM-768 public key (which is a standard hex string). It will NEVER end in `.onion`.
2. **Permanent Loopback Fallback**: Because the public key is not a `.onion` address, the engine *always* falls back to the hardcoded string `"mock-recipient-address.onion"`.
3. **Connection Failure**: Tunneling a connection to `"mock-recipient-address.onion"` through the SOCKS5 proxy will always fail because it is not a registered onion service. The engine then falls back to a loopback connection on `127.0.0.1:8888` (connecting to itself) or fails entirely. As a result, P2P sharing never actually occurs over Tor hidden services.

#### Recommendation
1. Decouple the Tor onion address from the ML-KEM-768 public key. Add a dedicated `onion_address` column to the `contacts` table schema.
2. Modify the GUI and contact exchange wizards to collect and store the contact's actual `.onion` address during contact pairing, and use this column in `transmit_share()` to establish Tor connections.

---

### GD-AUDIT-61: In-Memory Concatenation and Buffering in verify_chunk_location Violates Zero-Copy Streaming Constraint
* **Severity**: **High**
* **Category**: Performance / Memory Safety
* **Files**: [healing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/healing.py)

#### Description
Spec §5.1 mandates a strict **Zero-Copy Streaming** constraint: the application must process file data in small 64 KB blocks to avoid buffering large files in RAM, preventing Out-Of-Memory (OOM) crashes on low-resource hardware.

However, the integrity verification functions in [healing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/healing.py) (`verify_chunk_location()` and `_heal_chunk_record()`) completely violate this constraint. During verification, they download all ciphertext blocks from the backend, append them to a list, and join them into a single giant in-memory byte string:
```python
        blocks = []
        async for block in backend_obj.download(loc["reference_id"]):
            if block:
                blocks.append(block)
        ...
        all_ct = b"".join(blocks)
```
This combined byte string is then fed entirely to the `ChunkDecryptor` MAC engine.

#### Impact
When verifying or healing large sub-blocks (up to 50 MB each), concatenating the downloaded blocks in memory forces the application to allocate a contiguous 50 MB buffer in RAM, alongside the overhead of intermediate lists and Python's garbage collection copies. On systems running concurrent health sweeps or healing tasks, this buffering causes massive RAM spikes and significantly increases the risk of OOM crashes, violating the core zero-copy architecture.

#### Recommendation
Refactor the verification and healing functions to stream the downloaded blocks directly into the `ChunkDecryptor` as they are received. To extract the trailing 16-byte Poly1305 tag without buffering the whole stream, maintain a small 16-byte ring buffer (sliding window) of the last received bytes. Feed all bytes preceding this window directly to `decryptor.feed()`, and use the final 16 bytes in the window as the expected tag once the download finishes.

---

### GD-AUDIT-62: Discord Client Cache Failure on Upload leading to False Connection Errors
* **Severity**: **High**
* **Category**: Usability / Reliability
* **Files**: [discord_backend.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/backends/discord_backend.py)

#### Description
In [discord_backend.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/backends/discord_backend.py), the `upload()` method retrieves the target Discord channel object using the client's internal cache:
```python
        channel = self._client.get_channel(self._channel_id)
        if channel is None:
            raise BackendConnectionError(
                f"Discord channel {self._channel_id} not found. "
                "Check CHANNEL_ID and bot permissions."
            )
```

#### Impact
This is a severe reliability hazard. In the `discord.py` library, `get_channel()` only retrieves channels that are currently cached in the bot's memory. If the bot has just logged in, or if it is connected to a large number of guilds, the target channel may not be present in the local cache yet. In this case, `get_channel()` returns `None`, and the upload immediately fails with a `BackendConnectionError`, even if the bot has full administrative access to the channel.

#### Recommendation
Modify the channel resolution logic to fall back to an asynchronous API call if the channel is not in the cache:
```python
        channel = self._client.get_channel(self._channel_id)
        if channel is None:
            try:
                channel = await self._client.fetch_channel(self._channel_id)
            except Exception as exc:
                raise BackendConnectionError(
                    f"Discord channel {self._channel_id} not found on server: {exc}"
                )
```

---

### GD-AUDIT-63: Spec Violation: Non-UUID Primary Key in sharing_audit_log Table
* **Severity**: **Medium-Low**
* **Category**: Spec Compliance
* **Files**: [sharing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/sharing.py)

#### Description
Spec §8.2 explicitly mandates that all primary keys across all GhostDrive database tables must be UUIDv4 text strings to ensure global uniqueness and prevent sequential integer guessing attacks.

However, in [sharing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/sharing.py), the incoming P2P share package handler logs events to the `sharing_audit_log` table using the event loop time converted to a string as the primary key:
```python
                        # Add to sharing audit log
                        self.db._conn.execute(
                            "INSERT OR IGNORE INTO sharing_audit_log (id, share_id, event_type, timestamp, hmac_chain) "
                            "VALUES (?, ?, 'share_created', ?, 'mock-hmac')",
                            (str(asyncio.get_event_loop().time()), share_id, datetime.now(timezone.utc).isoformat())
                        )
```

#### Impact
This is a direct violation of the database specification. Using the event loop time string (`str(asyncio.get_event_loop().time())`) as a primary key introduces a severe risk of primary key collisions if multiple sharing events are logged concurrently or within the same event loop tick. If a collision occurs, the database write is ignored (`INSERT OR IGNORE`), leaving critical audit events unrecorded.

#### Recommendation
Replace the event loop time string with a standard UUIDv4 generator call:
```python
                        import uuid
                        log_id = str(uuid.uuid4())
                        self.db._conn.execute(
                            "INSERT OR IGNORE INTO sharing_audit_log (id, share_id, event_type, timestamp, hmac_chain) "
                            "VALUES (?, ?, 'share_created', ?, 'mock-hmac')",
                            (log_id, share_id, datetime.now(timezone.utc).isoformat())
                        )
```

---
"""

full_text = "\n".join(new_lines)
target_header = "## Conclusion and Next Steps"

if target_header in full_text:
    parts = full_text.split(target_header)
    updated_text = parts[0] + detailed_descriptions + "\n" + target_header + parts[1]
else:
    updated_text = full_text + detailed_descriptions

# Update all finding counts from 57 to 63
updated_text = updated_text.replace("57 distinct findings", "63 distinct findings")
updated_text = updated_text.replace("57-point", "63-point")
updated_text = updated_text.replace("Addressing these 57 findings", "Addressing these 63 findings")

with open(report_md_path, "w", encoding="utf-8") as f:
    f.write(updated_text)

print("Report updated successfully with 6 new findings (total 63).")
