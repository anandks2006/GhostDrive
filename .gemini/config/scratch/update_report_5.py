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
        "id": "GD-AUDIT-53",
        "title": "Completely Broken P2P Handshake Lacks Cryptographic Proof of Identity (Trivial Impersonation)",
        "category": "Cryptographic Security / P2P Authentication",
        "severity": "Critical",
        "files": "[sharing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/sharing.py)"
    },
    {
        "id": "GD-AUDIT-54",
        "title": "Dead Code and False Security Claims: CLI Session-Key Isolation Bypassed in Ingestion Pipeline",
        "category": "Security / Cryptography",
        "severity": "High",
        "files": "[hkdf.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/crypto/hkdf.py)<br>[upload.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/upload.py)"
    },
    {
        "id": "GD-AUDIT-55",
        "title": "Completely Faked HMAC Chain Verification (Zero Replay Checks)",
        "category": "Cryptographic Security / Data Integrity",
        "severity": "Critical",
        "files": "[db.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/database/db.py)"
    },
    {
        "id": "GD-AUDIT-56",
        "title": "Complete Violation of Section 5.1: Entire Decrypted File Buffered in RAM on Download (OOM Risk)",
        "category": "Performance / Memory",
        "severity": "High",
        "files": "[file_browser.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/file_browser.py)"
    },
    {
        "id": "GD-AUDIT-57",
        "title": "Flawed Pre-Flight Database Write Check on Wrong Directory Blocks App Launch for Installed Builds",
        "category": "Usability / Platform Integration",
        "severity": "High",
        "files": "[preflight_wizard.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/preflight_wizard.py)"
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
### GD-AUDIT-53: Completely Broken P2P Handshake Lacks Cryptographic Proof of Identity (Trivial Impersonation)
* **Severity**: **Critical**
* **Category**: Cryptographic Security / P2P Authentication
* **Files**: [sharing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/sharing.py)

#### Description
The P2P sharing receiver in `sharing.py` listens for incoming connections and processes a `CMD_HANDSHAKE` command. During this handshake, the connecting sender simply provides their public key fingerprint:
```python
if cmd == CMD_HANDSHAKE:
    fingerprint = data.get("fingerprint")
    # Verify contact in DB
    with self.db.transaction():
        contact = self.db._conn.execute(
            "SELECT * FROM contacts WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
```
If the fingerprint exists in the recipient's `contacts` database, the connection is accepted, and `verified_contact` is set.

#### Impact
This handshake mechanism lacks any cryptographic challenge-response, key exchange, or digital signature verification. There is no proof that the connecting client actually possesses the private key corresponding to the provided fingerprint (which is public or easily obtained). An attacker can trivially connect to the client's P2P port, claim the fingerprint of one of the user's trusted contacts, and immediately gain authenticated access. This allows the attacker to inject malicious share packages and write arbitrary files/chunks directly into the victim's local cache.

#### Recommendation
Implement a cryptographically secure challenge-response protocol during the handshake:
1. When a client connects and sends their fingerprint, the receiver must generate a cryptographically secure random challenge (nonce).
2. The client must sign this challenge using their private key and return the signature.
3. The receiver must verify the signature against the registered contact's public key (e.g., using Ed25519 or ML-KEM-768/dilithium) before accepting the connection.

---

### GD-AUDIT-54: Dead Code and False Security Claims: CLI Session-Key Isolation Bypassed in Ingestion Pipeline
* **Severity**: **High**
* **Category**: Security / Cryptography
* **Files**: [hkdf.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/crypto/hkdf.py)<br>[upload.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/upload.py)

#### Description
The codebase defines a `derive_cli_session_key()` helper in `hkdf.py` and documents that CLI sessions use a time-limited session-specific key to isolate data uploads, ensuring that if a session key is compromised, other session data remains secure. 

However, the actual chunk upload pipeline in `upload.py` completely bypasses this logic. The `ChunkUploader` encrypts all chunks using a static, master-key-derived chunk key:
```python
chunk_key = derive_chunk_key(self._mk, self._salt)
```
which maps directly to the global purpose constant `INFO_CHUNK_ENCRYPTION = b"ghostdrive-v1-chunk-encryption"`. The CLI session key is never passed, utilized, or integrated into the encryption stream.

#### Impact
The session-key isolation framework is dead code. Chunks are encrypted with a single static key tied directly to the master key. A compromise of any session key or the master key exposes all uploaded chunks across all sessions, rendering the session-isolation and forward-secrecy claims in the documentation completely false.

#### Recommendation
Integrate the session-key derivation into the chunk encryption pipeline so that chunk keys are dynamically derived from the active session-scoped key. Alternatively, remove the misleading documentation and dead code to align the system design with the actual single-key encryption model.

---

### GD-AUDIT-55: Completely Faked HMAC Chain Verification (Zero Replay Checks)
* **Severity**: **Critical**
* **Category**: Cryptographic Security / Data Integrity
* **Files**: [db.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/database/db.py)

#### Description
GhostDrive's core database integrity mechanism is a tamper-evident HMAC chained ledger. Every write to ledger-tracked tables is chained to the previous tip using HMAC-SHA512. The `verify_hmac_chain()` method in `db.py` is documented as the function that audits the database integrity. 

However, this method is a complete mock stub:
```python
def verify_hmac_chain(self, partial_check: bool = False) -> bool:
    # ...
    row = self._conn.execute(
        "SELECT last_hmac, logical_clock FROM hmac_ledger WHERE id = 1"
    ).fetchone()
    if row is None:
        raise HMACChainError("HMAC ledger is missing...")
    if len(row["last_hmac"]) != 128:  # SHA-512 hex = 128 chars
        raise HMACChainError("HMAC ledger chain value has unexpected length.")
    return True
```
It only checks the formatting and length of the tip in the singleton table and immediately returns `True` without checking any individual database rows or replaying their hashes.

#### Impact
The database's cryptographic protection is completely faked. If an attacker or a malicious local process directly modifies, deletes, or inserts records in the SQLite file, the database integrity audit will still report that the database is authentic, as the verification function never validates the row-level integrity chain.

#### Recommendation
Implement the full O(N) row replay verification logic. The function must query all ledger-tracked rows across all tables in their exact insertion order, re-calculate the chained HMAC hashes, and verify that they match the stored chain tip, throwing a validation error on any discrepancy.

---

### GD-AUDIT-56: Complete Violation of Section 5.1: Entire Decrypted File Buffered in RAM on Download (OOM Risk)
* **Severity**: **High**
* **Category**: Performance / Memory
* **Files**: [file_browser.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/file_browser.py)

#### Description
Spec §5.1 explicitly requires zero-copy streaming, stating that the system must use a standard 64 KB block streaming pattern to avoid loading the entire file into RAM. However, the download implementation in `file_browser.py` completely violates this rule:
```python
decrypted_data = bytearray()
for idx, chunk in enumerate(chunks):
    # ... download and decrypt chunk ...
    chunk_plaintext = decryptor.verify_and_decrypt()
    decrypted_data.extend(chunk_plaintext)

with open(save_path, "wb") as f:
    f.write(decrypted_data)
```
The entire decrypted file content is accumulated in the `decrypted_data` bytearray in RAM, and only written to disk after the entire decryption process completes.

#### Impact
When downloading large files (e.g., movies, archives, or datasets of several gigabytes), this buffering causes massive RAM consumption. Due to memory allocation overheads in Python, downloading a large file will trigger Out-Of-Memory (OOM) crashes, system freezing, and desktop application instability, rendering the download feature unusable for large files.

#### Recommendation
Refactor `_download_file_core()` to write decrypted blocks directly to the output file stream during the decryption loop (using a buffered file writer), ensuring a small, constant memory footprint regardless of the file size.

---

### GD-AUDIT-57: Flawed Pre-Flight Database Write Check on Wrong Directory Blocks App Launch for Installed Builds
* **Severity**: **High**
* **Category**: Usability / Platform Integration
* **Files**: [preflight_wizard.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/preflight_wizard.py)

#### Description
The preflight checklist wizard in `preflight_wizard.py` runs a database accessibility check using the `DiagnosticsWorker` thread. To verify write access, the thread attempts to create, write to, and delete a temporary file `.gd_write_test` in the current working directory of the application:
```python
# Check write in current directory
test_file = ".gd_write_test"
with open(test_file, "w") as f:
    f.write("test")
```

#### Impact
The check is performed on the process's current working directory instead of the actual resolved directory where the database file `ghostdrive.db` is configured to reside. If the application is installed in a system-protected, read-only directory (such as `C:\Program Files` on Windows or `/usr/share` on Linux) and launched by a standard user, the current working directory is read-only. The preflight check will fail and block the user from launching the application, even if the database is configured in their fully writable user profile folder.

#### Recommendation
Modify the preflight write check to verify write access directly in the parent directory of the resolved `ghostdrive.db` database path, ensuring the check reflects the actual database storage accessibility.

---
"""

target_header = "## Conclusion and Next Steps"

if target_header in full_text:
    parts = full_text.split(target_header)
    updated_text = parts[0] + detailed_descriptions + "\n" + target_header + parts[1]
else:
    updated_text = full_text + detailed_descriptions

# Update all finding counts from 52 to 57
updated_text = updated_text.replace("52 distinct findings", "57 distinct findings")
updated_text = updated_text.replace("52-point", "57-point")
updated_text = updated_text.replace("Addressing these 52 findings", "Addressing these 57 findings")

with open(report_md_path, "w", encoding="utf-8") as f:
    f.write(updated_text)

print("Report updated successfully with 5 new High/Critical findings (total 57).")
