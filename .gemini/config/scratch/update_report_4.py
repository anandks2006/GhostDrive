import os
from pathlib import Path

report_path = Path(r"C:\Users\Anand\Desktop\GhostDrive\.gemini\config\scratch\update_report_3.py") # we can overwrite or create a new one, let's update the actual report directly!
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
        "id": "GD-AUDIT-45",
        "title": "False Sense of Security: Ineffective Passphrase Zeroing and Heap Leaks",
        "category": "Cryptographic Security / Memory Safety",
        "severity": "High",
        "files": "[keystore.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/crypto/keystore.py)<br>[unlock_view.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/unlock_view.py)"
    },
    {
        "id": "GD-AUDIT-46",
        "title": "Fake P2P Metadata Encryption and Discarded Payloads in Sharing Engine",
        "category": "Cryptographic Security / Architecture",
        "severity": "High",
        "files": "[sharing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/sharing.py)<br>[schema.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/database/schema.py)"
    },
    {
        "id": "GD-AUDIT-47",
        "title": "Scoping Bug in macOS Screen Lock Callback Crashes and Prevents Auto-Locking",
        "category": "Security / Platform Integration",
        "severity": "Critical",
        "files": "[macos/screen_lock.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/platform/macos/screen_lock.py)"
    },
    {
        "id": "GD-AUDIT-48",
        "title": "Destructive Operation Log Omitted from HMAC Chain Ledger (Tampers Go Undetected)",
        "category": "Security / Data Integrity",
        "severity": "Critical",
        "files": "[secure_erase.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/secure_erase.py)<br>[db.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/database/db.py)"
    },
    {
        "id": "GD-AUDIT-49",
        "title": "Secrets Vault Key Leakage to Heap via Immutable bytes Conversion",
        "category": "Security / Cryptography",
        "severity": "High",
        "files": "[secrets_vault.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/crypto/secrets_vault.py)"
    },
    {
        "id": "GD-AUDIT-50",
        "title": "Weak Argon2id KDF Calibration Lack of Secure Minimum Bounds",
        "category": "Cryptographic Security",
        "severity": "High",
        "files": "[keystore.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/crypto/keystore.py)"
    },
    {
        "id": "GD-AUDIT-51",
        "title": "Heap Leakage of Private BIP39 Seed Phrase during Recovery",
        "category": "Security / Memory Safety",
        "severity": "High",
        "files": "[keystore.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/crypto/keystore.py)"
    },
    {
        "id": "GD-AUDIT-52",
        "title": "Constant Linux Vault Auto-Lock due to False Screensaver Process Detection",
        "category": "Usability / Reliability",
        "severity": "High",
        "files": "[linux/screen_lock.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/platform/linux/screen_lock.py)"
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
### GD-AUDIT-45: False Sense of Security: Ineffective Passphrase Zeroing and Heap Leaks
* **Severity**: **High**
* **Category**: Cryptographic Security / Memory Safety
* **Files**: [keystore.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/crypto/keystore.py)<br>[unlock_view.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/gui/unlock_view.py)

#### Description
The `KeystoreManager` class implements an explicit memory-zeroing helper `_zero_if_mutable(data)` to scrub sensitive passphrases from memory immediately after Argon2id key derivation. However, because Python `bytes` objects are immutable, `_zero_if_mutable` is a complete silent no-op when passed a `bytes` object. 

In `unlock_view.py`, the GUI retrieves the user's password from the `QLineEdit` input box as an immutable string and passes it directly to the unlock method after encoding it:
```python
self._km.unlock(password.encode("utf-8"))
```
This creates multiple immutable heap copies of the cleartext password (the `str` object from the widget and the `bytes` object from encoding) that are never zeroed. Furthermore, during first-run vault creation, the GUI caches the cleartext password in a class-level string `self._temp_password` on the `UnlockView` instance, preserving it in memory indefinitely.

#### Impact
The claim that passphrases are zeroed from memory immediately after KDF is a false security guarantee. Raw passwords remain fully exposed in cleartext in CPython's heap memory indefinitely, leaving them vulnerable to local memory dumping, core dumps, or heap-scraping malware.

#### Recommendation
1. Modify the GUI to store and process passphrases exclusively in mutable `bytearray` buffers as early as possible.
2. Ensure that the GUI immediately zeros out the `bytearray` contents once key derivation completes, and remove any class-level caching of cleartext password strings (e.g., `self._temp_password`).

---

### GD-AUDIT-46: Fake P2P Metadata Encryption and Discarded Payloads in Sharing Engine
* **Severity**: **High**
* **Category**: Cryptographic Security / Architecture
* **Files**: [sharing.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/sharing.py)<br>[schema.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/database/schema.py)

#### Description
In a zero-knowledge P2P sharing system, the metadata of the shared file (which contains critical decryption keys, chunk hashes, and filenames) must be encrypted and transmitted securely. However, the sharing engine in `sharing.py` completely mocks this process:
1. When transmitting a share, the sender formats a static, hardcoded string as the metadata payload:
   ```python
   "encrypted_metadata": "mock-encrypted-metadata-payload"
   ```
2. When receiving a share (`CMD_SHARE_PACKAGE`), the receiver parses the `encrypted_metadata` parameter but discards it completely. The `shares` table DDL in `schema.py` lacks an `encrypted_metadata` column, and the database insert query does not save it.

#### Impact
The zero-knowledge P2P sharing pipeline is cryptographically broken and non-functional. Because the actual file decryption keys and chunk layouts are never encrypted, transmitted, or saved by the receiver, the recipient is unable to perform a secure restore or decryption of the shared file, reducing the sharing panel to a mock interface.

#### Recommendation
Implement secure metadata encryption using the recipient's public key (using the contact's ML-KEM-768 key or an ECIES key derived from it). Update the database schema to include an `encrypted_metadata` column in the `shares` table, and write the logic for the receiver to decrypt the metadata payload using their private key upon file access.

---

### GD-AUDIT-47: Scoping Bug in macOS Screen Lock Callback Crashes and Prevents Auto-Locking
* **Severity**: **Critical**
* **Category**: Security / Platform Integration
* **Files**: [macos/screen_lock.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/platform/macos/screen_lock.py)

#### Description
The macOS screen lock monitor `MacOSScreenLockMonitor` uses PyObjC to subscribe to system lock notifications. It defines a nested Objective-C observer class `LockObserver` inside the `_notification_loop()` method:
```python
class LockObserver(NSObject):
    def screenLocked_(self, notification):
        logger.info("macOS Screen Locked detected")
        if self._on_lock:
            self._on_lock()
```
However, because `LockObserver` is a separate Python class definition, the identifier `self` inside the `screenLocked_` method refers to the `LockObserver` instance, NOT the outer `MacOSScreenLockMonitor` instance. 

#### Impact
Because the `LockObserver` class does not have an `_on_lock` attribute, when the macOS screen is locked and the notification fires, the callback throws an unhandled `AttributeError: 'LockObserver' object has no attribute '_on_lock'` and crashes. The locking callback is never executed. Consequently, the vault remains fully unlocked and exposed when the user locks their computer, presenting a severe physical security bypass.

#### Recommendation
Refactor the observer class to capture the monitor instance or the callback during initialization:
```python
class LockObserver(NSObject):
    def initWithCallback_(self, callback):
        self = super().init()
        if self:
            self.callback = callback
        return self
    def screenLocked_(self, notification):
        if self.callback:
            self.callback()
```

---

### GD-AUDIT-48: Destructive Operation Log Omitted from HMAC Chain Ledger (Tampers Go Undetected)
* **Severity**: **Critical**
* **Category**: Security / Data Integrity
* **Files**: [secure_erase.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/pipeline/secure_erase.py)<br>[db.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/database/db.py)

#### Description
The safety specification requires all destructive operations (e.g., L1 file secure erasure or remote backend deletions) to be logged to a tamper-evident, cryptographically chained HMAC ledger. The `DestructiveOperationGuard` in `secure_erase.py` calls `db.log_destructive_op_initiated()` and `db.log_destructive_op_completed()` to record these events. 

However, the database wrapper in `db.py` completely omits the destructive operations log table from the `_LEDGER_TABLES` set:
```python
_LEDGER_TABLES = frozenset({
    "files",
    "chunks",
    "chunk_locations",
    "sharing_audit_log",
    "index_snapshots",
})
```

#### Impact
Because the destructive operations log table is not included in the HMAC chain ledger, writes to this table do not advance the database's HMAC chain tip, and their integrity is never verified during the cryptographic ledger audit. An attacker or malicious process with write access to the local database file can freely modify, falsify, or delete the destructive operation logs to cover up unauthorized file erasures, and the tamper-evident chain verification will report that the database is fully authentic.

#### Recommendation
Add the destructive operations log table (e.g., `destructive_ops_log` or equivalent) to the `_LEDGER_TABLES` set in `db.py`. Ensure that every insertion or update to this table executes within the HMAC chain derivation block (`self._chain_hmac()`), guaranteeing full cryptographic tamper evidence.

---

### GD-AUDIT-49: Secrets Vault Key Leakage to Heap via Immutable bytes Conversion
* **Severity**: **High**
* **Category**: Security / Cryptography
* **Files**: [secrets_vault.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/crypto/secrets_vault.py)

#### Description
To prevent key material from lingering in memory, `SecretsVault` stores the derived secrets vault key in a mutable `bytearray` buffer `self._key` and implements a `lock()` method to overwrite the buffer with zeros. However, inside the `_encrypt()` and `_decrypt()` methods, the key is converted to an immutable Python `bytes` object prior to performing the AES-GCM operations:
```python
key_bytes = bytes(self._key)
ciphertext = AESGCM(key_bytes).encrypt(nonce, plaintext, None)
```

#### Impact
Converting the mutable `bytearray` key to an immutable `bytes` object creates a copy of the raw secrets key on the CPython heap. Because `bytes` objects are immutable, this copy cannot be zeroed out in-place. It remains in cleartext in the CPython heap memory until garbage collection occurs, and even then, the physical RAM pages are not scrubbed. This leaks the secrets vault key to the heap every time a secret is accessed, completely defeating the memory-zeroing protections of the `bytearray` container.

#### Recommendation
Avoid converting the key to an immutable `bytes` object. Pass the mutable `bytearray` key directly to the cryptographic functions if supported by the library, or use a ctypes-based buffer or low-level OpenSSL bindings that allow direct memory access and immediate zeroing of the temporary key copy.

---

### GD-AUDIT-50: Weak Argon2id KDF Calibration Lack of Secure Minimum Bounds
* **Severity**: **High**
* **Category**: Cryptographic Security
* **Files**: [keystore.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/crypto/keystore.py)

#### Description
The `calibrate_argon2id()` function in `keystore.py` measures the performance of a single Argon2id iteration on the user's hardware and scales the iteration count (`time_cost`) to target a 1.0-second derivation time. The calibration uses a simple lower bound:
```python
time_cost = max(1, round(target_seconds / elapsed_per_iter))
```

#### Impact
No secure minimum iteration count is enforced. On fast, multi-core, or virtualized hardware, a single Argon2id iteration might execute extremely quickly, or the system might be temporarily throttled. If the calibration outputs a `time_cost` of `1` or `2`, the cryptographic strength of the key derivation falls severely below the industry standard (OWASP recommends a minimum of 3 iterations for Argon2id with a 64 MB memory cost). This significantly reduces the work factor required for an attacker to perform offline GPU-based brute-force attacks if they steal the `keystore.json` file.

#### Recommendation
Enforce a cryptographically secure minimum bound on the calibrated iteration count. Update the calibration formula to enforce the OWASP minimum of 3 iterations:
```python
time_cost = max(3, round(target_seconds / elapsed_per_iter))
```

---

### GD-AUDIT-51: Heap Leakage of Private BIP39 Seed Phrase during Recovery
* **Severity**: **High**
* **Category**: Security / Memory Safety
* **Files**: [keystore.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/crypto/keystore.py)

#### Description
During the disaster recovery flow in `recover_from_seed()`, the user enters their 24-word BIP39 seed phrase. The `mnemonic_to_entropy()` helper in `keystore.py` processes this private seed phrase:
1. It accepts the phrase as an immutable Python `str`.
2. It splits the string into an immutable list of words: `words = phrase.strip().split()`.
3. It maps each word to its 11-bit index and builds an intermediate bit string.

#### Impact
Because all these intermediate variables (`str` objects, `list` of strings, and binary string representations) are immutable Python objects, they cannot be zeroed from memory. The entire 24-word private seed phrase—which represents the master cryptographic root of the entire drive—leaks in cleartext across multiple locations on the CPython heap and remains exposed to memory scraping.

#### Recommendation
Refactor the seed phrase recovery input and parser to ingest the mnemonic words directly into a mutable `bytearray` or a ctypes character buffer. Perform the word splitting, indexing, and bit-assembly operations in-place on mutable memory, and immediately zero out all buffers once the master key entropy is recovered.

---

### GD-AUDIT-52: Constant Linux Vault Auto-Lock due to False Screensaver Process Detection
* **Severity**: **High**
* **Category**: Usability / Reliability
* **Files**: [linux/screen_lock.py](file:///c:/Users/Anand/Desktop/GhostDrive/ghostdrive/platform/linux/screen_lock.py)

#### Description
The Linux screen lock monitor `LinuxScreenLockMonitor` falls back to checking running processes if D-Bus is unavailable. The fallback loop scans running processes every 10 seconds and checks their names against a set of screensaver and locker executables:
```python
lock_names = {"gnome-screensaver", "kscreenlocker", "light-locker", "i3lock", "swaylock", "slock"}
for proc in psutil.process_iter(["name"]):
    if proc.info["name"] in lock_names:
        logger.info("Linux Screen Lock detected...")
        if self._on_lock:
            self._on_lock()
```

#### Impact
This fallback logic is fundamentally flawed. Modern Linux desktop environments run screensaver and lock daemons (like `gnome-screensaver` or `kscreenlocker`) continuously in the background as system services, even when the screen is completely unlocked. Consequently, the monitor will continuously detect these processes as running and trigger the lock callback every 10 seconds, repeatedly locking the user out of their vault while they are actively using the application.

#### Recommendation
Do not assume a screensaver process is active/locked simply because its daemon is running. Query the specific lock state of the screensaver daemon via D-Bus method calls (e.g., checking the `Active` property of GNOME or freedesktop ScreenSaver interfaces), or check the session lock state via `logind` session properties, rather than scanning process names.

---
"""

if "GD-AUDIT-33" in full_text:
    # Let's verify we don't duplicate GD-AUDIT-33 or other details, the python script will handle it cleanly
    pass

target_header = "## Conclusion and Next Steps"

if target_header in full_text:
    parts = full_text.split(target_header)
    updated_text = parts[0] + detailed_descriptions + "\n" + target_header + parts[1]
else:
    updated_text = full_text + detailed_descriptions

# Update all finding counts from 44 to 52
updated_text = updated_text.replace("44 distinct findings", "52 distinct findings")
updated_text = updated_text.replace("44-point", "52-point")
updated_text = updated_text.replace("Addressing these 44 findings", "Addressing these 52 findings")

with open(report_md_path, "w", encoding="utf-8") as f:
    f.write(updated_text)

print("Report updated successfully with 8 new High/Critical findings (total 52).")
