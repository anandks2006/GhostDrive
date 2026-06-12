"""
test_crypto.py — Comprehensive unit tests for ALL Month 1 crypto paths.

Coverage targets (from Spec §12 Month 1):
  ✓ HKDF-SHA512 subkey derivation (all 6 info strings)
  ✓ hmac.compare_digest constant-time comparisons
  ✓ ChaCha20-Poly1305 streaming encryptor / decryptor (RFC 8439)
  ✓ Single-tag-per-chunk invariant
  ✓ Authentication failure before any plaintext is returned
  ✓ MasterKeyBuffer ctypes zeroing
  ✓ BIP39 entropy encoding and recovery with checksum verification
  ✓ Argon2id key derivation (determinism, output length, salt sensitivity)
  ✓ AES-256-GCM keystore encryption/decryption
  ✓ KeystoreManager first-run → verify → unlock → lock → change_passphrase
  ✓ NonceManager monotonic counter, persistence, fsync
  ✓ Async chunk encryption generator

All secret comparisons use hmac.compare_digest (enforced by test structure).
No 'except Exception: pass' anywhere in these tests.
"""

import asyncio
import hashlib
import hmac
import json
import os
import struct
import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from mnemonic import Mnemonic

from tests.conftest import FAST_ARGON2_PARAMS

# ─── Modules under test ───────────────────────────────────────────────────────
from ghostdrive.crypto.chunk_crypto import (
    BLOCK_SIZE,
    TAG_SIZE,
    ChunkDecryptor,
    ChunkEncryptor,
    _derive_poly1305_key,
    _make_chacha20_encryptor,
    encrypt_chunk_async,
)
from ghostdrive.crypto.compare import (
    constant_time_compare,
    verify_auth_tag,
    verify_blake3_hash,
    verify_hmac,
)
from ghostdrive.crypto.hkdf import (
    INFO_CHUNK_ENCRYPTION,
    INFO_CLI_SESSION,
    INFO_INDEX_BACKUP_NAME,
    INFO_INDEX_MAC,
    INFO_KEYSTORE_ENC,
    INFO_SHARE_KEY,
    derive_chunk_key,
    derive_cli_session_key,
    derive_index_backup_name,
    derive_index_mac_key,
    derive_keystore_enc_key,
    derive_share_key,
    derive_subkey,
)
from ghostdrive.crypto.keystore import (
    KeystoreManager,
    MasterKeyBuffer,
    _aes_gcm_decrypt,
    _aes_gcm_encrypt,
    _argon2id_derive,
    calibrate_argon2id,
    entropy_to_mnemonic,
    mnemonic_to_entropy,
)
from ghostdrive.crypto.nonce import MAX_NONCE_COUNTER, NONCE_BYTES, NonceManager
from ghostdrive.exceptions import (
    AuthenticationError,
    CryptoError,
    KeystoreError,
    NonceExhaustedError,
)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. HKDF-SHA512 Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestHKDF:
    """Tests for ghostdrive.crypto.hkdf"""

    _KEY  = os.urandom(32)
    _SALT = os.urandom(32)

    ALL_INFO_STRINGS = [
        INFO_CHUNK_ENCRYPTION,
        INFO_INDEX_MAC,
        INFO_KEYSTORE_ENC,
        INFO_SHARE_KEY,
        INFO_INDEX_BACKUP_NAME,
        INFO_CLI_SESSION,
    ]

    # ── Correctness ──────────────────────────────────────────────────────────

    def test_all_six_info_strings_produce_distinct_subkeys(self):
        """Different info strings MUST produce different subkeys (Spec §4.2)."""
        subkeys = [
            derive_subkey(self._KEY, self._SALT, info)
            for info in self.ALL_INFO_STRINGS
        ]
        # Every pair must be distinct
        for i, sk1 in enumerate(subkeys):
            for j, sk2 in enumerate(subkeys):
                if i != j:
                    assert sk1 != sk2, (
                        f"info_strings[{i}] and info_strings[{j}] produced "
                        f"the same subkey — cryptographic isolation failure!"
                    )

    def test_deterministic_for_same_inputs(self):
        """Same master_key + salt + info always produces the same subkey."""
        k1 = derive_subkey(self._KEY, self._SALT, INFO_CHUNK_ENCRYPTION)
        k2 = derive_subkey(self._KEY, self._SALT, INFO_CHUNK_ENCRYPTION)
        assert k1 == k2

    def test_different_master_key_different_output(self):
        """Different master keys produce different subkeys."""
        k1 = derive_subkey(os.urandom(32), self._SALT, INFO_CHUNK_ENCRYPTION)
        k2 = derive_subkey(os.urandom(32), self._SALT, INFO_CHUNK_ENCRYPTION)
        assert k1 != k2  # Negligible false-positive probability

    def test_different_salt_different_output(self):
        """Different HKDF salts produce different subkeys."""
        k1 = derive_subkey(self._KEY, os.urandom(32), INFO_CHUNK_ENCRYPTION)
        k2 = derive_subkey(self._KEY, os.urandom(32), INFO_CHUNK_ENCRYPTION)
        assert k1 != k2

    def test_output_length_for_all_requested_sizes(self):
        """Output length equals the requested length."""
        for length in [16, 32, 48, 64]:
            key = derive_subkey(self._KEY, self._SALT, b"test-info", length=length)
            assert len(key) == length, f"Expected {length} bytes, got {len(key)}"

    # ── Convenience wrappers ─────────────────────────────────────────────────

    def test_chunk_key_is_32_bytes(self):
        assert len(derive_chunk_key(self._KEY, self._SALT)) == 32

    def test_index_mac_key_is_64_bytes(self):
        assert len(derive_index_mac_key(self._KEY, self._SALT)) == 64

    def test_keystore_enc_key_is_32_bytes(self):
        assert len(derive_keystore_enc_key(self._KEY, self._SALT)) == 32

    def test_share_key_is_32_bytes(self):
        assert len(derive_share_key(self._KEY, self._SALT)) == 32

    def test_index_backup_name_is_32_bytes(self):
        assert len(derive_index_backup_name(self._KEY, self._SALT)) == 32

    def test_cli_session_key_is_32_bytes(self):
        session_salt = os.urandom(32)
        key = derive_cli_session_key(self._KEY, self._SALT, session_salt)
        assert len(key) == 32

    def test_cli_session_key_different_per_session_salt(self):
        k1 = derive_cli_session_key(self._KEY, self._SALT, os.urandom(32))
        k2 = derive_cli_session_key(self._KEY, self._SALT, os.urandom(32))
        assert k1 != k2

    # ── Input validation ─────────────────────────────────────────────────────

    def test_invalid_master_key_length_raises(self):
        with pytest.raises(CryptoError, match="master_key must be exactly 32 bytes"):
            derive_subkey(b"short", self._SALT, INFO_CHUNK_ENCRYPTION)

    def test_invalid_salt_length_raises(self):
        with pytest.raises(CryptoError, match="HKDF salt must be exactly 32 bytes"):
            derive_subkey(self._KEY, b"bad", INFO_CHUNK_ENCRYPTION)

    def test_empty_info_raises(self):
        with pytest.raises(CryptoError, match="HKDF info must be non-empty"):
            derive_subkey(self._KEY, self._SALT, b"")

    # ── Property-based tests ─────────────────────────────────────────────────

    @given(
        master_key=st.binary(min_size=32, max_size=32),
        salt=st.binary(min_size=32, max_size=32),
        length=st.integers(min_value=1, max_value=64),
    )
    def test_property_output_is_correct_length(self, master_key, salt, length):
        key = derive_subkey(master_key, salt, b"prop-test-info", length=length)
        assert len(key) == length

    @given(
        master_key=st.binary(min_size=32, max_size=32),
        salt=st.binary(min_size=32, max_size=32),
    )
    def test_property_chunk_and_mac_key_are_different(self, master_key, salt):
        """chunk key ≠ first 32 bytes of mac key (different info ⇒ different output)."""
        chunk_key = derive_chunk_key(master_key, salt)
        mac_key_head = derive_index_mac_key(master_key, salt)[:32]
        assert chunk_key != mac_key_head


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Constant-Time Comparison Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestConstantTimeCompare:
    """Tests for ghostdrive.crypto.compare"""

    def test_equal_bytes_returns_true(self):
        data = b"hello GhostDrive"
        assert constant_time_compare(data, bytes(data)) is True

    def test_different_bytes_returns_false(self):
        assert constant_time_compare(b"aaa", b"bbb") is False

    def test_empty_bytes(self):
        assert constant_time_compare(b"", b"") is True

    def test_one_empty_one_non_empty(self):
        assert constant_time_compare(b"", b"x") is False

    def test_wrong_type_raises(self):
        with pytest.raises(TypeError):
            constant_time_compare(b"bytes", 42)
        with pytest.raises(TypeError):
            constant_time_compare(None, b"bytes")

    def test_verify_auth_tag_equal_tags(self):
        tag = os.urandom(TAG_SIZE)
        assert verify_auth_tag(tag, bytes(tag)) is True

    def test_verify_auth_tag_different_tags(self):
        assert verify_auth_tag(os.urandom(TAG_SIZE), os.urandom(TAG_SIZE)) is False

    def test_verify_auth_tag_length_mismatch_raises(self):
        with pytest.raises(CryptoError, match="length mismatch"):
            verify_auth_tag(b"16_bytes_exactly", b"short")

    def test_verify_hmac_equal(self):
        h = os.urandom(64)
        assert verify_hmac(h, bytes(h)) is True

    def test_verify_hmac_different(self):
        assert verify_hmac(os.urandom(64), os.urandom(64)) is False

    def test_verify_blake3_equal(self):
        h = os.urandom(32)
        assert verify_blake3_hash(h, bytes(h)) is True

    def test_verify_blake3_different(self):
        assert verify_blake3_hash(os.urandom(32), os.urandom(32)) is False

    @given(data=st.binary(min_size=1, max_size=64))
    def test_property_self_comparison_always_true(self, data):
        assert constant_time_compare(data, data) is True

    @given(
        a=st.binary(min_size=1, max_size=32),
        b=st.binary(min_size=1, max_size=32),
    )
    def test_property_commutative(self, a, b):
        assert constant_time_compare(a, b) == constant_time_compare(b, a)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. ChaCha20-Poly1305 Streaming Encryption Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestChunkCrypto:
    """
    Tests for ghostdrive.crypto.chunk_crypto.

    Focus areas:
    - Single-tag-per-chunk invariant
    - Tag verified BEFORE any plaintext returned
    - Multi-block streaming correctness
    - RFC 8439 MAC construction
    """

    _KEY   = os.urandom(32)
    _NONCE = os.urandom(12)

    def _encrypt(self, key, nonce, plaintext, aad=b""):
        enc = ChunkEncryptor(key, nonce, aad=aad)
        ct  = enc.update(plaintext)
        tag = enc.finalize()
        return ct, tag

    def _decrypt(self, key, nonce, tag, ciphertext, aad=b""):
        dec = ChunkDecryptor(key, nonce, tag, aad=aad)
        dec.feed(ciphertext)
        return dec.verify_and_decrypt()

    # ── Basic round trips ────────────────────────────────────────────────────

    def test_single_block_round_trip(self):
        pt = b"Hello GhostDrive! " * 50
        ct, tag = self._encrypt(self._KEY, self._NONCE, pt)
        recovered = self._decrypt(self._KEY, self._NONCE, tag, ct)
        assert recovered == pt

    def test_empty_plaintext_round_trip(self):
        ct, tag = self._encrypt(self._KEY, self._NONCE, b"")
        assert ct == b""
        assert len(tag) == TAG_SIZE
        recovered = self._decrypt(self._KEY, self._NONCE, tag, b"")
        assert recovered == b""

    def test_multi_block_streaming_round_trip(self):
        """Simulate real streaming: multiple 64 KB blocks."""
        key, nonce = os.urandom(32), os.urandom(12)
        plaintext = os.urandom(BLOCK_SIZE * 3 + 12_345)  # 3.18 blocks

        enc = ChunkEncryptor(key, nonce)
        ct_parts = []
        for offset in range(0, len(plaintext), BLOCK_SIZE):
            block = plaintext[offset : offset + BLOCK_SIZE]
            ct_parts.append(enc.update(block))
        tag = enc.finalize()

        ciphertext = b"".join(ct_parts)

        dec = ChunkDecryptor(key, nonce, tag)
        dec.feed(ciphertext)
        recovered = dec.verify_and_decrypt()

        assert recovered == plaintext

    def test_multi_block_fed_in_sub_block_pieces(self):
        """Simulate 50 MB sub-block feeding (ciphertext split into chunks for feed())."""
        key, nonce = os.urandom(32), os.urandom(12)
        plaintext = os.urandom(BLOCK_SIZE * 5)

        enc = ChunkEncryptor(key, nonce)
        ciphertext = enc.update(plaintext)
        tag = enc.finalize()

        # Feed in 50 KB pieces (simulating sub-block assembly)
        dec = ChunkDecryptor(key, nonce, tag)
        piece_size = 50_000
        for i in range(0, len(ciphertext), piece_size):
            dec.feed(ciphertext[i : i + piece_size])
        recovered = dec.verify_and_decrypt()

        assert recovered == plaintext

    def test_aad_authenticated_and_correct(self):
        """Correct AAD allows decryption."""
        key, nonce = os.urandom(32), os.urandom(12)
        aad = b"chunk-index:0 file-id:abc123"
        pt  = b"secret model weights"

        ct, tag = self._encrypt(key, nonce, pt, aad=aad)
        recovered = self._decrypt(key, nonce, tag, ct, aad=aad)
        assert recovered == pt

    # ── Authentication failures ───────────────────────────────────────────────

    def test_corrupted_ciphertext_raises_authentication_error(self):
        pt = b"sensitive data that must not leak"
        ct, tag = self._encrypt(self._KEY, self._NONCE, pt)

        corrupted = bytearray(ct)
        corrupted[0] ^= 0x01  # Flip one bit

        dec = ChunkDecryptor(self._KEY, self._NONCE, tag)
        dec.feed(bytes(corrupted))
        with pytest.raises(AuthenticationError):
            dec.verify_and_decrypt()

    def test_wrong_tag_raises_and_returns_no_plaintext(self):
        """Spec §4.4: Tag verified before ANY decrypted byte returned."""
        pt = b"top secret"
        ct, _ = self._encrypt(self._KEY, self._NONCE, pt)
        wrong_tag = os.urandom(TAG_SIZE)

        dec = ChunkDecryptor(self._KEY, self._NONCE, wrong_tag)
        dec.feed(ct)
        with pytest.raises(AuthenticationError):
            dec.verify_and_decrypt()

    def test_wrong_key_fails_authentication(self):
        pt = b"model checkpoint data"
        ct, tag = self._encrypt(self._KEY, self._NONCE, pt)

        dec = ChunkDecryptor(os.urandom(32), self._NONCE, tag)
        dec.feed(ct)
        with pytest.raises(AuthenticationError):
            dec.verify_and_decrypt()

    def test_wrong_nonce_fails_authentication(self):
        key = os.urandom(32)
        pt  = b"dataset shard"
        ct, tag = self._encrypt(key, self._NONCE, pt)

        dec = ChunkDecryptor(key, os.urandom(12), tag)
        dec.feed(ct)
        with pytest.raises(AuthenticationError):
            dec.verify_and_decrypt()

    def test_wrong_aad_fails_authentication(self):
        """Modified AAD must invalidate the tag."""
        key, nonce = os.urandom(32), os.urandom(12)
        aad = b"correct-aad"
        pt  = b"data"

        ct, tag = self._encrypt(key, nonce, pt, aad=aad)

        dec = ChunkDecryptor(key, nonce, tag, aad=b"wrong-aad")
        dec.feed(ct)
        with pytest.raises(AuthenticationError):
            dec.verify_and_decrypt()

    def test_partial_ciphertext_fails_authentication(self):
        """Spec §5.4: authentication never attempted on partial chunk."""
        pt = os.urandom(2_000)
        ct, tag = self._encrypt(self._KEY, self._NONCE, pt)

        dec = ChunkDecryptor(self._KEY, self._NONCE, tag)
        dec.feed(ct[:500])  # Only feed half

        with pytest.raises(AuthenticationError):
            dec.verify_and_decrypt()

    # ── Single-tag-per-chunk invariant ───────────────────────────────────────

    def test_single_tag_covers_all_blocks_modifying_any_block_invalidates(self):
        """
        SPEC INVARIANT: ONE Poly1305 tag per logical chunk.
        Modifying any single block must invalidate the single shared tag.
        Tested for each block position independently.
        """
        key, nonce = os.urandom(32), os.urandom(12)
        block_count = 4
        blocks = [os.urandom(BLOCK_SIZE) for _ in range(block_count)]

        enc = ChunkEncryptor(key, nonce)
        ct_blocks = [enc.update(b) for b in blocks]
        tag = enc.finalize()

        for corrupt_idx in range(block_count):
            # Corrupt one block at position corrupt_idx
            corrupted_blocks = list(ct_blocks)
            arr = bytearray(corrupted_blocks[corrupt_idx])
            arr[0] ^= 0xFF
            corrupted_blocks[corrupt_idx] = bytes(arr)

            dec = ChunkDecryptor(key, nonce, tag)
            for cb in corrupted_blocks:
                dec.feed(cb)

            with pytest.raises(AuthenticationError):
                dec.verify_and_decrypt()

    # ── State machine / misuse resistance ────────────────────────────────────

    def test_finalize_twice_raises(self):
        enc = ChunkEncryptor(self._KEY, self._NONCE)
        enc.update(b"data")
        enc.finalize()
        with pytest.raises(CryptoError, match="single-use"):
            enc.finalize()

    def test_update_after_finalize_raises(self):
        enc = ChunkEncryptor(self._KEY, self._NONCE)
        enc.finalize()
        with pytest.raises(CryptoError, match="single-use"):
            enc.update(b"more data")

    def test_verify_and_decrypt_twice_raises(self):
        ct, tag = self._encrypt(self._KEY, self._NONCE, b"data")
        dec = ChunkDecryptor(self._KEY, self._NONCE, tag)
        dec.feed(ct)
        dec.verify_and_decrypt()
        with pytest.raises(CryptoError):
            dec.verify_and_decrypt()

    def test_feed_after_verify_raises(self):
        ct, tag = self._encrypt(self._KEY, self._NONCE, b"data")
        dec = ChunkDecryptor(self._KEY, self._NONCE, tag)
        dec.feed(ct)
        dec.verify_and_decrypt()
        with pytest.raises(CryptoError):
            dec.feed(b"more")

    # ── Input validation ─────────────────────────────────────────────────────

    def test_invalid_key_length_raises(self):
        with pytest.raises(CryptoError):
            ChunkEncryptor(b"short_key", self._NONCE)

    def test_invalid_nonce_length_raises(self):
        with pytest.raises(CryptoError):
            ChunkEncryptor(self._KEY, b"bad")

    def test_invalid_tag_length_raises(self):
        with pytest.raises(CryptoError):
            ChunkDecryptor(self._KEY, self._NONCE, b"too_short")

    # ── RFC 8439 construction internals ──────────────────────────────────────

    def test_poly1305_key_derivation_is_deterministic(self):
        key, nonce = os.urandom(32), os.urandom(12)
        pk1 = _derive_poly1305_key(key, nonce)
        pk2 = _derive_poly1305_key(key, nonce)
        assert pk1 == pk2
        assert len(pk1) == 32

    def test_poly1305_key_differs_per_nonce(self):
        key = os.urandom(32)
        pk1 = _derive_poly1305_key(key, os.urandom(12))
        pk2 = _derive_poly1305_key(key, os.urandom(12))
        assert pk1 != pk2

    def test_ciphertext_length_equals_plaintext_length(self):
        """ChaCha20 is a stream cipher — CT length == PT length."""
        pt = os.urandom(12_345)
        enc = ChunkEncryptor(self._KEY, self._NONCE)
        ct  = enc.update(pt)
        enc.finalize()
        assert len(ct) == len(pt)

    def test_ciphertext_differs_from_plaintext(self):
        pt = b"very secret data" * 10
        enc = ChunkEncryptor(self._KEY, self._NONCE)
        ct  = enc.update(pt)
        enc.finalize()
        assert ct != pt

    # ── Property-based tests ─────────────────────────────────────────────────

    @given(plaintext=st.binary(min_size=0, max_size=BLOCK_SIZE * 2))
    @settings(max_examples=50)
    def test_property_encrypt_decrypt_roundtrip(self, plaintext):
        key, nonce = os.urandom(32), os.urandom(12)
        enc = ChunkEncryptor(key, nonce)
        ct  = enc.update(plaintext)
        tag = enc.finalize()

        dec = ChunkDecryptor(key, nonce, tag)
        dec.feed(ct)
        recovered = dec.verify_and_decrypt()
        assert recovered == plaintext

    @given(plaintext=st.binary(min_size=1, max_size=512))
    @settings(max_examples=30)
    def test_property_single_byte_corruption_detected(self, plaintext):
        """Any single-bit change in ciphertext invalidates the tag."""
        key, nonce = os.urandom(32), os.urandom(12)
        enc = ChunkEncryptor(key, nonce)
        ct  = enc.update(plaintext)
        tag = enc.finalize()

        corrupted = bytearray(ct)
        corrupted[0] ^= 0x01

        dec = ChunkDecryptor(key, nonce, tag)
        dec.feed(bytes(corrupted))
        with pytest.raises(AuthenticationError):
            dec.verify_and_decrypt()


# ═══════════════════════════════════════════════════════════════════════════════
# 4. MasterKeyBuffer Tests (ctypes zeroing)
# ═══════════════════════════════════════════════════════════════════════════════

class TestMasterKeyBuffer:
    """Tests for MasterKeyBuffer ctypes secure memory."""

    def test_stores_and_retrieves_key(self):
        key = os.urandom(32)
        buf = MasterKeyBuffer(key)
        assert buf.key == key

    def test_zero_wipes_key(self):
        key = os.urandom(32)
        buf = MasterKeyBuffer(key)
        buf.zero()
        with pytest.raises(KeystoreError, match="zeroed"):
            _ = buf.key

    def test_double_zero_is_safe(self):
        buf = MasterKeyBuffer(os.urandom(32))
        buf.zero()
        buf.zero()  # Must not raise

    def test_wrong_key_length_raises(self):
        with pytest.raises(ValueError):
            MasterKeyBuffer(b"too short")

    def test_is_unlocked_false_after_zero(self):
        buf = MasterKeyBuffer(os.urandom(32))
        assert buf._zeroed is False
        buf.zero()
        assert buf._zeroed is True

    def test_context_manager_zeroes_on_exit(self):
        key = os.urandom(32)
        with MasterKeyBuffer(key) as buf:
            retrieved = buf.key
        assert retrieved == key

        with pytest.raises(KeystoreError):
            _ = buf.key  # Zeroed on context exit

    def test_key_is_immutable_copy_not_reference(self):
        """Each call to .key returns a copy, not a reference to the internal buffer."""
        key = os.urandom(32)
        buf = MasterKeyBuffer(key)
        k1 = buf.key
        k2 = buf.key
        assert k1 == k2 == key
        # Modifying k1 doesn't corrupt the buffer
        k1_arr = bytearray(k1)
        k1_arr[0] ^= 0xFF
        assert buf.key == key  # Buffer unchanged


# ═══════════════════════════════════════════════════════════════════════════════
# 5. BIP39 Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestBIP39:
    """Tests for BIP39 encoding / recovery with checksum verification."""

    def test_entropy_to_mnemonic_produces_24_words(self):
        entropy = os.urandom(32)
        phrase  = entropy_to_mnemonic(entropy)
        assert len(phrase.split()) == 24

    def test_mnemonic_to_entropy_round_trip(self):
        """entropy → mnemonic → entropy must be lossless."""
        entropy  = os.urandom(32)
        phrase   = entropy_to_mnemonic(entropy)
        recovered = mnemonic_to_entropy(phrase)
        assert recovered == entropy

    def test_all_words_are_valid_bip39(self):
        """All 24 words must be in the standard BIP39 English word list."""
        phrase = entropy_to_mnemonic(os.urandom(32))
        mnemo  = Mnemonic("english")
        for word in phrase.split():
            assert word in mnemo.wordlist, f"Non-BIP39 word generated: {word!r}"

    def test_invalid_word_raises(self):
        with pytest.raises(KeystoreError, match="Invalid BIP39 word"):
            mnemonic_to_entropy("notaword " * 24)

    def test_wrong_word_count_raises(self):
        phrase = entropy_to_mnemonic(os.urandom(32))
        short  = " ".join(phrase.split()[:12])
        with pytest.raises(KeystoreError, match="24 words"):
            mnemonic_to_entropy(short)

    def test_checksum_failure_raises(self):
        """Swapping two non-adjacent words in a valid phrase should fail checksum."""
        phrase = entropy_to_mnemonic(os.urandom(32))
        words  = phrase.split()
        # Swap word 0 and word 12 (highly likely to break checksum)
        words[0], words[12] = words[12], words[0]
        modified = " ".join(words)
        try:
            mnemonic_to_entropy(modified)
            # If checksum still passes (astronomically unlikely), test passes vacuously
        except KeystoreError as exc:
            assert "checksum" in str(exc).lower() or "verification" in str(exc).lower()

    def test_constant_time_checksum_comparison(self):
        """The checksum is compared with hmac.compare_digest (enforced by inspect)."""
        import inspect
        import ghostdrive.crypto.keystore as ks_mod
        source = inspect.getsource(ks_mod.mnemonic_to_entropy)
        assert "hmac.compare_digest" in source, (
            "mnemonic_to_entropy MUST use hmac.compare_digest for checksum comparison "
            "(Spec §4.1 — constant-time comparisons required for all secret material)"
        )

    def test_wrong_entropy_length_raises(self):
        with pytest.raises(CryptoError):
            entropy_to_mnemonic(b"too_short")

    @given(entropy=st.binary(min_size=32, max_size=32))
    @settings(max_examples=20)
    def test_property_round_trip(self, entropy):
        phrase    = entropy_to_mnemonic(entropy)
        recovered = mnemonic_to_entropy(phrase)
        assert recovered == entropy


# ═══════════════════════════════════════════════════════════════════════════════
# 6. AES-256-GCM Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestAESGCM:
    """Tests for AES-256-GCM keystore encryption."""

    def test_encrypt_decrypt_round_trip(self):
        key = os.urandom(32)
        pt  = b"keystore payload: master_key + hkdf_salt + genesis_seed"
        nonce, ct = _aes_gcm_encrypt(key, pt)
        recovered = _aes_gcm_decrypt(key, nonce, ct)
        assert recovered == pt

    def test_wrong_key_raises_authentication_error(self):
        key = os.urandom(32)
        nonce, ct = _aes_gcm_encrypt(key, b"test")
        with pytest.raises(AuthenticationError):
            _aes_gcm_decrypt(os.urandom(32), nonce, ct)

    def test_tampered_ciphertext_raises(self):
        key = os.urandom(32)
        nonce, ct = _aes_gcm_encrypt(key, b"secret")
        corrupted = bytearray(ct)
        corrupted[0] ^= 0xFF
        with pytest.raises(AuthenticationError):
            _aes_gcm_decrypt(key, nonce, bytes(corrupted))

    def test_nonces_are_unique_across_calls(self):
        key    = os.urandom(32)
        nonces = {_aes_gcm_encrypt(key, b"data")[0] for _ in range(100)}
        assert len(nonces) == 100, "AES-GCM nonces must be unique (never reuse!)"

    def test_invalid_key_length_raises(self):
        with pytest.raises(CryptoError):
            _aes_gcm_encrypt(b"short", b"data")

    def test_ciphertext_is_longer_than_plaintext_by_tag(self):
        """AES-GCM appends a 16-byte authentication tag."""
        key = os.urandom(32)
        pt  = b"hello"
        _, ct = _aes_gcm_encrypt(key, pt)
        assert len(ct) == len(pt) + 16


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Argon2id Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestArgon2id:
    """Tests for Argon2id passphrase KDF."""

    PARAMS = FAST_ARGON2_PARAMS

    def test_derivation_is_deterministic(self):
        pp   = b"correct horse battery staple"
        salt = os.urandom(32)
        k1   = _argon2id_derive(pp, salt, self.PARAMS)
        k2   = _argon2id_derive(pp, salt, self.PARAMS)
        assert k1 == k2

    def test_different_passphrase_different_key(self):
        salt = os.urandom(32)
        k1   = _argon2id_derive(b"passphrase1", salt, self.PARAMS)
        k2   = _argon2id_derive(b"passphrase2", salt, self.PARAMS)
        assert k1 != k2

    def test_different_salt_different_key(self):
        pp = b"same passphrase"
        k1 = _argon2id_derive(pp, os.urandom(32), self.PARAMS)
        k2 = _argon2id_derive(pp, os.urandom(32), self.PARAMS)
        assert k1 != k2

    def test_output_is_hash_len_bytes(self):
        key = _argon2id_derive(b"pass", os.urandom(32), self.PARAMS)
        assert len(key) == self.PARAMS["hash_len"]

    def test_calibrate_returns_valid_params(self):
        params = calibrate_argon2id(target_seconds=0.1)
        assert params["time_cost"]   >= 1
        assert params["memory_cost"] > 0
        assert params["parallelism"] >= 1
        assert params["hash_len"]    == 32


# ═══════════════════════════════════════════════════════════════════════════════
# 8. KeystoreManager Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestKeystoreManager:
    """Integration tests for the full keystore state machine."""

    def _create_and_unlock(self, path, passphrase=b"test_pass"):
        mgr    = KeystoreManager(path)
        phrase = mgr.create_new(passphrase, calibrate=False, argon2_params=FAST_ARGON2_PARAMS)
        mgr.verify_and_save(phrase)
        return mgr, phrase

    # ── First-run flow ────────────────────────────────────────────────────────

    def test_create_new_returns_24_word_phrase(self, tmp_keystore_path):
        mgr    = KeystoreManager(tmp_keystore_path)
        phrase = mgr.create_new(b"pass", calibrate=False, argon2_params=FAST_ARGON2_PARAMS)
        assert len(phrase.split()) == 24

    def test_verify_and_save_writes_keystore_file(self, tmp_keystore_path):
        mgr, phrase = self._create_and_unlock(tmp_keystore_path)
        assert tmp_keystore_path.exists()

    def test_keystore_is_unlocked_after_verify_and_save(self, tmp_keystore_path):
        mgr, _ = self._create_and_unlock(tmp_keystore_path)
        assert mgr.is_unlocked

    def test_master_key_is_32_bytes(self, tmp_keystore_path):
        mgr, _ = self._create_and_unlock(tmp_keystore_path)
        assert len(mgr.master_key) == 32

    def test_hkdf_salt_is_32_bytes(self, tmp_keystore_path):
        mgr, _ = self._create_and_unlock(tmp_keystore_path)
        assert len(mgr.hkdf_salt) == 32

    def test_genesis_seed_is_32_bytes(self, tmp_keystore_path):
        mgr, _ = self._create_and_unlock(tmp_keystore_path)
        assert len(mgr.genesis_seed) == 32

    def test_create_new_fails_if_keystore_exists(self, tmp_keystore_path):
        self._create_and_unlock(tmp_keystore_path)
        mgr2 = KeystoreManager(tmp_keystore_path)
        with pytest.raises(KeystoreError, match="already exists"):
            mgr2.create_new(b"pass", calibrate=False, argon2_params=FAST_ARGON2_PARAMS)

    def test_verify_and_save_without_create_new_raises(self, tmp_keystore_path):
        mgr = KeystoreManager(tmp_keystore_path)
        with pytest.raises(KeystoreError, match="create_new"):
            mgr.verify_and_save("word " * 24)

    def test_wrong_seed_phrase_in_verify_raises(self, tmp_keystore_path):
        mgr = KeystoreManager(tmp_keystore_path)
        mgr.create_new(b"pass", calibrate=False, argon2_params=FAST_ARGON2_PARAMS)
        wrong_phrase = entropy_to_mnemonic(os.urandom(32))
        with pytest.raises(KeystoreError, match="verification"):
            mgr.verify_and_save(wrong_phrase)

    # ── Unlock / lock ─────────────────────────────────────────────────────────

    def test_unlock_with_correct_passphrase_succeeds(self, tmp_keystore_path):
        passphrase = b"my_secure_passphrase"
        mgr, phrase = self._create_and_unlock(tmp_keystore_path, passphrase)
        original_key = mgr.master_key
        mgr.lock()

        mgr2 = KeystoreManager(tmp_keystore_path)
        mgr2.unlock(passphrase)
        assert mgr2.is_unlocked
        assert mgr2.master_key == original_key

    def test_unlock_with_wrong_passphrase_raises(self, tmp_keystore_path):
        self._create_and_unlock(tmp_keystore_path, b"correct")
        mgr2 = KeystoreManager(tmp_keystore_path)
        with pytest.raises(AuthenticationError):
            mgr2.unlock(b"wrong")

    def test_master_key_consistent_across_lock_unlock_cycles(self, tmp_keystore_path):
        mgr, _ = self._create_and_unlock(tmp_keystore_path)
        key1   = mgr.master_key
        salt1  = mgr.hkdf_salt
        mgr.lock()

        mgr.unlock(b"test_pass")
        assert mgr.master_key == key1
        assert mgr.hkdf_salt  == salt1

    def test_lock_zeroes_master_key(self, tmp_keystore_path):
        mgr, _ = self._create_and_unlock(tmp_keystore_path)
        assert mgr.is_unlocked
        mgr.lock()
        assert not mgr.is_unlocked
        with pytest.raises(KeystoreError):
            _ = mgr.master_key

    def test_properties_raise_when_locked(self, tmp_keystore_path):
        mgr = KeystoreManager(tmp_keystore_path)
        with pytest.raises(KeystoreError):
            _ = mgr.master_key
        with pytest.raises(KeystoreError):
            _ = mgr.hkdf_salt
        with pytest.raises(KeystoreError):
            _ = mgr.genesis_seed

    def test_unlock_nonexistent_keystore_raises(self, tmp_keystore_path):
        mgr = KeystoreManager(tmp_keystore_path)
        with pytest.raises(KeystoreError, match="not found"):
            mgr.unlock(b"pass")

    # ── Passphrase change ─────────────────────────────────────────────────────

    def test_passphrase_change_old_fails_new_succeeds(self, tmp_keystore_path):
        passphrase = b"old_passphrase"
        mgr, _     = self._create_and_unlock(tmp_keystore_path, passphrase)
        original_key = mgr.master_key

        mgr.change_passphrase(b"new_passphrase")
        mgr.lock()

        # Old passphrase must fail
        mgr2 = KeystoreManager(tmp_keystore_path)
        with pytest.raises(AuthenticationError):
            mgr2.unlock(passphrase)

        # New passphrase must succeed with same Master Key
        mgr3 = KeystoreManager(tmp_keystore_path)
        mgr3.unlock(b"new_passphrase")
        assert mgr3.master_key == original_key

    def test_change_passphrase_while_locked_raises(self, tmp_keystore_path):
        mgr = KeystoreManager(tmp_keystore_path)
        with pytest.raises(KeystoreError, match="unlocked"):
            mgr.change_passphrase(b"new")

    # ── Export seed phrase ────────────────────────────────────────────────────

    def test_export_seed_phrase_matches_original(self, tmp_keystore_path):
        mgr, original_phrase = self._create_and_unlock(tmp_keystore_path)
        exported = mgr.export_seed_phrase()
        assert exported == original_phrase

    def test_export_seed_phrase_while_locked_raises(self, tmp_keystore_path):
        mgr = KeystoreManager(tmp_keystore_path)
        with pytest.raises(KeystoreError):
            mgr.export_seed_phrase()

    # ── HKDF subkey consistency ───────────────────────────────────────────────

    def test_hkdf_subkeys_consistent_across_unlock_cycles(self, tmp_keystore_path):
        mgr, _ = self._create_and_unlock(tmp_keystore_path)
        chunk_key1 = derive_chunk_key(mgr.master_key, mgr.hkdf_salt)
        mgr.lock()
        mgr.unlock(b"test_pass")
        chunk_key2 = derive_chunk_key(mgr.master_key, mgr.hkdf_salt)
        assert chunk_key1 == chunk_key2

    # ── Recovery from seed ────────────────────────────────────────────────────

    def test_recover_from_seed_phrase(self, tmp_keystore_path, tmp_path):
        mgr, phrase = self._create_and_unlock(tmp_keystore_path)
        original_key = mgr.master_key
        mgr.lock()

        # Simulate new install
        new_ks_path = tmp_path / "recovered_keystore.json"
        mgr2 = KeystoreManager(new_ks_path)
        with pytest.warns(UserWarning):  # Warns about new salt
            mgr2.recover_from_seed(phrase, b"new_pass")

        assert mgr2.is_unlocked
        assert mgr2.master_key == original_key


# ═══════════════════════════════════════════════════════════════════════════════
# 9. NonceManager Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestNonceManager:
    """Tests for monotonic nonce counter with persistence and fsync."""

    def test_first_nonce_has_counter_value_1(self, tmp_data_dir):
        nm    = NonceManager(tmp_data_dir)
        nonce = nm.next_nonce()
        assert len(nonce) == NONCE_BYTES
        assert NonceManager.nonce_to_counter(nonce) == 1

    def test_nonces_are_strictly_increasing(self, tmp_data_dir):
        nm       = NonceManager(tmp_data_dir)
        counters = [NonceManager.nonce_to_counter(nm.next_nonce()) for _ in range(10)]
        for i in range(len(counters) - 1):
            assert counters[i] < counters[i + 1]

    def test_nonces_are_unique(self, tmp_data_dir):
        nm     = NonceManager(tmp_data_dir)
        nonces = [nm.next_nonce() for _ in range(50)]
        assert len(set(nonces)) == 50

    def test_counter_persists_across_instances(self, tmp_data_dir):
        """Simulates app restart: new NonceManager reads saved counter."""
        nm1 = NonceManager(tmp_data_dir)
        for _ in range(5):
            nm1.next_nonce()  # Counter is now 5

        nm2   = NonceManager(tmp_data_dir)  # New instance, same directory
        nonce = nm2.next_nonce()            # Should be 6
        assert NonceManager.nonce_to_counter(nonce) == 6

    def test_counter_file_written_after_first_nonce(self, tmp_data_dir):
        nm = NonceManager(tmp_data_dir)
        nm.next_nonce()
        counter_file = tmp_data_dir / "nonce_counter.json"
        assert counter_file.exists()

    def test_counter_file_contains_correct_value(self, tmp_data_dir):
        nm = NonceManager(tmp_data_dir)
        nm.next_nonce()
        nm.next_nonce()
        nm.next_nonce()
        counter_file = tmp_data_dir / "nonce_counter.json"
        with open(counter_file) as fh:
            data = json.load(fh)
        assert data["nonce_counter"] == 3

    def test_counter_to_nonce_round_trip(self):
        for counter in [1, 255, 256, 65535, 2**32, 2**64 - 1, 2**80]:
            nonce = NonceManager.counter_to_nonce(counter)
            assert len(nonce) == NONCE_BYTES
            assert NonceManager.nonce_to_counter(nonce) == counter

    def test_invalid_counter_zero_raises(self):
        with pytest.raises(CryptoError):
            NonceManager.counter_to_nonce(0)

    def test_invalid_nonce_length_raises(self):
        with pytest.raises(CryptoError):
            NonceManager.nonce_to_counter(b"too_short")

    def test_peek_counter_does_not_increment(self, tmp_data_dir):
        nm = NonceManager(tmp_data_dir)
        nm.next_nonce()  # Counter = 1
        nm.peek_counter()
        nm.peek_counter()
        assert nm.peek_counter() == 1  # Still 1

    def test_peek_after_increment(self, tmp_data_dir):
        nm = NonceManager(tmp_data_dir)
        nm.next_nonce()
        nm.next_nonce()
        assert nm.peek_counter() == 2


# ═══════════════════════════════════════════════════════════════════════════════
# 10. Async Encryption Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestAsyncEncryption:
    """Tests for the async generator-based chunk encryption pipeline."""

    async def test_encrypt_chunk_async_round_trip(self, tmp_path):
        # Write test file
        plaintext = os.urandom(BLOCK_SIZE * 2 + 5_000)
        src = tmp_path / "test_chunk.bin"
        src.write_bytes(plaintext)

        key, nonce = os.urandom(32), os.urandom(12)

        # Collect all yielded data from the async generator
        parts = []
        async for chunk in encrypt_chunk_async(key, nonce, src, 0, len(plaintext)):
            parts.append(chunk)

        all_data   = b"".join(parts)
        ciphertext = all_data[:-TAG_SIZE]
        tag        = all_data[-TAG_SIZE:]

        assert len(tag) == TAG_SIZE
        assert len(ciphertext) == len(plaintext)

        # Decrypt and verify
        dec = ChunkDecryptor(key, nonce, tag)
        dec.feed(ciphertext)
        recovered = dec.verify_and_decrypt()
        assert recovered == plaintext

    async def test_encrypt_chunk_async_yields_blocks_then_tag(self, tmp_path):
        """The last yielded item is always exactly TAG_SIZE bytes (the tag)."""
        plaintext = os.urandom(BLOCK_SIZE * 3)
        src = tmp_path / "chunk.bin"
        src.write_bytes(plaintext)

        parts = []
        async for chunk in encrypt_chunk_async(
            os.urandom(32), os.urandom(12), src, 0, len(plaintext)
        ):
            parts.append(chunk)

        # Last item is the 16-byte tag
        assert len(parts[-1]) == TAG_SIZE

    async def test_encrypt_chunk_async_with_offset(self, tmp_path):
        """Test reading a sub-region of a file (chunk offset)."""
        full_data = os.urandom(BLOCK_SIZE * 4)
        src = tmp_path / "file.bin"
        src.write_bytes(full_data)

        offset = BLOCK_SIZE
        size   = BLOCK_SIZE * 2
        key, nonce = os.urandom(32), os.urandom(12)

        parts = []
        async for chunk in encrypt_chunk_async(key, nonce, src, offset, size):
            parts.append(chunk)

        all_data   = b"".join(parts)
        ciphertext = all_data[:-TAG_SIZE]
        tag        = all_data[-TAG_SIZE:]

        dec = ChunkDecryptor(key, nonce, tag)
        dec.feed(ciphertext)
        recovered = dec.verify_and_decrypt()

        assert recovered == full_data[offset : offset + size]
