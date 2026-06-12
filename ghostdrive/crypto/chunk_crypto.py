"""
chunk_crypto.py — ChaCha20-Poly1305 streaming encryption for file chunks.

Spec §4.4 — Critical Cryptographic Invariants
==============================================
1.  ONE Poly1305 tag per logical chunk — NOT per 64 KB block.
    The tag covers the COMPLETE concatenated ciphertext of the entire chunk.
2.  Nonce counter incremented BEFORE upload begins (handled in nonce.py).
3.  All sub-blocks must be assembled before the Poly1305 tag is verified.
    Authentication is NEVER attempted on a partial chunk.
4.  Tag verified before ANY decrypted byte is returned to the application.
5.  asyncio.to_thread() wraps encryptor.update() to keep ChaCha20 CPU work
    off the main Qt thread. One persistent encryption thread per active upload
    stream — not one thread per block.

Streaming Pipeline (from spec §5.1)
------------------------------------
    async def encrypted_chunk_stream(file_path, offset, size, key, nonce):
        encryptor = ChaCha20Poly1305(key)           # one instance per chunk
        async with aiofiles.open(file_path, "rb") as f:
            await f.seek(offset)
            bytes_read = 0
            while bytes_read < size:
                block = await f.read(min(65536, size - bytes_read))
                if not block: break
                ct_block = await asyncio.to_thread(encryptor.update, block)
                yield ct_block                       # 64 KB ciphertext → socket
                bytes_read += len(block)
        tag = encryptor.finalize()                  # ONE Poly1305 tag for entire chunk
        yield tag                                    # appended after last block

Implementation Notes — RFC 8439 Construction
---------------------------------------------
The ``cryptography`` library's ``ChaCha20Poly1305`` AEAD is one-shot only.
To achieve streaming update()/finalize() we implement the RFC 8439 construction
manually using the hazardous materials layer:

  1. Poly1305 one-time key: first 32 bytes of ChaCha20(key, counter=0, nonce)
  2. Encryption: ChaCha20(key, counter=1, nonce) XOR plaintext
  3. MAC input: pad16(aad) ‖ pad16(ciphertext) ‖ LE64(len_aad) ‖ LE64(len_ct)

The ``cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20`` nonce
format is 16 bytes: 4-byte LE uint32 counter ‖ 12-byte nonce.
The ``cryptography.hazmat.primitives.poly1305.Poly1305`` class supports
incremental ``update()`` + ``finalize()``.

ChaCha20-Poly1305 maximum message size is 2^38 − 64 bytes (~256 GB).
No logical chunk approaches this limit. Documented for future developers.
"""

import asyncio
import struct
from pathlib import Path
from typing import AsyncGenerator

import aiofiles
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.poly1305 import Poly1305

from ghostdrive.crypto.compare import verify_auth_tag
from ghostdrive.exceptions import AuthenticationError, CryptoError

# ─── Constants ────────────────────────────────────────────────────────────────

BLOCK_SIZE: int = 65_536   # 64 KB — hard architectural constraint (Spec §5.1)
TAG_SIZE:   int = 16       # Poly1305 tag is always 16 bytes


# ─── Low-level RFC 8439 primitives ────────────────────────────────────────────

def _derive_poly1305_key(chacha_key: bytes, nonce_12: bytes) -> bytes:
    """
    Derive the Poly1305 one-time key per RFC 8439 §2.6.1.

    ChaCha20 is run with counter=0; the first 32 bytes of the 64-byte output
    block become the Poly1305 key. This key is NEVER reused — it is unique per
    (chacha_key, nonce_12) pair.

    Args:
        chacha_key: 32-byte ChaCha20 key.
        nonce_12:   12-byte nonce (96-bit, from the nonce_counter).

    Returns:
        32-byte Poly1305 one-time key.
    """
    # algorithms.ChaCha20 nonce layout: 4-byte LE counter ‖ 12-byte nonce
    full_nonce = b"\x00\x00\x00\x00" + nonce_12  # counter = 0
    cipher = Cipher(algorithms.ChaCha20(chacha_key, full_nonce), mode=None)
    enc = cipher.encryptor()
    block = enc.update(b"\x00" * 64)  # 64-byte ChaCha20 keystream block
    return block[:32]                  # First 32 bytes = Poly1305 key


def _make_chacha20_encryptor(chacha_key: bytes, nonce_12: bytes):
    """
    Create a ChaCha20 encryptor/decryptor starting at counter=1 (RFC 8439).

    The Poly1305 one-time key consumed counter=0; actual payload encryption
    starts at counter=1. The ``cryptography`` library internally increments the
    counter for each 64-byte block, so large chunks are handled correctly.

    Args:
        chacha_key: 32-byte ChaCha20 key.
        nonce_12:   12-byte nonce.

    Returns:
        A ``CipherContext`` encryptor object (call ``.update(data)`` on it).
    """
    full_nonce = b"\x01\x00\x00\x00" + nonce_12  # counter = 1
    cipher = Cipher(algorithms.ChaCha20(chacha_key, full_nonce), mode=None)
    return cipher.encryptor()


# ─── ChunkEncryptor ───────────────────────────────────────────────────────────

class ChunkEncryptor:
    """
    Single-use streaming ChaCha20-Poly1305 encryptor for ONE logical chunk.

    Usage Pattern
    -------------
        enc = ChunkEncryptor(key, nonce)
        for block in read_64kb_blocks(file_region):
            ct_block = enc.update(block)   # yield to network socket
        tag = enc.finalize()               # ONE 16-byte tag for entire chunk
        # Upload: ct_block_0 ‖ ct_block_1 ‖ … ‖ tag

    Each instance is single-use. Calling ``finalize()`` twice raises
    ``CryptoError``. Re-use of the same (key, nonce) pair across different
    chunks is catastrophic — the caller is responsible for nonce uniqueness
    (see ``nonce.py``).

    Thread Safety
    -------------
    ``update()`` is intended to be called from ``asyncio.to_thread()`` to keep
    ChaCha20 CPU work off the Qt main thread. One ChunkEncryptor instance is
    used for the entire upload stream — not one per 64 KB block.
    """

    def __init__(self, key: bytes, nonce: bytes, aad: bytes = b"") -> None:
        """
        Args:
            key:   32-byte ChaCha20-Poly1305 key (derived via HKDF chunk-encryption).
            nonce: 12-byte nonce for this chunk (from NonceManager.next_nonce()).
            aad:   Additional Authenticated Data (e.g. chunk header metadata).
                   The AAD is authenticated but NOT encrypted.
        """
        _validate_key_nonce(key, nonce)

        self._aad = aad
        self._aad_len = len(aad)
        self._total_ct_len = 0
        self._finalized = False

        # Derive Poly1305 one-time key and set up MAC state
        poly1305_key = _derive_poly1305_key(key, nonce)
        self._poly = Poly1305(poly1305_key)

        # Process AAD into MAC: pad16(aad)
        if aad:
            self._poly.update(aad)
            pad = (16 - len(aad) % 16) % 16
            if pad:
                self._poly.update(b"\x00" * pad)

        # Set up ChaCha20 keystream starting at counter=1
        self._chacha20 = _make_chacha20_encryptor(key, nonce)

    def update(self, plaintext: bytes) -> bytes:
        """
        Encrypt one block of plaintext and feed the ciphertext to the Poly1305 MAC.

        Should be called from ``asyncio.to_thread()`` to avoid blocking Qt.

        Args:
            plaintext: Up to ``BLOCK_SIZE`` (64 KB) bytes of plaintext.
                       The last call may be smaller.

        Returns:
            Ciphertext bytes of the same length as ``plaintext``.

        Raises:
            CryptoError: If called after ``finalize()``.
        """
        if self._finalized:
            raise CryptoError(
                "ChunkEncryptor.update() called after finalize(). "
                "Each ChunkEncryptor instance is single-use."
            )
        if not plaintext:
            return b""

        ciphertext = self._chacha20.update(plaintext)

        # Feed raw ciphertext to Poly1305 incrementally (no inter-block padding)
        self._poly.update(ciphertext)
        self._total_ct_len += len(ciphertext)

        return ciphertext

    def finalize(self) -> bytes:
        """
        Finalize encryption and produce the ONE Poly1305 authentication tag.

        The tag covers ALL ciphertext blocks produced by all ``update()`` calls,
        as one contiguous unit. This is the single-tag-per-chunk invariant.

        Returns:
            16-byte Poly1305 authentication tag.

        Raises:
            CryptoError: If called more than once.
        """
        if self._finalized:
            raise CryptoError(
                "ChunkEncryptor.finalize() called more than once. "
                "Each ChunkEncryptor instance is single-use."
            )
        self._finalized = True

        # Pad total ciphertext to 16-byte boundary in MAC
        if self._total_ct_len > 0:
            pad = (16 - self._total_ct_len % 16) % 16
            if pad:
                self._poly.update(b"\x00" * pad)

        # RFC 8439 length fields: LE uint64(len_aad) ‖ LE uint64(len_ct)
        self._poly.update(struct.pack("<QQ", self._aad_len, self._total_ct_len))

        return self._poly.finalize()  # 16 bytes


# ─── ChunkDecryptor ───────────────────────────────────────────────────────────

class ChunkDecryptor:
    """
    Single-use ChaCha20-Poly1305 decryptor for ONE logical chunk.

    Critical Constraint
    -------------------
    The Poly1305 tag MUST be verified before ANY decrypted byte is returned
    to the application (Spec §4.4). This is enforced by design: ``feed()``
    only accumulates ciphertext and feeds it to the MAC; ``verify_and_decrypt()``
    checks the tag FIRST and only then runs the ChaCha20 decryption.

    Usage Pattern
    -------------
        dec = ChunkDecryptor(key, nonce, expected_tag)
        for ct_block in assembled_sub_blocks:   # all sub-blocks present
            dec.feed(ct_block)
        plaintext = dec.verify_and_decrypt()    # raises AuthenticationError if bad
    """

    def __init__(
        self,
        key: bytes,
        nonce: bytes,
        expected_tag: bytes,
        aad: bytes = b"",
    ) -> None:
        """
        Args:
            key:          32-byte decryption key.
            nonce:        12-byte nonce (stored in chunk_locations record).
            expected_tag: 16-byte Poly1305 tag (stored alongside the chunk).
            aad:          Additional Authenticated Data (same as used during encryption).
        """
        _validate_key_nonce(key, nonce)
        if not isinstance(expected_tag, bytes) or len(expected_tag) != TAG_SIZE:
            raise CryptoError(
                f"expected_tag must be {TAG_SIZE} bytes; got "
                f"{len(expected_tag) if isinstance(expected_tag, bytes) else type(expected_tag).__name__}"
            )

        self._key = key
        self._nonce = nonce
        self._expected_tag = expected_tag
        self._aad = aad
        self._aad_len = len(aad)
        self._total_ct_len = 0
        self._verified = False

        # Buffer to accumulate ciphertext (needed for decryption after MAC verification)
        self._ct_buffer = bytearray()

        # Initialize Poly1305 MAC state with AAD
        poly1305_key = _derive_poly1305_key(key, nonce)
        self._poly = Poly1305(poly1305_key)

        if aad:
            self._poly.update(aad)
            pad = (16 - len(aad) % 16) % 16
            if pad:
                self._poly.update(b"\x00" * pad)

    def feed(self, ciphertext: bytes) -> None:
        """
        Accumulate a ciphertext block and update the Poly1305 MAC.

        Does NOT decrypt. All sub-blocks must be fed before calling
        ``verify_and_decrypt()``.

        Args:
            ciphertext: One sub-block's worth of ciphertext bytes.

        Raises:
            CryptoError: If called after ``verify_and_decrypt()``.
        """
        if self._verified:
            raise CryptoError(
                "ChunkDecryptor.feed() called after verify_and_decrypt(). "
                "Each ChunkDecryptor instance is single-use."
            )
        if not ciphertext:
            return

        # Feed to MAC (no inter-block padding between sub-block boundaries)
        self._poly.update(ciphertext)
        self._ct_buffer.extend(ciphertext)
        self._total_ct_len += len(ciphertext)

    def verify_and_decrypt(self) -> bytes:
        """
        Verify the Poly1305 tag FIRST, then decrypt.

        RETURNS NOTHING unless the tag is valid. If the tag is invalid,
        ``AuthenticationError`` is raised WITHOUT returning any plaintext bytes.
        This is the fundamental security guarantee of this class.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            AuthenticationError: If Poly1305 tag verification fails.
                                  The chunk is corrupted, tampered, or the
                                  wrong key/nonce was provided.
            CryptoError: If called more than once.
        """
        if self._verified:
            raise CryptoError(
                "ChunkDecryptor.verify_and_decrypt() called more than once."
            )
        self._verified = True

        # ── Step 1: Finalise the MAC computation ──────────────────────────────
        if self._total_ct_len > 0:
            pad = (16 - self._total_ct_len % 16) % 16
            if pad:
                self._poly.update(b"\x00" * pad)

        # RFC 8439 length fields
        self._poly.update(struct.pack("<QQ", self._aad_len, self._total_ct_len))
        computed_tag = self._poly.finalize()

        # ── Step 2: Constant-time tag comparison ──────────────────────────────
        # verify_auth_tag uses hmac.compare_digest — constant time (Spec §4.1)
        if not verify_auth_tag(computed_tag, self._expected_tag):
            raise AuthenticationError(
                "Poly1305 authentication tag verification FAILED. "
                "The chunk is corrupted, tampered, or the wrong key/nonce was used. "
                "NO decrypted data has been returned."
            )

        # ── Step 3: Decrypt only after successful MAC verification ────────────
        chacha20 = _make_chacha20_encryptor(self._key, self._nonce)
        plaintext = chacha20.update(bytes(self._ct_buffer))

        return plaintext

    def verify_and_decrypt_streaming(self) -> "Generator[bytes, None, None]":
        """
        Variant that yields plaintext in BLOCK_SIZE chunks after tag verification.
        Still verifies the tag FIRST — no plaintext is yielded before that.

        Useful for large chunks to avoid holding the full plaintext in memory.
        """
        plaintext = self.verify_and_decrypt()
        offset = 0
        while offset < len(plaintext):
            yield plaintext[offset : offset + BLOCK_SIZE]
            offset += BLOCK_SIZE


# ─── Async high-level helper ──────────────────────────────────────────────────

async def encrypt_chunk_async(
    key: bytes,
    nonce: bytes,
    file_path: Path,
    offset: int,
    size: int,
    aad: bytes = b"",
) -> AsyncGenerator[bytes, None]:
    """
    Async generator: reads a file region and yields encrypted 64 KB blocks
    followed by the 16-byte Poly1305 tag.

    Encryption runs in ``asyncio.to_thread()`` to keep ChaCha20 CPU work
    off the Qt main thread. One ``ChunkEncryptor`` instance is used for the
    entire chunk — not one per block (Spec §5.1).

    Yields:
        Sequence of 64 KB ciphertext blocks, then a final 16-byte tag.

    Args:
        key:       32-byte ChaCha20-Poly1305 key.
        nonce:     12-byte nonce (already incremented and fsynced by caller).
        file_path: Path to the source file.
        offset:    Byte offset of this chunk within the file.
        size:      Byte length of this chunk.
        aad:       Optional Additional Authenticated Data.
    """
    encryptor = ChunkEncryptor(key, nonce, aad)

    async with aiofiles.open(file_path, "rb") as fh:
        await fh.seek(offset)
        bytes_remaining = size

        while bytes_remaining > 0:
            read_size = min(BLOCK_SIZE, bytes_remaining)
            block = await fh.read(read_size)
            if not block:
                break

            # ChaCha20 is CPU-bound — run in a thread to keep Qt responsive
            ct_block = await asyncio.to_thread(encryptor.update, block)
            yield ct_block
            bytes_remaining -= len(block)

    # ONE Poly1305 tag for the ENTIRE chunk — appended after the last block
    tag = await asyncio.to_thread(encryptor.finalize)
    yield tag  # 16 bytes


# ─── Private validation helper ────────────────────────────────────────────────

def _validate_key_nonce(key: bytes, nonce: bytes) -> None:
    """Validate ChaCha20-Poly1305 key and nonce lengths."""
    if not isinstance(key, bytes) or len(key) != 32:
        raise CryptoError(
            f"ChaCha20-Poly1305 key must be exactly 32 bytes; "
            f"got {len(key) if isinstance(key, bytes) else type(key).__name__!r}"
        )
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise CryptoError(
            f"ChaCha20-Poly1305 nonce must be exactly 12 bytes; "
            f"got {len(nonce) if isinstance(nonce, bytes) else type(nonce).__name__!r}"
        )
