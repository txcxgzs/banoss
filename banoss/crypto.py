"""Envelope and chunked AES-256-GCM encryption for secrets and stored objects."""

from __future__ import annotations

import base64
import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

GCM_TAG_SIZE = 16
GCM_NONCE_SIZE = 12
NONCE_PREFIX_SIZE = 4


@dataclass(frozen=True)
class SegmentCryptoMeta:
    """Per-segment encryption metadata generated at write time."""

    dek: bytes
    wrapped_dek: str
    nonce_prefix: bytes
    nonce_prefix_b64: str


class CryptoService:
    """Handles secret-at-rest wrapping and random-access chunked object encryption."""

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != 32:
            raise ValueError("Master key must be exactly 32 bytes for AES-256-GCM")
        self._kek = AESGCM(master_key)

    def encrypt_secret(self, plaintext: str) -> str:
        """Encrypt a sensitive credential (AK/SK/SSH key/password) for SQLite storage."""
        if plaintext == "":
            return ""
        nonce = os.urandom(GCM_NONCE_SIZE)
        ct = self._kek.encrypt(nonce, plaintext.encode("utf-8"), b"banoss-secret-v1")
        return base64.urlsafe_b64encode(nonce + ct).decode("ascii")

    def decrypt_secret(self, token: str) -> str:
        """Decrypt a credential stored in SQLite."""
        if token == "":
            return ""
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        nonce, ct = raw[:GCM_NONCE_SIZE], raw[GCM_NONCE_SIZE:]
        return self._kek.decrypt(nonce, ct, b"banoss-secret-v1").decode("utf-8")

    def new_segment_key(self, segment_id: str) -> SegmentCryptoMeta:
        """Generate and wrap a fresh DEK and nonce prefix for an object segment."""
        dek = os.urandom(32)
        nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)
        wrap_nonce = os.urandom(GCM_NONCE_SIZE)
        aad = f"dek:{segment_id}".encode("utf-8")
        wrapped = wrap_nonce + self._kek.encrypt(wrap_nonce, dek, aad)
        return SegmentCryptoMeta(
            dek=dek,
            wrapped_dek=base64.urlsafe_b64encode(wrapped).decode("ascii"),
            nonce_prefix=nonce_prefix,
            nonce_prefix_b64=base64.urlsafe_b64encode(nonce_prefix).decode("ascii"),
        )

    def unwrap_dek(self, segment_id: str, wrapped_dek: str) -> bytes:
        """Unwrap a segment's DEK using its segment ID as associated data."""
        raw = base64.urlsafe_b64decode(wrapped_dek.encode("ascii"))
        wrap_nonce, ct = raw[:GCM_NONCE_SIZE], raw[GCM_NONCE_SIZE:]
        aad = f"dek:{segment_id}".encode("utf-8")
        return self._kek.decrypt(wrap_nonce, ct, aad)

    @staticmethod
    def encrypt_chunk(
        dek: bytes,
        nonce_prefix: bytes,
        segment_id: str,
        chunk_index: int,
        plaintext: bytes,
    ) -> bytes:
        """Encrypt a single plaintext chunk with deterministic non-repeating nonce."""
        nonce = nonce_prefix + struct.pack(">Q", chunk_index)
        aad = f"{segment_id}:{chunk_index}".encode("utf-8")
        return AESGCM(dek).encrypt(nonce, plaintext, aad)

    @staticmethod
    def decrypt_chunk(
        dek: bytes,
        nonce_prefix: bytes,
        segment_id: str,
        chunk_index: int,
        ciphertext: bytes,
    ) -> bytes:
        """Decrypt and authenticate a single chunk."""
        nonce = nonce_prefix + struct.pack(">Q", chunk_index)
        aad = f"{segment_id}:{chunk_index}".encode("utf-8")
        return AESGCM(dek).decrypt(nonce, ciphertext, aad)


def encrypted_size(plain_size: int, chunk_size: int) -> int:
    """Compute the exact remote byte length of an encrypted segment."""
    if plain_size <= 0:
        return 0
    num_chunks = (plain_size + chunk_size - 1) // chunk_size
    return plain_size + num_chunks * GCM_TAG_SIZE


def remote_chunk_span(
    plain_start: int,
    plain_end_inclusive: int,
    plain_total: int,
    chunk_size: int,
) -> tuple[int, int, int, int]:
    """Compute (first_chunk, last_chunk, remote_offset, remote_length) for a byte range."""
    if plain_total <= 0 or plain_start > plain_end_inclusive:
        return 0, -1, 0, 0
    first_chunk = plain_start // chunk_size
    last_chunk = plain_end_inclusive // chunk_size
    enc_stride = chunk_size + GCM_TAG_SIZE
    remote_offset = first_chunk * enc_stride
    last_chunk_plain_len = min(chunk_size, plain_total - last_chunk * chunk_size)
    remote_end_exclusive = last_chunk * enc_stride + last_chunk_plain_len + GCM_TAG_SIZE
    return first_chunk, last_chunk, remote_offset, remote_end_exclusive - remote_offset
