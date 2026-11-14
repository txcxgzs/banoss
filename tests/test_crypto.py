"""Unit tests for envelope secrets and chunked AES-256-GCM encryption."""

import os
import pytest
from cryptography.exceptions import InvalidTag

from banoss.crypto import CryptoService, encrypted_size, remote_chunk_span


def test_secret_roundtrip():
    cs = CryptoService(os.urandom(32))
    secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\n-----END OPENSSH PRIVATE KEY-----"
    tok = cs.encrypt_secret(secret)
    assert tok != secret
    assert cs.decrypt_secret(tok) == secret
    assert cs.encrypt_secret("") == ""
    assert cs.decrypt_secret("") == ""


def test_chunk_encryption_and_range_math():
    cs = CryptoService(os.urandom(32))
    seg_id = "objs/aa/bb/test-uuid"
    meta = cs.new_segment_key(seg_id)
    dek = cs.unwrap_dek(seg_id, meta.wrapped_dek)
    assert dek == meta.dek

    chunk_size = 64
    plaintext = os.urandom(150)  # 64 + 64 + 22 bytes (3 chunks)
    chunks = [
        cs.encrypt_chunk(dek, meta.nonce_prefix, seg_id, idx, plaintext[i : i + chunk_size])
        for idx, i in enumerate(range(0, len(plaintext), chunk_size))
    ]
    blob = b"".join(chunks)
    assert len(blob) == encrypted_size(len(plaintext), chunk_size)

    # Range crossing chunk 0 -> chunk 2
    first, last, r_off, r_len = remote_chunk_span(50, 140, len(plaintext), chunk_size)
    assert (first, last) == (0, 2)
    assert r_off == 0
    assert r_len == len(blob)

    # Range starting in chunk 1 -> chunk 2
    first2, last2, r_off2, r_len2 = remote_chunk_span(70, 135, len(plaintext), chunk_size)
    assert (first2, last2) == (1, 2)
    assert r_off2 == chunk_size + 16
    assert r_len2 == (64 + 16) + (22 + 16)

    # Tamper detection
    bad_chunk = bytearray(chunks[1])
    bad_chunk[10] ^= 0xFF
    with pytest.raises(InvalidTag):
        cs.decrypt_chunk(dek, meta.nonce_prefix, seg_id, 1, bytes(bad_chunk))
