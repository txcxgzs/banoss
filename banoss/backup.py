"""Encrypted disaster-recovery vault backup and restore for banoss.db + .master.key + .admin.token."""

from __future__ import annotations

import io
import os
import sqlite3
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VAULT_MAGIC = b"BANOSSV1"
SALT_SIZE = 16
NONCE_SIZE = 12
SCRYPT_N = 2**16  # 64 MiB work factor: strong offline resistance while friendly to 1GB VPS
SCRYPT_R = 8
SCRYPT_P = 1


def _derive_vault_key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 8:
        raise ValueError("Passphrase must be at least 8 characters")
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def snapshot_sqlite_bytes(db_path: Path) -> bytes:
    """Create a consistent SQLite snapshot using the online backup API (WAL-safe)."""
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")
    with tempfile.TemporaryDirectory() as tmpdir:
        snap_path = Path(tmpdir) / "banoss.db"
        src = sqlite3.connect(db_path)
        dst = sqlite3.connect(snap_path)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        return snap_path.read_bytes()


def create_vault_bytes(data_dir: Path, db_path: Path, passphrase: str) -> bytes:
    """Bundle SQLite snapshot, .master.key, and .admin.token into an scrypt+AES-256-GCM encrypted vault."""
    db_bytes = snapshot_sqlite_bytes(db_path)
    master_key_file = data_dir / ".master.key"
    admin_token_file = data_dir / ".admin.token"

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        _add_bytes_to_tar(tar, "banoss.db", db_bytes, mode=0o600)
        if master_key_file.exists():
            _add_bytes_to_tar(tar, ".master.key", master_key_file.read_bytes(), mode=0o600)
        if admin_token_file.exists():
            _add_bytes_to_tar(tar, ".admin.token", admin_token_file.read_bytes(), mode=0o600)

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_vault_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, buf.getvalue(), VAULT_MAGIC)
    return VAULT_MAGIC + salt + nonce + ciphertext


def restore_vault_bytes(
    vault_bytes: bytes,
    passphrase: str,
    target_data_dir: Path,
    target_db_path: Optional[Path] = None,
) -> list[str]:
    """Decrypt a vault archive and restore banoss.db, .master.key, and .admin.token safely."""
    header_len = len(VAULT_MAGIC) + SALT_SIZE + NONCE_SIZE
    if len(vault_bytes) <= header_len or not vault_bytes.startswith(VAULT_MAGIC):
        raise ValueError("Invalid BanOSS vault file format")

    salt = vault_bytes[len(VAULT_MAGIC) : len(VAULT_MAGIC) + SALT_SIZE]
    nonce = vault_bytes[len(VAULT_MAGIC) + SALT_SIZE : header_len]
    ciphertext = vault_bytes[header_len:]

    key = _derive_vault_key(passphrase, salt)
    plain_tar = AESGCM(key).decrypt(nonce, ciphertext, VAULT_MAGIC)

    target_data_dir.mkdir(parents=True, exist_ok=True)
    allowed_names = {"banoss.db", ".master.key", ".admin.token"}
    restored: list[str] = []

    with tarfile.open(fileobj=io.BytesIO(plain_tar), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or member.name not in allowed_names:
                continue
            f = tar.extractfile(member)
            if f is None:
                continue
            data = f.read()
            if member.name == "banoss.db" and target_db_path is not None:
                out_path = target_db_path
            else:
                out_path = target_data_dir / member.name
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(data)
            try:
                os.chmod(out_path, 0o600)
            except OSError:
                pass
            restored.append(str(out_path))

    return restored


def _add_bytes_to_tar(tar: tarfile.TarFile, name: str, data: bytes, mode: int = 0o600) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mode = mode
    tar.addfile(info, io.BytesIO(data))
