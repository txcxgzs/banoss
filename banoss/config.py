"""Application configuration and auto-managed secret bootstrap."""

from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for the BanOSS gateway."""

    model_config = SettingsConfigDict(
        env_prefix="BANOSS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = "0.0.0.0"
    port: int = 9000
    data_dir: Path = Path("./data")
    db_path: Optional[Path] = None
    master_key: Optional[str] = None
    admin_token: Optional[str] = None
    chunk_size: int = 1024 * 1024  # 1 MiB plaintext per encrypted chunk
    sftp_idle_timeout: int = 60
    base_domains: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])
    region: str = "us-east-1"
    clock_skew_seconds: int = 900

    def resolve_db_path(self) -> Path:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.db_path or (self.data_dir / "banoss.db")

    def resolve_master_key_bytes(self) -> bytes:
        """Load or bootstrap a 32-byte AES-256 master key (KEK)."""
        raw = self.master_key
        key_file = self.data_dir / ".master.key"
        if not raw:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            if key_file.exists():
                raw = key_file.read_text(encoding="utf-8").strip()
            else:
                raw = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
                key_file.write_text(raw, encoding="utf-8")
                try:
                    os.chmod(key_file, 0o600)
                except OSError:
                    pass

        return _decode_key_material(raw)

    def resolve_admin_token(self) -> str:
        """Load or bootstrap the admin console bearer token."""
        if self.admin_token:
            return self.admin_token.strip()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        token_file = self.data_dir / ".admin.token"
        if token_file.exists():
            return token_file.read_text(encoding="utf-8").strip()
        token = secrets.token_urlsafe(32)
        token_file.write_text(token, encoding="utf-8")
        try:
            os.chmod(token_file, 0o600)
        except OSError:
            pass
        return token


def _decode_key_material(raw: str) -> bytes:
    """Decode base64/hex or derive a 32-byte key if a passphrase is provided."""
    stripped = raw.strip()
    if len(stripped) == 64:
        try:
            return bytes.fromhex(stripped)
        except ValueError:
            pass
    try:
        padded = stripped + "=" * (-len(stripped) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass
    import hashlib

    return hashlib.sha256(stripped.encode("utf-8")).digest()
