"""Tests for scrypt+AES-256-GCM disaster-recovery vault backup, push, and full restore."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from banoss.app import create_app
from banoss.backup import restore_vault_bytes
from banoss.config import Settings


def test_vault_backup_push_and_full_gateway_restore(tmp_path: Path):
    store_dir = tmp_path / "store"
    src_data = tmp_path / "data_src"
    cfg = Settings(
        data_dir=src_data,
        admin_token="adm-secret-1",
    )
    app = create_app(cfg)

    secret_payload = b"top-secret-dataset-bytes-0123456789"
    with TestClient(app) as client:
        client.post("/api/admin/login", json={"token": "adm-secret-1"}).raise_for_status()
        bk = client.post(
            "/api/admin/backends",
            json={"name": "node-a", "protocol": "local", "base_path": str(store_dir)},
        ).json()["backend"]
        usr = client.post(
            "/api/admin/users",
            json={"username": "alice", "encryption_enabled": True},
        ).json()["user"]
        client.post(
            "/api/admin/bindings",
            json={"user_id": usr["id"], "backend_id": bk["id"], "priority": 1},
        ).raise_for_status()

        # Login user and upload encrypted object
        client.post(
            "/api/console/login",
            json={"access_key": usr["access_key"], "secret_key": usr["secret_key"]},
        ).raise_for_status()
        client.post("/api/console/buckets", json={"name": "vault-test"}).raise_for_status()
        client.post(
            "/api/console/buckets/vault-test/upload?key=secret.bin",
            content=secret_payload,
        ).raise_for_status()

        # Download encrypted vault
        passphrase = "correct horse battery staple 2026"
        dl = client.post("/api/admin/backup/download", json={"passphrase": passphrase})
        assert dl.status_code == 200
        vault_bytes = dl.content
        assert vault_bytes.startswith(b"BANOSSV1")
        assert secret_payload not in vault_bytes

        # Push encrypted vault to backend
        push = client.post(
            "/api/admin/backup/push",
            json={
                "passphrase": passphrase,
                "backend_id": bk["id"],
                "remote_path": ".banoss_backup/latest.vault",
            },
        )
        assert push.status_code == 200
        pushed_file = store_dir / ".banoss_backup" / "latest.vault"
        assert pushed_file.exists()

    # Wrong passphrase fails decryption
    dst_data = tmp_path / "data_restored"
    with pytest.raises(InvalidTag):
        restore_vault_bytes(pushed_file.read_bytes(), "wrong-passphrase-123", dst_data)

    # Restore from pushed vault into clean data directory
    restored_files = restore_vault_bytes(pushed_file.read_bytes(), passphrase, dst_data)
    assert any(p.endswith("banoss.db") for p in restored_files)
    assert any(p.endswith(".master.key") for p in restored_files)

    # Boot brand-new app instance from restored data_dir and verify decryption works
    restored_app = create_app(Settings(data_dir=dst_data))
    with TestClient(restored_app) as restored_client:
        restored_client.post(
            "/api/console/login",
            json={"access_key": usr["access_key"], "secret_key": usr["secret_key"]},
        ).raise_for_status()
        got = restored_client.get(
            "/api/console/buckets/vault-test/objects/download?key=secret.bin"
        )
        assert got.status_code == 200
        assert got.content == secret_payload


def test_main_asgi_entrypoint_imports():
    import main

    assert main.app is not None
