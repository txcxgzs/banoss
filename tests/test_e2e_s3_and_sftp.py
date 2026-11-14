"""End-to-end integration tests with a real SFTP server, live Uvicorn HTTP gateway, and boto3."""

from __future__ import annotations

import asyncio
import hashlib
import os
import socket
import threading
import time
from pathlib import Path

import asyncssh
import boto3
import httpx
import pytest
import uvicorn
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from banoss.app import create_app
from banoss.config import Settings
from banoss.crypto import encrypted_size


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _TestSSHServer(asyncssh.SSHServer):
    def __init__(self, expected_pubkey: asyncssh.SSHKey) -> None:
        self._pubkey = expected_pubkey

    def begin_auth(self, username: str) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        return username == "scnet" and key == self._pubkey


@pytest.fixture()
def live_env(tmp_path: Path):
    """Spin up an asyncssh SFTP server and live BanOSS uvicorn HTTP server."""
    sftp_root_1 = tmp_path / "sftp_node_1"
    sftp_root_2 = tmp_path / "sftp_node_2"
    local_root_3 = tmp_path / "local_node_3"
    sftp_root_1.mkdir()
    sftp_root_2.mkdir()
    local_root_3.mkdir()

    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    client_priv_pem = client_key.export_private_key().decode("utf-8")
    client_pub = client_key.export_public_key()
    expected_pub = asyncssh.import_public_key(client_pub)

    sftp_port = _free_port()
    sftp_ready = threading.Event()
    sftp_loop_holder: dict[str, asyncio.AbstractEventLoop] = {}
    sftp_server_holder: dict[str, asyncssh.SSHAcceptor] = {}

    def _run_sftp() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        sftp_loop_holder["loop"] = loop

        async def _start():
            srv = await asyncssh.listen(
                "127.0.0.1",
                sftp_port,
                server_host_keys=[host_key],
                server_factory=lambda: _TestSSHServer(expected_pub),
                sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=str(tmp_path)),
            )
            sftp_server_holder["srv"] = srv
            sftp_ready.set()

        loop.run_until_complete(_start())
        loop.run_forever()

    sftp_thread = threading.Thread(target=_run_sftp, daemon=True)
    sftp_thread.start()
    assert sftp_ready.wait(timeout=10), "Test SFTP server failed to start"

    gw_port = _free_port()
    settings = Settings(
        host="127.0.0.1",
        port=gw_port,
        data_dir=tmp_path / "gw_data",
        admin_token="test-admin-token-123",
        chunk_size=1024,  # 1 KiB chunks in test so multi-chunk & range math get thoroughly exercised
        sftp_idle_timeout=2,
    )
    app = create_app(settings)
    uvi_config = uvicorn.Config(app, host="127.0.0.1", port=gw_port, log_level="warning")
    uvi_server = uvicorn.Server(uvi_config)
    gw_thread = threading.Thread(target=uvi_server.run, daemon=True)
    gw_thread.start()

    endpoint = f"http://127.0.0.1:{gw_port}"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"{endpoint}/healthz", timeout=1.0)
            if r.status_code == 200:
                break
        except Exception:
            time.sleep(0.1)
    else:
        raise RuntimeError("BanOSS server failed to become healthy")

    try:
        yield {
            "endpoint": endpoint,
            "admin_token": "test-admin-token-123",
            "sftp_port": sftp_port,
            "client_priv_pem": client_priv_pem,
            "sftp_root_1": sftp_root_1,
            "sftp_root_2": sftp_root_2,
            "local_root_3": local_root_3,
            "chunk_size": 1024,
            "storage": app.state.storage,
            "crypto": app.state.crypto,
        }
    finally:
        uvi_server.should_exit = True
        gw_thread.join(timeout=5)
        loop = sftp_loop_holder.get("loop")
        srv = sftp_server_holder.get("srv")
        if loop and srv:
            loop.call_soon_threadsafe(srv.close)
            loop.call_soon_threadsafe(loop.stop)
        sftp_thread.join(timeout=5)


def test_multi_user_sftp_s3_lifecycle(live_env):
    ep = live_env["endpoint"]
    headers = {"Authorization": f"Bearer {live_env['admin_token']}"}
    client = httpx.Client(base_url=ep, headers=headers, timeout=15.0)

    # 1. Create 2 SFTP backends (pointing to real asyncssh SFTP server) and 1 local backend
    b1 = client.post(
        "/api/admin/backends",
        json={
            "name": "scnet-sftp-1",
            "protocol": "sftp",
            "host": "127.0.0.1",
            "port": live_env["sftp_port"],
            "username": "scnet",
            "auth_type": "key",
            "credential": live_env["client_priv_pem"],
            "base_path": "/sftp_node_1",
            "max_connections": 2,
            "idle_timeout_sec": 2,
            "quota_bytes": 5000,  # Tight quota to test automatic failover to scnet-sftp-2
        },
    ).json()["backend"]

    b2 = client.post(
        "/api/admin/backends",
        json={
            "name": "scnet-sftp-2",
            "protocol": "sftp",
            "host": "127.0.0.1",
            "port": live_env["sftp_port"],
            "username": "scnet",
            "auth_type": "key",
            "credential": live_env["client_priv_pem"],
            "base_path": "/sftp_node_2",
            "max_connections": 2,
            "idle_timeout_sec": 2,
            "quota_bytes": 0,
        },
    ).json()["backend"]

    b3 = client.post(
        "/api/admin/backends",
        json={
            "name": "local-bob",
            "protocol": "local",
            "base_path": str(live_env["local_root_3"]),
            "quota_bytes": 0,
        },
    ).json()["backend"]

    # Probe real SFTP backend
    probe = client.post(f"/api/admin/backends/{b1['id']}/probe").json()
    assert probe["ok"] is True

    # 2. Create two users (Alice & Bob) and bind them to separate backends
    alice = client.post(
        "/api/admin/users",
        json={"username": "alice", "encryption_enabled": True},
    ).json()["user"]
    bob = client.post(
        "/api/admin/users",
        json={"username": "bob", "encryption_enabled": True},
    ).json()["user"]

    client.post(
        "/api/admin/bindings",
        json={"user_id": alice["id"], "backend_id": b1["id"], "priority": 10},
    ).raise_for_status()
    client.post(
        "/api/admin/bindings",
        json={"user_id": alice["id"], "backend_id": b2["id"], "priority": 20},
    ).raise_for_status()
    client.post(
        "/api/admin/bindings",
        json={"user_id": bob["id"], "backend_id": b3["id"], "priority": 10},
    ).raise_for_status()

    s3_alice = boto3.client(
        "s3",
        endpoint_url=ep,
        aws_access_key_id=alice["access_key"],
        aws_secret_access_key=alice["secret_key"],
        region_name="us-east-1",
        config=BotoConfig(s3={"addressing_style": "path"}),
    )
    s3_bob = boto3.client(
        "s3",
        endpoint_url=ep,
        aws_access_key_id=bob["access_key"],
        aws_secret_access_key=bob["secret_key"],
        region_name="us-east-1",
        config=BotoConfig(s3={"addressing_style": "path"}),
    )

    # 3. Bucket isolation
    s3_alice.create_bucket(Bucket="alice-box")
    assert [b["Name"] for b in s3_alice.list_buckets()["Buckets"]] == ["alice-box"]
    assert s3_bob.list_buckets()["Buckets"] == []
    with pytest.raises(ClientError) as exc_info:
        s3_bob.list_objects_v2(Bucket="alice-box")
    assert exc_info.value.response["Error"]["Code"] == "AccessDenied"

    # 4. PutObject on SFTP backend 1 + verify encrypted at rest + Range requests
    payload1 = b"A" * 500 + os.urandom(2000) + b"END_MARKER"  # 2510 bytes (3 chunks of 1024)
    s3_alice.put_object(
        Bucket="alice-box",
        Key="dir/test.bin",
        Body=payload1,
        ContentType="application/octet-stream",
        Metadata={"author": "alice"},
    )

    # Verify remote file on sftp_node_1 is encrypted (not equal to plaintext and has 3*16 tag bytes)
    stored_files_1 = [p for p in live_env["sftp_root_1"].rglob("*") if p.is_file()]
    assert len(stored_files_1) == 1
    raw_disk = stored_files_1[0].read_bytes()
    assert raw_disk != payload1
    assert b"END_MARKER" not in raw_disk
    assert len(raw_disk) == encrypted_size(len(payload1), live_env["chunk_size"])

    # Full GET + HEAD
    head = s3_alice.head_object(Bucket="alice-box", Key="dir/test.bin")
    assert head["ContentLength"] == len(payload1)
    assert head["Metadata"]["author"] == "alice"
    got_full = s3_alice.get_object(Bucket="alice-box", Key="dir/test.bin")["Body"].read()
    assert got_full == payload1

    # Range GET across chunk boundaries
    got_range = s3_alice.get_object(
        Bucket="alice-box", Key="dir/test.bin", Range="bytes=900-2100"
    )["Body"].read()
    assert got_range == payload1[900:2101]

    # Suffix Range GET
    got_suffix = s3_alice.get_object(
        Bucket="alice-box", Key="dir/test.bin", Range="bytes=-10"
    )["Body"].read()
    assert got_suffix == b"END_MARKER"

    # Presigned URL GET (both default SigV2 and explicit SigV4)
    presigned_v2 = s3_alice.generate_presigned_url(
        "get_object", Params={"Bucket": "alice-box", "Key": "dir/test.bin"}, ExpiresIn=120
    )
    pre_resp_v2 = httpx.get(presigned_v2, timeout=10.0)
    assert pre_resp_v2.status_code == 200
    assert pre_resp_v2.content == payload1

    s3_alice_v4 = boto3.client(
        "s3",
        endpoint_url=ep,
        aws_access_key_id=alice["access_key"],
        aws_secret_access_key=alice["secret_key"],
        region_name="us-east-1",
        config=BotoConfig(signature_version="s3v4", s3={"addressing_style": "path"}),
    )
    presigned_v4 = s3_alice_v4.generate_presigned_url(
        "get_object", Params={"Bucket": "alice-box", "Key": "dir/test.bin"}, ExpiresIn=120
    )
    pre_resp_v4 = httpx.get(presigned_v4, timeout=10.0)
    assert pre_resp_v4.status_code == 200
    assert pre_resp_v4.content == payload1

    # 5. Quota failover: next 4000-byte upload exceeds b1's 5000B cap -> routes to scnet-sftp-2!
    payload2 = os.urandom(4000)
    s3_alice.put_object(Bucket="alice-box", Key="dir/overflow.bin", Body=payload2)
    stored_files_2 = [p for p in live_env["sftp_root_2"].rglob("*") if p.is_file()]
    assert len(stored_files_2) == 1
    assert s3_alice.get_object(Bucket="alice-box", Key="dir/overflow.bin")["Body"].read() == payload2

    # 6. ListObjectsV2 prefix + delimiter + pagination
    s3_alice.put_object(Bucket="alice-box", Key="a.txt", Body=b"hello")
    listed = s3_alice.list_objects_v2(Bucket="alice-box", Delimiter="/")
    assert [c["Key"] for c in listed["Contents"]] == ["a.txt"]
    assert [cp["Prefix"] for cp in listed["CommonPrefixes"]] == ["dir/"]

    # 7. Multipart Upload + cross-segment Range + CopyObject + ref-counted Delete
    mp = s3_alice.create_multipart_upload(Bucket="alice-box", Key="big/multi.bin")
    upload_id = mp["UploadId"]
    part1 = os.urandom(1500)  # intentionally unaligned to 1024 chunk_size
    part2 = os.urandom(1700)
    p1_res = s3_alice.upload_part(
        Bucket="alice-box", Key="big/multi.bin", UploadId=upload_id, PartNumber=1, Body=part1
    )
    p2_res = s3_alice.upload_part(
        Bucket="alice-box", Key="big/multi.bin", UploadId=upload_id, PartNumber=2, Body=part2
    )
    parts_list = s3_alice.list_parts(Bucket="alice-box", Key="big/multi.bin", UploadId=upload_id)
    assert len(parts_list["Parts"]) == 2
    s3_alice.complete_multipart_upload(
        Bucket="alice-box",
        Key="big/multi.bin",
        UploadId=upload_id,
        MultipartUpload={
            "Parts": [
                {"PartNumber": 1, "ETag": p1_res["ETag"]},
                {"PartNumber": 2, "ETag": p2_res["ETag"]},
            ]
        },
    )
    combined = part1 + part2
    assert s3_alice.get_object(Bucket="alice-box", Key="big/multi.bin")["Body"].read() == combined
    # Cross-segment Range read spanning part 1 -> part 2!
    cross_slice = s3_alice.get_object(
        Bucket="alice-box", Key="big/multi.bin", Range="bytes=1400-1650"
    )["Body"].read()
    assert cross_slice == combined[1400:1651]

    # Zero-copy CopyObject + source delete does not break destination
    s3_alice.copy_object(
        Bucket="alice-box",
        CopySource={"Bucket": "alice-box", "Key": "big/multi.bin"},
        Key="big/multi-copy.bin",
    )
    s3_alice.delete_object(Bucket="alice-box", Key="big/multi.bin")
    assert s3_alice.get_object(Bucket="alice-box", Key="big/multi-copy.bin")["Body"].read() == combined

    # Batch delete remaining objects and delete bucket
    s3_alice.delete_objects(
        Bucket="alice-box",
        Delete={
            "Objects": [
                {"Key": "a.txt"},
                {"Key": "dir/test.bin"},
                {"Key": "dir/overflow.bin"},
                {"Key": "big/multi-copy.bin"},
            ]
        },
    )
    s3_alice.delete_bucket(Bucket="alice-box")
    assert s3_alice.list_buckets()["Buckets"] == []

    # Verify all remote encrypted files were garbage-collected
    assert [p for p in live_env["sftp_root_1"].rglob("*") if p.is_file()] == []
    assert [p for p in live_env["sftp_root_2"].rglob("*") if p.is_file()] == []


async def test_sftp_dir_cache_and_self_healing(live_env):
    import shutil
    from banoss.storage import StorageManager, make_segment_rel_path

    crypto = live_env["crypto"]
    storage = StorageManager(db=None, crypto=crypto, default_chunk_size=1024)  # type: ignore[arg-type]
    backend = {
        "id": "cache-test-backend",
        "protocol": "sftp",
        "host": "127.0.0.1",
        "port": live_env["sftp_port"],
        "username": "scnet",
        "auth_type": "key",
        "credential_enc": crypto.encrypt_secret(live_env["client_priv_pem"]),
        "passphrase_enc": "",
        "base_path": "/sftp_node_1",
        "max_connections": 2,
        "idle_timeout_sec": 30,
        "is_active": True,
    }

    async def _bytes():
        yield b"fast-upload-payload"

    try:
        rel = make_segment_rel_path("aa112233-4455-6677-8899-00aabbccdde0")
        assert rel == "objs/aa/aa112233-4455-6677-8899-00aabbccdde0"
        await storage.write_stream(backend, rel, _bytes(), segment_id=rel, encrypt=True)
        assert ("cache-test-backend", "/sftp_node_1/objs/aa") in storage._known_dirs

        # Simulate external removal of the cached shard dir; write_stream must auto-heal and succeed
        shutil.rmtree(live_env["sftp_root_1"] / "objs" / "aa")
        await storage.write_stream(backend, rel, _bytes(), segment_id=rel, encrypt=True)
        assert (live_env["sftp_root_1"] / "objs" / "aa" / "aa112233-4455-6677-8899-00aabbccdde0").is_file()
        await storage.invalidate_backend_pool("cache-test-backend")
        assert all(bid != "cache-test-backend" for bid, _ in storage._known_dirs)

        # Transient TimeoutError on first SSH connect attempt must retry cleanly instead of 500
        calls = {"n": 0}
        orig_open = storage._open_sftp

        async def _flaky_open(bk):
            calls["n"] += 1
            if calls["n"] == 1:
                raise TimeoutError("simulated handshake jitter")
            return await orig_open(bk)

        storage._open_sftp = _flaky_open  # type: ignore[method-assign]
        try:
            async with storage.acquire_sftp(backend) as sftp:
                assert await sftp.isdir("/sftp_node_1")
            assert calls["n"] == 2
        finally:
            storage._open_sftp = orig_open  # type: ignore[method-assign]
    finally:
        await storage.stop()
