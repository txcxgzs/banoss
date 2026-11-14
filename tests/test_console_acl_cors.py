"""Tests for Bucket ACL (public-read/private), CORS, and User Self-Service OSS Console (/console)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from banoss.app import create_app
from banoss.config import Settings


def test_console_portal_acl_cors_and_folder_ops(tmp_path: Path):
    cfg = Settings(
        data_dir=tmp_path / "data",
        admin_token="adm-token",
        base_domains=["localhost"],
    )
    app = create_app(cfg)

    with TestClient(app) as client:
        # Setup via admin API
        client.post("/api/admin/login", json={"token": "adm-token"}).raise_for_status()
        bk = client.post(
            "/api/admin/backends",
            json={
                "name": "local-1",
                "protocol": "local",
                "base_path": str(tmp_path / "store"),
            },
        ).json()["backend"]
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
            json={"user_id": alice["id"], "backend_id": bk["id"], "priority": 1},
        ).raise_for_status()

        # Browser GET / without auth redirects to /console
        r_root = client.get("/", headers={"Accept": "text/html"}, follow_redirects=False)
        assert r_root.status_code == 302
        assert r_root.headers["location"] == "/console"

        # User Console page loads
        assert client.get("/console").status_code == 200

        # Login with wrong SK fails, right AK/SK succeeds
        assert (
            client.post(
                "/api/console/login",
                json={"access_key": alice["access_key"], "secret_key": "wrong"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/console/login",
                json={"access_key": alice["access_key"], "secret_key": alice["secret_key"]},
            ).status_code
            == 200
        )

        me = client.get("/api/console/me").json()
        assert me["user"]["username"] == "alice"
        assert me["user"]["has_storage_pool"] is True
        assert "bindings" not in me

        # Create private bucket & upload via Console API
        client.post("/api/console/buckets", json={"name": "media", "acl": "private"}).raise_for_status()
        client.post("/api/console/buckets/media/folders", json={"folder": "pics"}).raise_for_status()
        up = client.post(
            "/api/console/buckets/media/upload?key=pics/hello.txt",
            content=b"public-read-test-content",
            headers={"Content-Type": "text/plain"},
        )
        assert up.status_code == 200

        # List with delimiter='/' sees 'pics/' folder
        listed = client.get("/api/console/buckets/media/objects?prefix=&delimiter=/").json()
        assert listed["common_prefixes"] == ["pics/"]

        # Private bucket denies anonymous GET /media/pics/hello.txt
        assert client.get("/media/pics/hello.txt").status_code == 403

        # Presigned share URL works even while bucket is private
        share = client.post(
            "/api/console/buckets/media/presign",
            json={"key": "pics/hello.txt", "expires_seconds": 600},
        ).json()
        assert share["public_url"] is None
        pre_path = share["presigned_url"].split("testserver", 1)[-1]
        assert client.get(pre_path).content == b"public-read-test-content"

        # Switch bucket ACL to public-read and set CORS rule
        client.patch(
            "/api/console/buckets/media",
            json={
                "acl": "public-read",
                "cors_rules": [
                    {
                        "allowed_origins": ["https://example.com"],
                        "allowed_methods": ["GET", "HEAD"],
                        "allowed_headers": ["*"],
                        "expose_headers": ["ETag"],
                        "max_age_seconds": 600,
                    }
                ],
            },
        ).raise_for_status()

        # Anonymous GET + CORS headers succeed
        preflight = client.options(
            "/media/pics/hello.txt",
            headers={
                "Origin": "https://example.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert preflight.status_code == 200
        assert preflight.headers["access-control-allow-origin"] == "https://example.com"

        anon_get = client.get(
            "/media/pics/hello.txt", headers={"Origin": "https://example.com"}
        )
        assert anon_get.status_code == 200
        assert anon_get.content == b"public-read-test-content"
        assert anon_get.headers["access-control-allow-origin"] == "https://example.com"

        # Inline preview via Console
        prev = client.get("/api/console/buckets/media/objects/download?key=pics/hello.txt&inline=1")
        assert prev.status_code == 200
        assert "inline;" in prev.headers["content-disposition"]

        # Bob logging into /console cannot see or access Alice's bucket
        client.post(
            "/api/console/login",
            json={"access_key": bob["access_key"], "secret_key": bob["secret_key"]},
        ).raise_for_status()
        assert client.get("/api/console/buckets").json()["buckets"] == []
        assert client.get("/api/console/buckets/media/objects").status_code == 403

        # Switch back to Alice and recursively delete 'pics/' folder
        client.post(
            "/api/console/login",
            json={"access_key": alice["access_key"], "secret_key": alice["secret_key"]},
        ).raise_for_status()
        del_res = client.post(
            "/api/console/buckets/media/delete-batch",
            json={"keys": [], "prefixes": ["pics/"]},
        ).json()
        assert del_res["deleted"] == 2  # pics/ marker + pics/hello.txt
        assert client.delete("/api/console/buckets/media").status_code == 200


def test_new_console_and_admin_ops(tmp_path: Path):
    cfg = Settings(
        data_dir=tmp_path / "data",
        admin_token="adm-token",
        base_domains=["localhost"],
    )
    app = create_app(cfg)

    with TestClient(app) as client:
        client.post("/api/admin/login", json={"token": "adm-token"}).raise_for_status()

        # Pre-save backend connection test (local dir) without inserting into DB
        probe_dir = tmp_path / "probe-store"
        probe_res = client.post(
            "/api/admin/backends/test",
            json={"name": "probe-tmp", "protocol": "local", "base_path": str(probe_dir)},
        )
        assert probe_res.status_code == 200
        assert probe_res.json()["ok"] is True
        assert client.get("/api/admin/backends").json()["backends"] == []

        # Create backend, user, binding, bucket
        bk = client.post(
            "/api/admin/backends",
            json={"name": "local-1", "protocol": "local", "base_path": str(tmp_path / "store")},
        ).json()["backend"]
        all_probe = client.post("/api/admin/backends/probe-all")
        assert all_probe.status_code == 200
        assert all_probe.json()["total"] == 1
        assert all_probe.json()["ok"] == 1

        alice = client.post(
            "/api/admin/users",
            json={"username": "alice", "encryption_enabled": True},
        ).json()["user"]
        client.post(
            "/api/admin/bindings",
            json={"user_id": alice["id"], "backend_id": bk["id"], "priority": 1},
        ).raise_for_status()

        # Login as Alice in /console
        client.post(
            "/api/console/login",
            json={"access_key": alice["access_key"], "secret_key": alice["secret_key"]},
        ).raise_for_status()
        client.post("/api/console/buckets", json={"name": "work", "acl": "private"}).raise_for_status()

        # Web chunked multipart upload (simulating >24 MiB CF bypass flow)
        init_res = client.post(
            "/api/console/buckets/work/multipart/init",
            json={"key": "报告/中文文件.txt", "content_type": "text/plain"},
        )
        assert init_res.status_code == 200
        upload_id = init_res.json()["upload_id"]

        p1 = client.post(
            f"/api/console/buckets/work/multipart/{upload_id}/part?part_number=1",
            content=b"Hello-",
        )
        assert p1.status_code == 200
        p2 = client.post(
            f"/api/console/buckets/work/multipart/{upload_id}/part?part_number=2",
            content=b"BanOSS!",
        )
        assert p2.status_code == 200

        comp = client.post(
            f"/api/console/buckets/work/multipart/{upload_id}/complete",
            json={
                "parts": [
                    {"part_number": 1, "etag": p1.json()["etag"]},
                    {"part_number": 2, "etag": p2.json()["etag"]},
                ]
            },
        )
        assert comp.status_code == 200
        assert comp.json()["object"]["size"] == len(b"Hello-BanOSS!")

        # Download UTF-8 / Chinese filename -> RFC 5987 Content-Disposition + exact content
        dl = client.get("/api/console/buckets/work/objects/download", params={"key": "报告/中文文件.txt"})
        assert dl.status_code == 200
        assert dl.content == b"Hello-BanOSS!"
        assert "filename*=UTF-8''" in dl.headers["content-disposition"]

        # Rename object + collision check
        rn = client.post(
            "/api/console/buckets/work/objects/rename",
            json={"old_key": "报告/中文文件.txt", "new_key": "归档/最终版.txt"},
        )
        assert rn.status_code == 200
        assert rn.json()["object"]["key"] == "归档/最终版.txt"

        # Upload another and verify rename collision -> 409
        client.post(
            "/api/console/buckets/work/upload",
            params={"key": "other.txt"},
            content=b"x",
        ).raise_for_status()
        dup = client.post(
            "/api/console/buckets/work/objects/rename",
            json={"old_key": "other.txt", "new_key": "归档/最终版.txt"},
        )
        assert dup.status_code == 409

        # Single-object delete on /console
        d1 = client.delete("/api/console/buckets/work/objects", params={"key": "归档/最终版.txt"})
        assert d1.status_code == 200
        assert client.get("/api/console/buckets/work/objects/download", params={"key": "归档/最终版.txt"}).status_code == 404


def test_ssh_credential_expiry_inspect_and_rotate(tmp_path: Path):
    import time
    from datetime import datetime, timedelta, timezone
    import asyncssh

    cfg = Settings(
        data_dir=tmp_path / "data",
        admin_token="adm-token",
        base_domains=["localhost"],
    )
    app = create_app(cfg)

    key = asyncssh.generate_private_key("ssh-ed25519", comment="short-key")
    pem = key.export_private_key().decode()
    now = int(time.time())
    cert = key.generate_user_certificate(
        key, "short-cert", principals=["alice"], valid_after=now - 60, valid_before=now + 3600
    )
    combined_cred = pem + "\n" + cert.export_certificate().decode()

    with TestClient(app) as client:
        client.post("/api/admin/login", json={"token": "adm-token"}).raise_for_status()

        # Inspect combined PEM + OpenSSH certificate
        ins = client.post(
            "/api/admin/backends/inspect-credential",
            json={"auth_type": "key", "credential": combined_cred},
        )
        assert ins.status_code == 200
        info = ins.json()
        assert info["valid"] is True
        assert info["algorithm"] == "ssh-ed25519"
        assert info["has_certificate"] is True
        assert info["cert_valid_before"] is not None

        # Create SFTP backend with combined key+cert (auto-extracts 1h expiry -> expiring_soon)
        bk_res = client.post(
            "/api/admin/backends",
            json={
                "name": "sftp-short",
                "protocol": "sftp",
                "host": "127.0.0.1",
                "port": 1,
                "username": "alice",
                "auth_type": "key",
                "credential": combined_cred,
                "base_path": "/work1/share/alice/banoss",
            },
        )
        assert bk_res.status_code == 200
        bk = bk_res.json()["backend"]
        assert bk["credential_status"] == "expiring_soon"
        assert 0 < bk["credential_remaining_seconds"] <= 3600

        # Admin overview should surface alert for expiring credential
        ov = client.get("/api/admin/overview").json()
        assert ov["stats"]["credential_alerts"] == 1
        assert ov["credential_alerts"][0]["id"] == bk["id"]

        # Safe rotate with test_before_save=True fails cleanly against unreachable port and keeps old expiry
        bad_rot = client.post(
            f"/api/admin/backends/{bk['id']}/rotate-credential",
            json={
                "auth_type": "key",
                "credential": pem,
                "credential_ttl_hours": 72,
                "test_before_save": True,
            },
        )
        assert bad_rot.status_code == 400
        still = client.get("/api/admin/backends").json()["backends"][0]
        assert still["credential_expires_at"] == bk["credential_expires_at"]

        # Force rotate with 72h TTL resets status to valid and clears alerts
        good_rot = client.post(
            f"/api/admin/backends/{bk['id']}/rotate-credential",
            json={
                "auth_type": "key",
                "credential": pem,
                "credential_ttl_hours": 72,
                "test_before_save": False,
            },
        )
        assert good_rot.status_code == 200
        rotated = good_rot.json()["backend"]
        assert rotated["credential_status"] == "valid"
        assert rotated["credential_remaining_seconds"] > 3600 * 48
        assert client.get("/api/admin/overview").json()["stats"]["credential_alerts"] == 0

        # Explicit past expiry transitions status immediately to expired + alerts again
        past_iso = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        client.patch(
            f"/api/admin/backends/{bk['id']}",
            json={"credential_expires_at": past_iso},
        ).raise_for_status()
        exp_bk = client.get("/api/admin/backends").json()["backends"][0]
        assert exp_bk["credential_status"] == "expired"
        assert client.get("/api/admin/overview").json()["stats"]["credential_alerts"] == 1


def test_user_registration_bucket_requests_and_zero_leakage(tmp_path: Path):
    cfg = Settings(
        data_dir=tmp_path / "data",
        admin_token="adm-token",
        base_domains=["localhost"],
    )
    app = create_app(cfg)

    with TestClient(app) as client:
        # Admin prepares two secret backend nodes
        client.post("/api/admin/login", json={"token": "adm-token"}).raise_for_status()
        bk1 = client.post(
            "/api/admin/backends",
            json={"name": "secret-scnet-node-1", "protocol": "local", "base_path": str(tmp_path / "store1")},
        ).json()["backend"]
        bk2 = client.post(
            "/api/admin/backends",
            json={"name": "secret-scnet-node-2", "protocol": "local", "base_path": str(tmp_path / "store2")},
        ).json()["backend"]

        # Public /console HTML contains zero backend/SSH/SFTP/SCNet details
        console_html = client.get("/console").text.lower()
        for forbidden in ["secret-scnet", "sftp", "超算", "scnet", "e-shell", "/work1"]:
            assert forbidden not in console_html

        # Ordinary user registers with username + password + initial bucket request
        reg = client.post(
            "/api/console/register",
            json={
                "username": "newcomer",
                "password": "my-secret-password",
                "bucket_name": "newcomer-data",
                "bucket_acl": "private",
                "requested_quota_bytes": 10 * (1024 ** 3),
                "reason": "Need research storage",
            },
        )
        assert reg.status_code == 200
        reg_data = reg.json()
        assert reg_data["user"]["username"] == "newcomer"
        assert reg_data["bucket_request"]["status"] == "pending"

        # Before admin approval, user cannot create buckets directly or leak backend info
        me_before = client.get("/api/console/me").json()
        assert me_before["user"]["has_storage_pool"] is False
        assert "bindings" not in me_before
        assert "secret-scnet" not in str(me_before).lower()
        assert client.post("/api/console/buckets", json={"name": "unauthorized-bucket"}).status_code == 403

        # Re-login via username + password works too
        client.post("/api/console/logout").raise_for_status()
        assert (
            client.post(
                "/api/console/login",
                json={"account": "newcomer", "secret": "my-secret-password"},
            ).status_code
            == 200
        )
        # User can reveal their S3 AK/SK for client tools
        sec = client.post("/api/console/reveal-secret").json()
        assert sec["access_key"] == reg_data["user"]["access_key"]
        assert sec["secret_key"] == reg_data["user"]["secret_key"]

        # Admin views pending request & approves with BOTH backends aggregated + 15 GiB quota
        reqs = client.get("/api/admin/bucket-requests?status=pending").json()["requests"]
        assert len(reqs) == 1
        req_id = reqs[0]["id"]
        appr = client.post(
            f"/api/admin/bucket-requests/{req_id}/approve",
            json={
                "backend_ids": [bk1["id"], bk2["id"]],
                "user_quota_bytes": 15 * (1024 ** 3),
                "admin_note": "Approved for research",
            },
        )
        assert appr.status_code == 200
        assert appr.json()["bucket"]["name"] == "newcomer-data"

        # Now user sees approved bucket, can upload & inspect WITHOUT any backend/remote_path leaks
        me_after = client.get("/api/console/me").json()
        assert me_after["user"]["has_storage_pool"] is True
        assert me_after["user"]["effective_quota_bytes"] == 15 * (1024 ** 3)
        assert "bindings" not in me_after

        up = client.post(
            "/api/console/buckets/newcomer-data/upload?key=notes.txt",
            content=b"secret-safe-data",
        )
        assert up.status_code == 200

        insp = client.get("/api/console/buckets/newcomer-data/objects/inspect?key=notes.txt").json()
        assert insp["object"]["key"] == "notes.txt"
        assert insp["encrypted"] is True
        assert "segments" not in insp
        assert "secret-scnet" not in str(insp).lower()
        assert "remote_path" not in str(insp).lower()


def test_aws_chunked_trailer_decoding_in_put_and_multipart(tmp_path: Path):
    """Ensure STREAMING-UNSIGNED-PAYLOAD-TRAILER and aws-chunked frames are stripped before storing."""
    import hashlib
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    cfg = Settings(
        data_dir=tmp_path / "data",
        admin_token="adm-token",
        base_domains=["testserver", "localhost"],
    )
    app = create_app(cfg)

    with TestClient(app) as client:
        client.post("/api/admin/login", json={"token": "adm-token"}).raise_for_status()
        bk = client.post(
            "/api/admin/backends",
            json={"name": "local-chunked", "protocol": "local", "base_path": str(tmp_path / "store")},
        ).json()["backend"]
        usr = client.post("/api/admin/users", json={"username": "sdkuser", "encryption_enabled": True}).json()["user"]
        client.post(
            "/api/admin/bindings",
            json={"user_id": usr["id"], "backend_id": bk["id"], "priority": 10},
        ).raise_for_status()
        client.post(
            "/api/admin/buckets",
            json={"name": "chunk-box", "owner_user_id": usr["id"]},
        ).raise_for_status()

        creds = Credentials(usr["access_key"], usr["secret_key"])

        def _signed_headers(method: str, path: str, body: bytes, extra_headers: dict[str, str]) -> dict[str, str]:
            req = AWSRequest(
                method=method,
                url=f"http://testserver{path}",
                data=body,
                headers={"Host": "testserver", **extra_headers},
            )
            SigV4Auth(creds, "s3", "us-east-1").add_auth(req)
            return {k: str(v) for k, v in req.headers.items()}

        # 1. Exact reproduction of boto3 STREAMING-UNSIGNED-PAYLOAD-TRAILER with CRC32 trailer
        plain = b"0123456789ABCDEFGHIJ"
        framed = (
            b"14\r\n"
            + plain
            + b"\r\n0\r\n"
            + b"x-amz-checksum-crc32:aBMQFg==\r\n\r\n"
        )
        hdrs = _signed_headers(
            "PUT",
            "/chunk-box/sample.txt",
            framed,
            {
                "Content-Encoding": "aws-chunked",
                "X-Amz-Decoded-Content-Length": str(len(plain)),
                "X-Amz-Trailer": "x-amz-checksum-crc32",
                "x-amz-sdk-checksum-algorithm": "CRC32",
                "X-Amz-Content-SHA256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
            },
        )
        # Send header value as signed payload indicator (testserver doesn't automatically swap x-amz-content-sha256 unless passed)
        put_resp = client.put("/chunk-box/sample.txt", content=framed, headers=hdrs)
        assert put_resp.status_code == 200, put_resp.text
        expected_etag = f'"{hashlib.md5(plain).hexdigest()}"'
        assert put_resp.headers["etag"] == expected_etag

        get_hdrs = _signed_headers("GET", "/chunk-box/sample.txt", b"", {"X-Amz-Content-SHA256": hashlib.sha256(b"").hexdigest()})
        get_resp = client.get("/chunk-box/sample.txt", headers=get_hdrs)
        assert get_resp.status_code == 200
        assert get_resp.content == plain
        assert int(get_resp.headers["content-length"]) == len(plain)

        # 2. Multi-chunk signed+trailer format (STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER) across chunks
        part1 = b"Hello-"
        part2 = b"BanOSS-World!"
        framed_multi = (
            b"6;chunk-signature=deadbeef\r\n"
            + part1
            + b"\r\nd;chunk-signature=cafebabe\r\n"
            + part2
            + b"\r\n0;chunk-signature=00000000\r\n"
            + b"x-amz-checksum-crc32:AAAAAA==\r\n\r\n"
        )
        hdrs_multi = _signed_headers(
            "PUT",
            "/chunk-box/multi.txt",
            framed_multi,
            {
                "Content-Encoding": "aws-chunked",
                "X-Amz-Decoded-Content-Length": str(len(part1) + len(part2)),
                "X-Amz-Content-SHA256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
            },
        )
        put2 = client.put("/chunk-box/multi.txt", content=framed_multi, headers=hdrs_multi)
        assert put2.status_code == 200
        get2 = client.get(
            "/chunk-box/multi.txt",
            headers=_signed_headers("GET", "/chunk-box/multi.txt", b"", {"X-Amz-Content-SHA256": hashlib.sha256(b"").hexdigest()}),
        )
        assert get2.status_code == 200
        assert get2.content == part1 + part2
