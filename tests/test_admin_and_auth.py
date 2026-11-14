"""Tests for Admin API, key rotation, virtual-hosted routing, and AWS chunked payload decoding."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from banoss.app import create_app
from banoss.config import Settings
from banoss.s3_auth import derive_signing_key


def _sign_headers(
    method: str,
    host: str,
    path: str,
    query: str,
    payload_hash: str,
    ak: str,
    sk: str,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, str]:
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    region = "us-east-1"

    headers = {
        "host": host,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
    }
    if extra_headers:
        for k, v in extra_headers.items():
            headers[k.lower()] = v

    signed_names = sorted(headers.keys())
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in signed_names)
    signed_headers_str = ";".join(signed_names)

    canonical_req = "\n".join(
        [method.upper(), path, query, canonical_headers, signed_headers_str, payload_hash]
    )
    scope = f"{date_stamp}/{region}/s3/aws4_request"
    sts = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_req.encode("utf-8")).hexdigest(),
        ]
    )
    sig_key = derive_signing_key(sk, date_stamp, region, "s3")
    sig = hmac.new(sig_key, sts.encode("utf-8"), hashlib.sha256).hexdigest()

    out = dict(headers)
    out["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders={signed_headers_str}, Signature={sig}"
    )
    return out


def test_admin_ui_and_streaming_chunked_upload(tmp_path: Path):
    cfg = Settings(
        data_dir=tmp_path / "data",
        admin_token="adm-secret",
        base_domains=["s3.local"],
    )
    app = create_app(cfg)

    with TestClient(app) as client:
        # Admin page loads
        r = client.get("/admin")
        assert r.status_code == 200
        assert "BanOSS" in r.text

        # Login cookie flow
        assert client.get("/api/admin/overview").status_code == 401
        login = client.post("/api/admin/login", json={"token": "adm-secret"})
        assert login.status_code == 200
        assert client.get("/api/admin/overview").status_code == 200

        # Create local backend + user + binding
        bk = client.post(
            "/api/admin/backends",
            json={
                "name": "local-test",
                "protocol": "local",
                "base_path": str(tmp_path / "store"),
            },
        ).json()["backend"]
        usr = client.post(
            "/api/admin/users",
            json={"username": "tester", "encryption_enabled": False},
        ).json()["user"]
        client.post(
            "/api/admin/bindings",
            json={"user_id": usr["id"], "backend_id": bk["id"], "priority": 1},
        ).raise_for_status()

        # Virtual-hosted style CreateBucket + AWS chunked PutObject + GetObject
        host = "vh-bucket.s3.local"
        h_create = _sign_headers(
            "PUT",
            host,
            "/",
            "",
            hashlib.sha256(b"").hexdigest(),
            usr["access_key"],
            usr["secret_key"],
        )
        assert client.put("/", headers=h_create).status_code == 200

        raw_data = b"hello-aws-chunked-stream!"
        aws_chunked_body = (
            f"{len(raw_data):x};chunk-signature={'0'*64}\r\n".encode("ascii")
            + raw_data
            + b"\r\n"
            + f"0;chunk-signature={'0'*64}\r\n\r\n".encode("ascii")
        )
        h_put = _sign_headers(
            "PUT",
            host,
            "/stream.txt",
            "",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            usr["access_key"],
            usr["secret_key"],
            extra_headers={"x-amz-decoded-content-length": str(len(raw_data))},
        )
        r_put = client.put("/stream.txt", content=aws_chunked_body, headers=h_put)
        assert r_put.status_code == 200

        h_get = _sign_headers(
            "GET",
            host,
            "/stream.txt",
            "",
            "UNSIGNED-PAYLOAD",
            usr["access_key"],
            usr["secret_key"],
        )
        r_get = client.get("/stream.txt", headers=h_get)
        assert r_get.status_code == 200
        assert r_get.content == raw_data

        # Rotate user keys and verify old key fails
        rot = client.post(f"/api/admin/users/{usr['id']}/rotate-keys")
        assert rot.status_code == 200
        new_usr = rot.json()["user"]
        assert new_usr["access_key"] != usr["access_key"]
        assert client.get("/stream.txt", headers=h_get).status_code == 403
