"""Admin REST API and Web Console routes."""

from __future__ import annotations

import asyncio
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from banoss.backup import create_vault_bytes

from banoss.bucket_ops import (
    abort_web_multipart,
    build_share_urls,
    complete_web_multipart,
    create_folder_marker,
    delete_batch_keys_and_prefixes,
    init_web_multipart,
    rename_bucket_object,
    stream_object_response,
    upload_object_from_request,
    upload_web_multipart_part,
)
from banoss.config import Settings
from banoss.console_router import (
    CreateFolderRequest,
    DeleteBatchRequest,
    InitMultipartRequest,
    PresignRequest,
    RenameObjectRequest,
    UpdateBucketRequest,
)
from banoss.crypto import CryptoService
from banoss.db import Database, utcnow_iso
from banoss.storage import (
    StorageManager,
    compute_credential_status,
    inspect_ssh_credential,
)

STATIC_DIR = Path(__file__).parent / "static"


class LoginRequest(BaseModel):
    token: str


class CreateBackendRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    protocol: str = Field(pattern="^(sftp|local)$")
    host: str = ""
    port: int = Field(default=22, ge=1, le=65535)
    username: str = ""
    auth_type: str = Field(default="key", pattern="^(key|password|none)$")
    credential: str = ""
    passphrase: str = ""
    base_path: str = Field(min_length=1)
    max_connections: int = Field(default=3, ge=1, le=64)
    idle_timeout_sec: int = Field(default=600, ge=0, le=86400)
    quota_bytes: int = Field(default=0, ge=0)
    is_active: bool = True
    read_only: bool = False
    credential_ttl_hours: Optional[float] = Field(default=None, ge=0, le=87600)
    credential_expires_at: Optional[str] = None


class TestBackendRequest(BaseModel):
    backend_id: Optional[str] = None
    protocol: str = Field(pattern="^(sftp|local)$")
    host: str = ""
    port: int = Field(default=22, ge=1, le=65535)
    username: str = ""
    auth_type: str = Field(default="key", pattern="^(key|password|none)$")
    credential: str = ""
    passphrase: str = ""
    base_path: str = Field(min_length=1)
    max_connections: int = Field(default=3, ge=1, le=64)
    idle_timeout_sec: int = Field(default=600, ge=0, le=86400)


class UpdateBackendRequest(BaseModel):
    name: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    username: Optional[str] = None
    auth_type: Optional[str] = Field(default=None, pattern="^(key|password|none)$")
    credential: Optional[str] = None
    passphrase: Optional[str] = None
    base_path: Optional[str] = None
    max_connections: Optional[int] = Field(default=None, ge=1, le=64)
    idle_timeout_sec: Optional[int] = Field(default=None, ge=0, le=86400)
    quota_bytes: Optional[int] = Field(default=None, ge=0)
    is_active: Optional[bool] = None
    read_only: Optional[bool] = None
    credential_ttl_hours: Optional[float] = Field(default=None, ge=0, le=87600)
    credential_expires_at: Optional[str] = None


class InspectCredentialRequest(BaseModel):
    auth_type: str = Field(default="key", pattern="^(key|password|none)$")
    credential: str = ""
    passphrase: str = ""


class RotateCredentialRequest(BaseModel):
    auth_type: Optional[str] = Field(default=None, pattern="^(key|password)$")
    credential: str = Field(min_length=1)
    passphrase: Optional[str] = None
    credential_ttl_hours: Optional[float] = Field(default=None, ge=0, le=87600)
    credential_expires_at: Optional[str] = None
    test_before_save: bool = True


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    encryption_enabled: bool = True
    quota_bytes: int = Field(default=0, ge=0)
    is_active: bool = True


class UpdateUserRequest(BaseModel):
    is_active: Optional[bool] = None
    encryption_enabled: Optional[bool] = None
    quota_bytes: Optional[int] = Field(default=None, ge=0)


class UpsertBindingRequest(BaseModel):
    user_id: str
    backend_id: str
    priority: int = Field(default=100, ge=0, le=100000)
    quota_bytes: int = Field(default=0, ge=0)
    is_active: bool = True


class CreateBucketAdminRequest(BaseModel):
    name: str = Field(min_length=3, max_length=63, pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
    owner_user_id: str


class ApproveBucketRequestPayload(BaseModel):
    backend_ids: list[str] = Field(default_factory=list)
    user_quota_bytes: Optional[int] = Field(default=None, ge=0)
    admin_note: str = Field(default="", max_length=500)


class RejectBucketRequestPayload(BaseModel):
    admin_note: str = Field(default="", max_length=500)


class BackupDownloadRequest(BaseModel):
    passphrase: str = Field(min_length=8, max_length=256)


class BackupPushRequest(BaseModel):
    passphrase: str = Field(min_length=8, max_length=256)
    backend_id: str
    remote_path: Optional[str] = None


def _generate_ak() -> str:
    return "BANOSS" + secrets.token_hex(7).upper()


def _generate_sk() -> str:
    return secrets.token_urlsafe(30)


def create_admin_router(
    settings: Settings,
    admin_token: str,
    db: Database,
    crypto: CryptoService,
    storage: StorageManager,
) -> APIRouter:
    router = APIRouter()

    async def require_admin(
        authorization: Optional[str] = Header(default=None),
        banoss_admin: Optional[str] = Cookie(default=None),
    ) -> None:
        token: Optional[str] = None
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
        elif banoss_admin:
            token = banoss_admin.strip()
        if not token or not hmac.compare_digest(token, admin_token):
            raise HTTPException(status_code=401, detail="Invalid or missing admin token")

    @router.get("/admin", include_in_schema=False)
    @router.get("/admin/", include_in_schema=False)
    async def admin_ui() -> FileResponse:
        return FileResponse(STATIC_DIR / "admin.html", media_type="text/html")

    @router.post("/api/admin/login")
    async def admin_login(payload: LoginRequest, response: Response) -> dict[str, Any]:
        if not hmac.compare_digest(payload.token.strip(), admin_token):
            raise HTTPException(status_code=401, detail="Invalid admin token")
        response.set_cookie(
            key="banoss_admin",
            value=admin_token,
            httponly=True,
            samesite="lax",
            path="/",
        )
        return {"ok": True}

    @router.post("/api/admin/logout")
    async def admin_logout(response: Response) -> dict[str, Any]:
        response.delete_cookie("banoss_admin", path="/")
        return {"ok": True}

    def _sanitize_backend(r: dict[str, Any], pools: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        row = dict(r)
        has_cred = bool(row.pop("credential_enc", ""))
        row.pop("passphrase_enc", None)
        row["has_credential"] = has_cred
        if pools is not None:
            row["pool"] = pools.get(
                row["id"], {"active": 0, "idle": 0, "max_connections": row["max_connections"]}
            )
        row.update(compute_credential_status(row))
        return row

    def _resolve_expiry_iso(
        *,
        protocol: str,
        auth_type: str,
        credential: str = "",
        passphrase: str = "",
        ttl_hours: Optional[float] = None,
        explicit_expires_at: Optional[str] = None,
        sentinel_keep: bool = False,
    ) -> Any:
        """Resolve UTC ISO expiry string, None (no expiry), or _KEEP sentinel when unchanged."""
        if protocol == "local":
            return None
        if ttl_hours is not None:
            if ttl_hours <= 0:
                return None
            return (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if explicit_expires_at is not None:
            raw = explicit_expires_at.strip()
            if not raw:
                return None
            try:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"无效的过期时间格式: {exc}") from exc
        if credential and auth_type == "key":
            info = inspect_ssh_credential(credential, auth_type="key", passphrase=passphrase or None)
            if info.get("cert_valid_before"):
                return info["cert_valid_before"]
        return ... if sentinel_keep else None

    @router.get("/api/admin/overview", dependencies=[Depends(require_admin)])
    async def admin_overview() -> dict[str, Any]:
        stats = await db.get_stats()
        pools = storage.get_pool_snapshot()
        rows = await db.list_backends()
        alerts = []
        for r in rows:
            if not r.get("is_active") or r.get("protocol") != "sftp":
                continue
            info = compute_credential_status(r)
            if info["credential_status"] in {"expired", "expiring_soon"} or info["credential_auth_error"]:
                alerts.append(
                    {
                        "id": r["id"],
                        "name": r["name"],
                        "auth_type": r["auth_type"],
                        "last_status": r.get("last_status", "unknown"),
                        "last_message": r.get("last_message", ""),
                        **info,
                    }
                )
        stats["credential_alerts"] = len(alerts)
        return {
            "stats": stats,
            "pools": pools,
            "credential_alerts": alerts,
            "chunk_size": settings.chunk_size,
            "region": settings.region,
        }

    # ------------------------------------------------------------------
    # Backends
    # ------------------------------------------------------------------
    @router.get("/api/admin/backends", dependencies=[Depends(require_admin)])
    async def list_backends() -> dict[str, Any]:
        rows = await db.list_backends()
        pools = storage.get_pool_snapshot()
        return {"backends": [_sanitize_backend(r, pools) for r in rows]}

    @router.post("/api/admin/backends", dependencies=[Depends(require_admin)])
    async def create_backend(payload: CreateBackendRequest) -> dict[str, Any]:
        if payload.protocol == "sftp" and (not payload.host or not payload.username):
            raise HTTPException(status_code=400, detail="SFTP backend requires host and username")
        eff_auth = "none" if payload.protocol == "local" else payload.auth_type
        if payload.protocol == "sftp" and eff_auth == "key" and payload.credential.strip():
            info = inspect_ssh_credential(
                payload.credential, auth_type="key", passphrase=payload.passphrase or None
            )
            if not info.get("valid"):
                raise HTTPException(status_code=400, detail=info.get("error") or "SSH 私钥无效")
        expires_at = _resolve_expiry_iso(
            protocol=payload.protocol,
            auth_type=eff_auth,
            credential=payload.credential,
            passphrase=payload.passphrase,
            ttl_hours=payload.credential_ttl_hours,
            explicit_expires_at=payload.credential_expires_at,
        )
        try:
            row = await db.create_backend(
                name=payload.name.strip(),
                protocol=payload.protocol,
                host=payload.host.strip(),
                port=payload.port,
                username=payload.username.strip(),
                auth_type=eff_auth,
                credential_enc=crypto.encrypt_secret(payload.credential) if payload.credential else "",
                passphrase_enc=crypto.encrypt_secret(payload.passphrase) if payload.passphrase else "",
                base_path=payload.base_path.strip(),
                max_connections=payload.max_connections,
                idle_timeout_sec=payload.idle_timeout_sec,
                quota_bytes=payload.quota_bytes,
                is_active=payload.is_active,
                read_only=payload.read_only,
                credential_updated_at=utcnow_iso() if payload.credential else None,
                credential_expires_at=expires_at,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        storage.schedule_warm_backend(row)
        return {"backend": _sanitize_backend(row)}

    @router.patch("/api/admin/backends/{backend_id}", dependencies=[Depends(require_admin)])
    async def update_backend(backend_id: str, payload: UpdateBackendRequest) -> dict[str, Any]:
        existing = await db.get_backend(backend_id)
        if not existing:
            raise HTTPException(status_code=404, detail="Backend not found")
        updates = payload.model_dump(exclude_none=True)
        ttl_hours = updates.pop("credential_ttl_hours", None)
        explicit_exp = updates.pop("credential_expires_at", None)
        cred_val = updates.pop("credential", None)
        pp_val = updates.pop("passphrase", None)
        eff_auth = updates.get("auth_type", existing.get("auth_type", "key"))

        if cred_val is not None and cred_val != "":
            if existing.get("protocol") == "sftp" and eff_auth == "key":
                eff_pp = pp_val if pp_val is not None else crypto.decrypt_secret(existing.get("passphrase_enc", ""))
                info = inspect_ssh_credential(cred_val, auth_type="key", passphrase=eff_pp or None)
                if not info.get("valid"):
                    raise HTTPException(status_code=400, detail=info.get("error") or "SSH 私钥无效")
            updates["credential_enc"] = crypto.encrypt_secret(cred_val)
            updates["credential_updated_at"] = utcnow_iso()
        if pp_val is not None:
            updates["passphrase_enc"] = crypto.encrypt_secret(pp_val) if pp_val else ""

        resolved_exp = _resolve_expiry_iso(
            protocol=existing.get("protocol", "sftp"),
            auth_type=eff_auth,
            credential=cred_val or "",
            passphrase=pp_val or "",
            ttl_hours=ttl_hours,
            explicit_expires_at=explicit_exp,
            sentinel_keep=True,
        )
        if resolved_exp is not ...:
            updates["credential_expires_at"] = resolved_exp

        updated = await db.update_backend(backend_id, updates)
        await storage.invalidate_backend_pool(backend_id)
        if updated:
            storage.schedule_warm_backend(updated)
        return {"backend": _sanitize_backend(updated, storage.get_pool_snapshot()) if updated else None}

    @router.post("/api/admin/backends/inspect-credential", dependencies=[Depends(require_admin)])
    async def inspect_backend_credential(payload: InspectCredentialRequest) -> dict[str, Any]:
        return inspect_ssh_credential(
            payload.credential,
            auth_type=payload.auth_type,
            passphrase=payload.passphrase or None,
        )

    @router.post("/api/admin/backends/{backend_id}/rotate-credential", dependencies=[Depends(require_admin)])
    async def rotate_backend_credential(
        backend_id: str, payload: RotateCredentialRequest
    ) -> dict[str, Any]:
        existing = await db.get_backend(backend_id)
        if not existing:
            raise HTTPException(status_code=404, detail="Backend not found")
        if existing.get("protocol") != "sftp":
            raise HTTPException(status_code=400, detail="仅 SFTP 节点支持 SSH 凭据轮换")

        eff_auth = payload.auth_type or existing.get("auth_type", "key")
        eff_pass = payload.passphrase if payload.passphrase is not None else ""
        if eff_auth == "key":
            info = inspect_ssh_credential(
                payload.credential, auth_type="key", passphrase=eff_pass or None
            )
            if not info.get("valid"):
                raise HTTPException(status_code=400, detail=info.get("error") or "SSH 私钥无效")

        new_cred_enc = crypto.encrypt_secret(payload.credential)
        new_pass_enc = crypto.encrypt_secret(eff_pass) if (eff_auth == "key" and eff_pass) else ""
        probe_res: Optional[dict[str, Any]] = None
        if payload.test_before_save:
            ephemeral = {
                **existing,
                "id": f"rotate-test-{secrets.token_hex(6)}",
                "auth_type": eff_auth,
                "credential_enc": new_cred_enc,
                "passphrase_enc": new_pass_enc,
            }
            probe_res = await storage.probe_backend(ephemeral, persist_status=False)
            if not probe_res.get("ok"):
                raise HTTPException(
                    status_code=400,
                    detail=f"新凭据连通测试失败，旧凭据保留未改动: {probe_res.get('message', '')}",
                )

        expires_at = _resolve_expiry_iso(
            protocol="sftp",
            auth_type=eff_auth,
            credential=payload.credential,
            passphrase=eff_pass,
            ttl_hours=payload.credential_ttl_hours,
            explicit_expires_at=payload.credential_expires_at,
        )
        updates: dict[str, Any] = {
            "auth_type": eff_auth,
            "credential_enc": new_cred_enc,
            "passphrase_enc": new_pass_enc,
            "credential_updated_at": utcnow_iso(),
            "credential_expires_at": expires_at,
        }
        if probe_res and probe_res.get("ok"):
            updates["last_status"] = "healthy"
            updates["last_message"] = str(probe_res.get("message", ""))[:300]
            updates["last_checked_at"] = utcnow_iso()

        updated = await db.update_backend(backend_id, updates)
        await storage.invalidate_backend_pool(backend_id)
        if updated:
            storage.schedule_warm_backend(updated)
        return {
            "backend": _sanitize_backend(updated, storage.get_pool_snapshot()) if updated else None,
            "probe": probe_res,
        }

    @router.post("/api/admin/backends/test", dependencies=[Depends(require_admin)])
    async def test_backend_config(payload: TestBackendRequest) -> dict[str, Any]:
        existing = await db.get_backend(payload.backend_id) if payload.backend_id else None
        cred_enc = (
            crypto.encrypt_secret(payload.credential)
            if payload.credential
            else (existing.get("credential_enc", "") if existing else "")
        )
        pass_enc = (
            crypto.encrypt_secret(payload.passphrase)
            if payload.passphrase
            else (existing.get("passphrase_enc", "") if existing else "")
        )
        ephemeral = {
            "id": f"test-{secrets.token_hex(6)}",
            "protocol": payload.protocol,
            "host": payload.host.strip(),
            "port": payload.port,
            "username": payload.username.strip(),
            "auth_type": "none" if payload.protocol == "local" else payload.auth_type,
            "credential_enc": cred_enc,
            "passphrase_enc": pass_enc,
            "base_path": payload.base_path.strip(),
            "max_connections": payload.max_connections,
            "idle_timeout_sec": payload.idle_timeout_sec,
        }
        return await storage.probe_backend(ephemeral, persist_status=False)

    @router.post("/api/admin/backends/probe-all", dependencies=[Depends(require_admin)])
    async def probe_all_backends() -> dict[str, Any]:
        rows = [b for b in await db.list_backends() if b["is_active"]]
        results = await asyncio.gather(*(storage.probe_backend(b) for b in rows))
        ok_count = sum(1 for r in results if r.get("ok"))
        return {"total": len(rows), "ok": ok_count}

    @router.post("/api/admin/backends/{backend_id}/probe", dependencies=[Depends(require_admin)])
    async def probe_backend(backend_id: str) -> dict[str, Any]:
        backend = await db.get_backend(backend_id)
        if not backend:
            raise HTTPException(status_code=404, detail="Backend not found")
        return await storage.probe_backend(backend)

    @router.delete("/api/admin/backends/{backend_id}", dependencies=[Depends(require_admin)])
    async def delete_backend(backend_id: str) -> dict[str, Any]:
        backend = await db.get_backend(backend_id)
        if not backend:
            raise HTTPException(status_code=404, detail="Backend not found")
        try:
            await db.delete_backend(backend_id)
        except Exception as exc:
            raise HTTPException(
                status_code=409,
                detail="Cannot delete backend while objects or multipart parts still reference it",
            ) from exc
        await storage.invalidate_backend_pool(backend_id)
        return {"ok": True}

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------
    def _sanitize_user(u: dict[str, Any]) -> dict[str, Any]:
        u.pop("secret_key_enc", None)
        u.pop("password_hash", None)
        return u

    @router.get("/api/admin/users", dependencies=[Depends(require_admin)])
    async def list_users() -> dict[str, Any]:
        rows = await db.list_users()
        return {"users": [_sanitize_user(r) for r in rows]}

    @router.post("/api/admin/users", dependencies=[Depends(require_admin)])
    async def create_user(payload: CreateUserRequest) -> dict[str, Any]:
        ak = (payload.access_key or "").strip() or _generate_ak()
        sk = (payload.secret_key or "").strip() or _generate_sk()
        try:
            user = await db.create_user(
                username=payload.username.strip(),
                access_key=ak,
                secret_key_enc=crypto.encrypt_secret(sk),
                encryption_enabled=payload.encryption_enabled,
                quota_bytes=payload.quota_bytes,
                is_active=payload.is_active,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        _sanitize_user(user)
        user["secret_key"] = sk
        return {"user": user}

    @router.patch("/api/admin/users/{user_id}", dependencies=[Depends(require_admin)])
    async def update_user(user_id: str, payload: UpdateUserRequest) -> dict[str, Any]:
        updated = await db.update_user(
            user_id,
            is_active=payload.is_active,
            encryption_enabled=payload.encryption_enabled,
            quota_bytes=payload.quota_bytes,
        )
        if not updated:
            raise HTTPException(status_code=404, detail="User not found")
        return {"user": _sanitize_user(updated)}

    @router.post("/api/admin/users/{user_id}/rotate-keys", dependencies=[Depends(require_admin)])
    async def rotate_user_keys(user_id: str) -> dict[str, Any]:
        new_ak = _generate_ak()
        new_sk = _generate_sk()
        updated = await db.update_user(
            user_id, access_key=new_ak, secret_key_enc=crypto.encrypt_secret(new_sk)
        )
        if not updated:
            raise HTTPException(status_code=404, detail="User not found")
        _sanitize_user(updated)
        updated["secret_key"] = new_sk
        return {"user": updated}

    @router.post("/api/admin/users/{user_id}/reveal-secret", dependencies=[Depends(require_admin)])
    async def reveal_user_secret(user_id: str) -> dict[str, Any]:
        user = await db.get_user(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return {
            "access_key": user["access_key"],
            "secret_key": crypto.decrypt_secret(user["secret_key_enc"]),
        }

    @router.delete("/api/admin/users/{user_id}", dependencies=[Depends(require_admin)])
    async def delete_user(user_id: str) -> dict[str, Any]:
        user = await db.get_user(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        orphans = await db.delete_user(user_id)
        if orphans:
            await storage.delete_remote_files(orphans)
        return {"ok": True}

    # ------------------------------------------------------------------
    # User-Backend Bindings
    # ------------------------------------------------------------------
    @router.get("/api/admin/bindings", dependencies=[Depends(require_admin)])
    async def list_bindings(user_id: Optional[str] = Query(default=None)) -> dict[str, Any]:
        return {"bindings": await db.list_user_backends(user_id=user_id)}

    @router.post("/api/admin/bindings", dependencies=[Depends(require_admin)])
    async def upsert_binding(payload: UpsertBindingRequest) -> dict[str, Any]:
        if not await db.get_user(payload.user_id):
            raise HTTPException(status_code=404, detail="User not found")
        if not await db.get_backend(payload.backend_id):
            raise HTTPException(status_code=404, detail="Backend not found")
        binding = await db.upsert_user_backend(
            user_id=payload.user_id,
            backend_id=payload.backend_id,
            priority=payload.priority,
            quota_bytes=payload.quota_bytes,
            is_active=payload.is_active,
        )
        return {"binding": binding}

    @router.delete("/api/admin/bindings/{user_id}/{backend_id}", dependencies=[Depends(require_admin)])
    async def delete_binding(user_id: str, backend_id: str) -> dict[str, Any]:
        await db.delete_user_backend(user_id, backend_id)
        return {"ok": True}

    # ------------------------------------------------------------------
    # Buckets & Objects Inspector
    # ------------------------------------------------------------------
    @router.get("/api/admin/buckets", dependencies=[Depends(require_admin)])
    async def list_buckets_admin(user_id: Optional[str] = Query(default=None)) -> dict[str, Any]:
        return {"buckets": await db.list_buckets(owner_user_id=user_id)}

    @router.post("/api/admin/buckets", dependencies=[Depends(require_admin)])
    async def create_bucket_admin(payload: CreateBucketAdminRequest) -> dict[str, Any]:
        if not await db.get_user(payload.owner_user_id):
            raise HTTPException(status_code=404, detail="Owner user not found")
        if await db.get_bucket(payload.name):
            raise HTTPException(status_code=409, detail="Bucket already exists")
        b = await db.create_bucket(payload.name, payload.owner_user_id)
        return {"bucket": b}

    @router.patch("/api/admin/buckets/{bucket}", dependencies=[Depends(require_admin)])
    async def update_bucket_admin(bucket: str, payload: UpdateBucketRequest) -> dict[str, Any]:
        if not await db.get_bucket(bucket):
            raise HTTPException(status_code=404, detail="Bucket not found")
        updated = await db.update_bucket(bucket, acl=payload.acl, cors_rules=payload.cors_rules)
        return {"bucket": updated}

    @router.delete("/api/admin/buckets/{bucket}", dependencies=[Depends(require_admin)])
    async def delete_bucket_admin(bucket: str) -> dict[str, Any]:
        if not await db.get_bucket(bucket):
            raise HTTPException(status_code=404, detail="Bucket not found")
        if await db.count_bucket_objects(bucket) > 0:
            raise HTTPException(status_code=409, detail="Bucket is not empty")
        await db.delete_bucket(bucket)
        return {"ok": True}

    # ------------------------------------------------------------------
    # Bucket & Storage Requests Approval
    # ------------------------------------------------------------------
    @router.get("/api/admin/bucket-requests", dependencies=[Depends(require_admin)])
    async def list_bucket_requests_admin(status: Optional[str] = Query(default=None)) -> dict[str, Any]:
        return {"requests": await db.list_bucket_requests(status=status)}

    @router.post("/api/admin/bucket-requests/{request_id}/approve", dependencies=[Depends(require_admin)])
    async def approve_bucket_request_admin(
        request_id: str, payload: ApproveBucketRequestPayload
    ) -> dict[str, Any]:
        req = await db.get_bucket_request(request_id)
        if not req:
            raise HTTPException(status_code=404, detail="申请记录不存在")
        if req["status"] != "pending":
            raise HTTPException(status_code=409, detail="该申请已被处理")
        if await db.get_bucket(req["bucket_name"]):
            raise HTTPException(status_code=409, detail="目标 Bucket 名称已存在")

        existing_bindings = await db.list_user_backends(user_id=req["user_id"])
        if not existing_bindings and not payload.backend_ids:
            raise HTTPException(status_code=400, detail="请至少选择一个后端存储节点绑定给该用户")

        base_prio = max((b["priority"] for b in existing_bindings), default=0)
        for i, bid in enumerate(payload.backend_ids, start=1):
            if not await db.get_backend(bid):
                raise HTTPException(status_code=404, detail=f"存储节点不存在: {bid}")
            await db.upsert_user_backend(
                user_id=req["user_id"],
                backend_id=bid,
                priority=base_prio + i * 10,
                quota_bytes=0,
                is_active=True,
            )

        if payload.user_quota_bytes is not None:
            await db.update_user(req["user_id"], quota_bytes=payload.user_quota_bytes)

        bucket = await db.create_bucket(req["bucket_name"], req["user_id"], acl=req["acl"])
        updated_req = await db.update_bucket_request_status(
            request_id, "approved", admin_note=payload.admin_note.strip()
        )
        return {"request": updated_req, "bucket": bucket}

    @router.post("/api/admin/bucket-requests/{request_id}/reject", dependencies=[Depends(require_admin)])
    async def reject_bucket_request_admin(
        request_id: str, payload: RejectBucketRequestPayload
    ) -> dict[str, Any]:
        req = await db.get_bucket_request(request_id)
        if not req:
            raise HTTPException(status_code=404, detail="申请记录不存在")
        if req["status"] != "pending":
            raise HTTPException(status_code=409, detail="该申请已被处理")
        updated_req = await db.update_bucket_request_status(
            request_id, "rejected", admin_note=payload.admin_note.strip()
        )
        return {"request": updated_req}

    @router.get("/api/admin/buckets/{bucket}/objects", dependencies=[Depends(require_admin)])
    async def list_objects_admin(
        bucket: str,
        prefix: str = Query(default=""),
        delimiter: str = Query(default="/"),
        max_keys: int = Query(default=500, ge=1, le=1000),
    ) -> dict[str, Any]:
        if not await db.get_bucket(bucket):
            raise HTTPException(status_code=404, detail="Bucket not found")
        return await db.list_objects(bucket, prefix=prefix, delimiter=delimiter, max_keys=max_keys)

    @router.post("/api/admin/buckets/{bucket}/folders", dependencies=[Depends(require_admin)])
    async def create_folder_admin(bucket: str, payload: CreateFolderRequest) -> dict[str, Any]:
        b = await db.get_bucket(bucket)
        if not b:
            raise HTTPException(status_code=404, detail="Bucket not found")
        owner = await db.get_user(b["owner_user_id"])
        if not owner:
            raise HTTPException(status_code=404, detail="Bucket owner not found")
        obj = await create_folder_marker(settings, db, storage, b, owner, payload.folder)
        return {"object": obj}

    @router.post("/api/admin/buckets/{bucket}/upload", dependencies=[Depends(require_admin)])
    async def upload_object_admin(
        bucket: str, request: Request, key: str = Query(...)
    ) -> dict[str, Any]:
        b = await db.get_bucket(bucket)
        if not b:
            raise HTTPException(status_code=404, detail="Bucket not found")
        owner = await db.get_user(b["owner_user_id"])
        if not owner:
            raise HTTPException(status_code=404, detail="Bucket owner not found")
        obj = await upload_object_from_request(request, settings, db, storage, b, owner, key)
        return {"object": obj}

    @router.post("/api/admin/buckets/{bucket}/presign", dependencies=[Depends(require_admin)])
    async def presign_object_admin(
        bucket: str, payload: PresignRequest, request: Request
    ) -> dict[str, Any]:
        b = await db.get_bucket(bucket)
        if not b:
            raise HTTPException(status_code=404, detail="Bucket not found")
        if not await db.get_object(bucket, payload.key):
            raise HTTPException(status_code=404, detail="Object not found")
        owner = await db.get_user(b["owner_user_id"])
        if not owner:
            raise HTTPException(status_code=404, detail="Bucket owner not found")
        return build_share_urls(
            request, settings, crypto, b, owner, payload.key, payload.expires_seconds
        )

    @router.post("/api/admin/buckets/{bucket}/delete-batch", dependencies=[Depends(require_admin)])
    async def delete_batch_admin(bucket: str, payload: DeleteBatchRequest) -> dict[str, Any]:
        if not await db.get_bucket(bucket):
            raise HTTPException(status_code=404, detail="Bucket not found")
        cnt = await delete_batch_keys_and_prefixes(
            db, storage, bucket, payload.keys, payload.prefixes
        )
        return {"deleted": cnt}

    @router.get("/api/admin/buckets/{bucket}/objects/inspect", dependencies=[Depends(require_admin)])
    async def inspect_object_admin(bucket: str, key: str = Query(...)) -> dict[str, Any]:
        found = await db.get_object_with_segments(bucket, key)
        if not found:
            raise HTTPException(status_code=404, detail="Object not found")
        obj, segs = found
        backends = {b["id"]: b["name"] for b in await db.list_backends()}
        for s in segs:
            s.pop("wrapped_dek", None)
            s["backend_name"] = backends.get(s["backend_id"], s["backend_id"])
        return {"object": obj, "segments": segs}

    @router.get("/api/admin/buckets/{bucket}/objects/download", dependencies=[Depends(require_admin)])
    async def download_object_admin(
        bucket: str, key: str = Query(...), inline: bool = Query(default=False)
    ) -> Response:
        return await stream_object_response(db, storage, bucket, key, inline=inline)

    @router.delete("/api/admin/buckets/{bucket}/objects", dependencies=[Depends(require_admin)])
    async def delete_object_admin(bucket: str, key: str = Query(...)) -> dict[str, Any]:
        deleted, orphans = await db.delete_object(bucket, key)
        if not deleted:
            raise HTTPException(status_code=404, detail="Object not found")
        if orphans:
            await storage.delete_remote_files(orphans)
        return {"ok": True}

    @router.post("/api/admin/buckets/{bucket}/objects/rename", dependencies=[Depends(require_admin)])
    async def rename_object_admin(bucket: str, payload: RenameObjectRequest) -> dict[str, Any]:
        if not await db.get_bucket(bucket):
            raise HTTPException(status_code=404, detail="Bucket not found")
        obj = await rename_bucket_object(db, bucket, payload.old_key, payload.new_key)
        return {"object": obj}

    @router.post("/api/admin/buckets/{bucket}/multipart/init", dependencies=[Depends(require_admin)])
    async def multipart_init_admin(bucket: str, payload: InitMultipartRequest) -> dict[str, Any]:
        b = await db.get_bucket(bucket)
        if not b:
            raise HTTPException(status_code=404, detail="Bucket not found")
        owner = await db.get_user(b["owner_user_id"])
        if not owner:
            raise HTTPException(status_code=404, detail="Bucket owner not found")
        return await init_web_multipart(
            db, b, owner, payload.key, payload.content_type, payload.total_size
        )

    @router.post("/api/admin/buckets/{bucket}/multipart/{upload_id}/part", dependencies=[Depends(require_admin)])
    async def multipart_part_admin(
        bucket: str, upload_id: str, request: Request, part_number: int = Query(...)
    ) -> dict[str, Any]:
        b = await db.get_bucket(bucket)
        if not b:
            raise HTTPException(status_code=404, detail="Bucket not found")
        owner = await db.get_user(b["owner_user_id"])
        if not owner:
            raise HTTPException(status_code=404, detail="Bucket owner not found")
        return await upload_web_multipart_part(
            request, settings, db, storage, b, owner, upload_id, part_number
        )

    @router.post("/api/admin/buckets/{bucket}/multipart/{upload_id}/complete", dependencies=[Depends(require_admin)])
    async def multipart_complete_admin(bucket: str, upload_id: str) -> dict[str, Any]:
        b = await db.get_bucket(bucket)
        if not b:
            raise HTTPException(status_code=404, detail="Bucket not found")
        owner = await db.get_user(b["owner_user_id"])
        if not owner:
            raise HTTPException(status_code=404, detail="Bucket owner not found")
        obj = await complete_web_multipart(db, storage, b, owner, upload_id)
        return {"object": obj}

    @router.delete("/api/admin/buckets/{bucket}/multipart/{upload_id}", dependencies=[Depends(require_admin)])
    async def multipart_abort_admin(bucket: str, upload_id: str) -> dict[str, Any]:
        if not await db.get_bucket(bucket):
            raise HTTPException(status_code=404, detail="Bucket not found")
        return await abort_web_multipart(db, storage, bucket, upload_id)

    # ------------------------------------------------------------------
    # Encrypted Disaster-Recovery Vault Backup
    # ------------------------------------------------------------------
    @router.post("/api/admin/backup/download", dependencies=[Depends(require_admin)])
    async def backup_download(payload: BackupDownloadRequest) -> Response:
        vault = await asyncio.to_thread(
            create_vault_bytes,
            settings.data_dir,
            settings.resolve_db_path(),
            payload.passphrase,
        )
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        fname = f"banoss-vault-{ts}.vault"
        return Response(
            content=vault,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{fname}"',
                "Content-Length": str(len(vault)),
            },
        )

    @router.post("/api/admin/backup/push", dependencies=[Depends(require_admin)])
    async def backup_push(payload: BackupPushRequest) -> dict[str, Any]:
        backend = await db.get_backend(payload.backend_id)
        if not backend:
            raise HTTPException(status_code=404, detail="Backend not found")
        vault = await asyncio.to_thread(
            create_vault_bytes,
            settings.data_dir,
            settings.resolve_db_path(),
            payload.passphrase,
        )
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        rel_path = (payload.remote_path or f".banoss_backup/banoss-vault-{ts}.vault").lstrip("/")

        async def _once():
            yield vault

        res = await storage.write_stream(
            backend,
            rel_path,
            _once(),
            segment_id=rel_path,
            encrypt=False,
        )
        return {
            "ok": True,
            "backend_name": backend["name"],
            "remote_path": res.remote_path,
            "size": res.plain_size,
        }

    return router
