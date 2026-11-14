"""Self-service OSS User Console REST API (AK/SK session login, Bucket/Folder/Upload/Share)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, model_validator

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
from banoss.crypto import CryptoService
from banoss.db import Database
from banoss.storage import StorageManager

STATIC_DIR = Path(__file__).parent / "static"


_BUCKET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def _verify_password(password: str, stored: str) -> bool:
    if not stored or not stored.startswith("scrypt$"):
        return False
    parts = stored.split("$")
    if len(parts) != 3:
        return False
    try:
        salt = base64.b64decode(parts[1])
        expected = base64.b64decode(parts[2])
    except Exception:
        return False
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=len(expected))
    return hmac.compare_digest(dk, expected)


class ConsoleLoginRequest(BaseModel):
    account: Optional[str] = None
    secret: Optional[str] = None
    access_key: Optional[str] = None
    secret_key: Optional[str] = None

    @model_validator(mode="after")
    def _normalize_fields(self) -> "ConsoleLoginRequest":
        acc = (self.account or self.access_key or "").strip()
        sec = (self.secret or self.secret_key or "").strip()
        if not acc or not sec:
            raise ValueError("请输入用户名/Access Key 与密码/Secret Key")
        self.account = acc
        self.secret = sec
        return self


class ConsoleRegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,31}$")
    password: str = Field(min_length=6, max_length=128)
    bucket_name: Optional[str] = None
    bucket_acl: str = Field(default="private", pattern="^(private|public-read)$")
    requested_quota_bytes: int = Field(default=0, ge=0)
    reason: str = Field(default="", max_length=500)


class CreateBucketRequestPayload(BaseModel):
    bucket_name: str = Field(min_length=3, max_length=63, pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
    acl: str = Field(default="private", pattern="^(private|public-read)$")
    requested_quota_bytes: int = Field(default=0, ge=0)
    reason: str = Field(default="", max_length=500)


class CreateBucketConsoleRequest(BaseModel):
    name: str = Field(min_length=3, max_length=63, pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
    acl: str = Field(default="private", pattern="^(private|public-read)$")


class UpdateBucketRequest(BaseModel):
    acl: Optional[str] = Field(default=None, pattern="^(private|public-read)$")
    cors_rules: Optional[list[dict[str, Any]]] = None


class CreateFolderRequest(BaseModel):
    folder: str = Field(min_length=1, max_length=512)


class DeleteBatchRequest(BaseModel):
    keys: list[str] = Field(default_factory=list)
    prefixes: list[str] = Field(default_factory=list)


class PresignRequest(BaseModel):
    key: str = Field(min_length=1)
    expires_seconds: int = Field(default=3600, ge=60, le=604800)


class RenameObjectRequest(BaseModel):
    old_key: str = Field(min_length=1)
    new_key: str = Field(min_length=1)


class InitMultipartRequest(BaseModel):
    key: str = Field(min_length=1)
    content_type: str = "application/octet-stream"
    total_size: int = Field(default=0, ge=0)


def _sign_session(session_key: bytes, user_id: str, ttl_sec: int = 86400 * 7) -> str:
    exp = int(time.time()) + ttl_sec
    payload = f"{user_id}:{exp}"
    sig = hmac.new(session_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def _verify_session(session_key: bytes, token: str) -> Optional[str]:
    parts = token.split(":")
    if len(parts) != 3:
        return None
    user_id, exp_str, sig = parts
    try:
        exp = int(exp_str)
    except ValueError:
        return None
    if time.time() > exp:
        return None
    payload = f"{user_id}:{exp_str}"
    expected = hmac.new(session_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return None
    return user_id


def create_console_router(
    settings: Settings,
    session_key: bytes,
    db: Database,
    crypto: CryptoService,
    storage: StorageManager,
) -> APIRouter:
    router = APIRouter()

    async def require_console_user(
        banoss_console: Optional[str] = Cookie(default=None),
    ) -> dict[str, Any]:
        if not banoss_console:
            raise HTTPException(status_code=401, detail="Not logged in")
        user_id = _verify_session(session_key, banoss_console)
        if not user_id:
            raise HTTPException(status_code=401, detail="Session expired or invalid")
        user = await db.get_user(user_id)
        if not user or not user["is_active"]:
            raise HTTPException(status_code=401, detail="User not found or disabled")
        return user

    async def require_owned_bucket(bucket: str, user: dict[str, Any]) -> dict[str, Any]:
        b = await db.get_bucket(bucket)
        if not b:
            raise HTTPException(status_code=404, detail="Bucket not found")
        if b["owner_user_id"] != user["id"]:
            raise HTTPException(status_code=403, detail="Access denied")
        return b

    @router.get("/console", include_in_schema=False)
    @router.get("/console/", include_in_schema=False)
    async def console_ui() -> FileResponse:
        return FileResponse(STATIC_DIR / "console.html", media_type="text/html")

    def _safe_request_view(r: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": r["id"],
            "bucket_name": r["bucket_name"],
            "acl": r["acl"],
            "requested_quota_bytes": r["requested_quota_bytes"],
            "reason": r["reason"],
            "status": r["status"],
            "admin_note": r["admin_note"],
            "reviewed_at": r["reviewed_at"],
            "created_at": r["created_at"],
        }

    @router.post("/api/console/register")
    async def console_register(payload: ConsoleRegisterRequest, response: Response) -> dict[str, Any]:
        uname = payload.username.strip()
        if await db.get_user_by_username(uname):
            raise HTTPException(status_code=409, detail="用户名已存在，请更换或直接登录")
        bname = (payload.bucket_name or "").strip().lower()
        if bname:
            if not _BUCKET_NAME_RE.match(bname):
                raise HTTPException(
                    status_code=400,
                    detail="Bucket 名称需为 3~63 位小写字母、数字、点或连字符",
                )
            if await db.get_bucket(bname) or await db.get_pending_bucket_request_by_name(bname):
                raise HTTPException(status_code=409, detail="该 Bucket 名称已被占用或正在审批中")

        ak = "BANOSS" + secrets.token_hex(7).upper()
        sk = secrets.token_urlsafe(30)
        try:
            user = await db.create_user(
                username=uname,
                access_key=ak,
                secret_key_enc=crypto.encrypt_secret(sk),
                password_hash=_hash_password(payload.password),
                register_note=payload.reason.strip(),
                encryption_enabled=True,
                quota_bytes=0,
                is_active=True,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        req_view = None
        if bname:
            req_row = await db.create_bucket_request(
                user["id"],
                bname,
                acl=payload.bucket_acl,
                requested_quota_bytes=payload.requested_quota_bytes,
                reason=payload.reason.strip(),
            )
            req_view = _safe_request_view(req_row)

        cookie_val = _sign_session(session_key, user["id"])
        response.set_cookie(
            key="banoss_console",
            value=cookie_val,
            httponly=True,
            samesite="lax",
            path="/",
        )
        return {
            "ok": True,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "access_key": ak,
                "secret_key": sk,
            },
            "bucket_request": req_view,
        }

    @router.post("/api/console/login")
    async def console_login(payload: ConsoleLoginRequest, response: Response) -> dict[str, Any]:
        account = payload.account or ""
        secret = payload.secret or ""
        user = await db.get_user_by_access_key(account)
        if user:
            real_sk = crypto.decrypt_secret(user["secret_key_enc"])
            authed = bool(user["is_active"]) and hmac.compare_digest(real_sk, secret)
        else:
            user = await db.get_user_by_username(account)
            authed = bool(user and user["is_active"] and _verify_password(secret, user.get("password_hash", "")))

        if not user or not authed:
            raise HTTPException(status_code=401, detail="账号或密钥/密码错误，或账号已被停用")
        cookie_val = _sign_session(session_key, user["id"])
        response.set_cookie(
            key="banoss_console",
            value=cookie_val,
            httponly=True,
            samesite="lax",
            path="/",
        )
        return {"ok": True, "username": user["username"]}

    @router.post("/api/console/logout")
    async def console_logout(response: Response) -> dict[str, Any]:
        response.delete_cookie("banoss_console", path="/")
        return {"ok": True}

    @router.get("/api/console/me")
    async def console_me(user: dict[str, Any] = Depends(require_console_user)) -> dict[str, Any]:
        quota_info = await db.get_user_opaque_quota_info(user["id"])
        buckets = await db.list_buckets(owner_user_id=user["id"])
        reqs = await db.list_bucket_requests(user_id=user["id"], status="pending")
        return {
            "user": {
                "id": user["id"],
                "username": user["username"],
                "access_key": user["access_key"],
                "encryption_enabled": bool(user["encryption_enabled"]),
                "quota_bytes": user["quota_bytes"],
                "effective_quota_bytes": quota_info["effective_quota_bytes"],
                "used_bytes": quota_info["used_bytes"],
                "has_storage_pool": quota_info["has_storage_pool"],
                "bucket_count": len(buckets),
            },
            "pending_requests_count": len(reqs),
            "region": settings.region,
            "chunk_size": settings.chunk_size,
        }

    @router.post("/api/console/reveal-secret")
    async def console_reveal_secret(user: dict[str, Any] = Depends(require_console_user)) -> dict[str, Any]:
        return {
            "access_key": user["access_key"],
            "secret_key": crypto.decrypt_secret(user["secret_key_enc"]),
        }

    @router.get("/api/console/bucket-requests")
    async def console_list_bucket_requests(
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        rows = await db.list_bucket_requests(user_id=user["id"])
        return {"requests": [_safe_request_view(r) for r in rows]}

    @router.post("/api/console/bucket-requests")
    async def console_create_bucket_request(
        payload: CreateBucketRequestPayload,
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        if await db.get_bucket(payload.bucket_name) or await db.get_pending_bucket_request_by_name(payload.bucket_name):
            raise HTTPException(status_code=409, detail="该 Bucket 名称已被占用或正在审批中")
        row = await db.create_bucket_request(
            user["id"],
            payload.bucket_name,
            acl=payload.acl,
            requested_quota_bytes=payload.requested_quota_bytes,
            reason=payload.reason.strip(),
        )
        return {"request": _safe_request_view(row)}

    @router.get("/api/console/buckets")
    async def console_list_buckets(
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        return {"buckets": await db.list_buckets(owner_user_id=user["id"])}

    @router.post("/api/console/buckets")
    async def console_create_bucket(
        payload: CreateBucketConsoleRequest,
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        quota_info = await db.get_user_opaque_quota_info(user["id"])
        if not quota_info["has_storage_pool"]:
            raise HTTPException(
                status_code=403,
                detail="当前账号尚未开通存储资源，请先提交 Bucket 申请等待管理员审批开通",
            )
        if await db.get_bucket(payload.name):
            raise HTTPException(status_code=409, detail="Bucket already exists")
        b = await db.create_bucket(payload.name, user["id"], acl=payload.acl)
        return {"bucket": b}

    @router.patch("/api/console/buckets/{bucket}")
    async def console_update_bucket(
        bucket: str,
        payload: UpdateBucketRequest,
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        await require_owned_bucket(bucket, user)
        updated = await db.update_bucket(bucket, acl=payload.acl, cors_rules=payload.cors_rules)
        return {"bucket": updated}

    @router.delete("/api/console/buckets/{bucket}")
    async def console_delete_bucket(
        bucket: str,
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        await require_owned_bucket(bucket, user)
        if await db.count_bucket_objects(bucket) > 0:
            raise HTTPException(status_code=409, detail="Bucket is not empty")
        await db.delete_bucket(bucket)
        return {"ok": True}

    @router.get("/api/console/buckets/{bucket}/objects")
    async def console_list_objects(
        bucket: str,
        prefix: str = Query(default=""),
        delimiter: str = Query(default="/"),
        max_keys: int = Query(default=500, ge=1, le=1000),
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        await require_owned_bucket(bucket, user)
        return await db.list_objects(bucket, prefix=prefix, delimiter=delimiter, max_keys=max_keys)

    @router.post("/api/console/buckets/{bucket}/folders")
    async def console_create_folder(
        bucket: str,
        payload: CreateFolderRequest,
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        b = await require_owned_bucket(bucket, user)
        obj = await create_folder_marker(settings, db, storage, b, user, payload.folder)
        return {"object": obj}

    @router.post("/api/console/buckets/{bucket}/upload")
    async def console_upload_object(
        bucket: str,
        request: Request,
        key: str = Query(...),
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        b = await require_owned_bucket(bucket, user)
        obj = await upload_object_from_request(request, settings, db, storage, b, user, key)
        return {"object": obj}

    @router.post("/api/console/buckets/{bucket}/presign")
    async def console_presign_object(
        bucket: str,
        payload: PresignRequest,
        request: Request,
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        b = await require_owned_bucket(bucket, user)
        if not await db.get_object(bucket, payload.key):
            raise HTTPException(status_code=404, detail="Object not found")
        return build_share_urls(
            request, settings, crypto, b, user, payload.key, payload.expires_seconds
        )

    @router.get("/api/console/buckets/{bucket}/objects/inspect")
    async def console_inspect_object(
        bucket: str,
        key: str = Query(...),
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        await require_owned_bucket(bucket, user)
        found = await db.get_object_with_segments(bucket, key)
        if not found:
            raise HTTPException(status_code=404, detail="Object not found")
        obj, segs = found
        return {
            "object": obj,
            "segment_count": len(segs),
            "encrypted": any(bool(s.get("encrypted")) for s in segs),
        }

    @router.get("/api/console/buckets/{bucket}/objects/download")
    async def console_download_object(
        bucket: str,
        key: str = Query(...),
        inline: bool = Query(default=False),
        user: dict[str, Any] = Depends(require_console_user),
    ) -> Response:
        await require_owned_bucket(bucket, user)
        return await stream_object_response(db, storage, bucket, key, inline=inline)

    @router.post("/api/console/buckets/{bucket}/delete-batch")
    async def console_delete_batch(
        bucket: str,
        payload: DeleteBatchRequest,
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        await require_owned_bucket(bucket, user)
        cnt = await delete_batch_keys_and_prefixes(
            db, storage, bucket, payload.keys, payload.prefixes
        )
        return {"deleted": cnt}

    @router.delete("/api/console/buckets/{bucket}/objects")
    async def console_delete_object(
        bucket: str,
        key: str = Query(...),
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        await require_owned_bucket(bucket, user)
        deleted, orphans = await db.delete_object(bucket, key)
        if not deleted:
            raise HTTPException(status_code=404, detail="Object not found")
        if orphans:
            await storage.delete_remote_files(orphans)
        return {"ok": True}

    @router.post("/api/console/buckets/{bucket}/objects/rename")
    async def console_rename_object(
        bucket: str,
        payload: RenameObjectRequest,
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        await require_owned_bucket(bucket, user)
        obj = await rename_bucket_object(db, bucket, payload.old_key, payload.new_key)
        return {"object": obj}

    @router.post("/api/console/buckets/{bucket}/multipart/init")
    async def console_multipart_init(
        bucket: str,
        payload: InitMultipartRequest,
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        b = await require_owned_bucket(bucket, user)
        return await init_web_multipart(
            db, b, user, payload.key, payload.content_type, payload.total_size
        )

    @router.post("/api/console/buckets/{bucket}/multipart/{upload_id}/part")
    async def console_multipart_part(
        bucket: str,
        upload_id: str,
        request: Request,
        part_number: int = Query(...),
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        b = await require_owned_bucket(bucket, user)
        return await upload_web_multipart_part(
            request, settings, db, storage, b, user, upload_id, part_number
        )

    @router.post("/api/console/buckets/{bucket}/multipart/{upload_id}/complete")
    async def console_multipart_complete(
        bucket: str,
        upload_id: str,
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        b = await require_owned_bucket(bucket, user)
        obj = await complete_web_multipart(db, storage, b, user, upload_id)
        return {"object": obj}

    @router.delete("/api/console/buckets/{bucket}/multipart/{upload_id}")
    async def console_multipart_abort(
        bucket: str,
        upload_id: str,
        user: dict[str, Any] = Depends(require_console_user),
    ) -> dict[str, Any]:
        await require_owned_bucket(bucket, user)
        return await abort_web_multipart(db, storage, bucket, upload_id)

    return router
