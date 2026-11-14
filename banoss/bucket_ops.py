"""Shared bucket & object management operations used by both Admin and User Console APIs."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any, Optional
from urllib.parse import quote

from fastapi import HTTPException, Request, Response
from fastapi.responses import StreamingResponse

from banoss.config import Settings
from banoss.crypto import CryptoService, encrypted_size
from banoss.db import Database
from banoss.s3_auth import generate_presigned_v4_url
from banoss.storage import StorageManager, make_segment_rel_path


async def check_user_quota_or_413(db: Database, user: dict[str, Any], incoming_bytes: int) -> None:
    quota = int(user["quota_bytes"])
    if quota <= 0:
        return
    used = await db.get_user_logical_used_bytes(user["id"])
    if used + max(0, incoming_bytes) > quota:
        raise HTTPException(status_code=413, detail="User storage quota exceeded")


async def upload_object_from_request(
    request: Request,
    settings: Settings,
    db: Database,
    storage: StorageManager,
    bucket_row: dict[str, Any],
    owner_user: dict[str, Any],
    key: str,
) -> dict[str, Any]:
    clean_key = key.lstrip("/")
    if not clean_key:
        raise HTTPException(status_code=400, detail="Object key cannot be empty")

    len_hdr = request.headers.get("content-length")
    expected_plain = int(len_hdr) if len_hdr and len_hdr.isdigit() else 0
    await check_user_quota_or_413(db, owner_user, expected_plain)

    encrypt = bool(owner_user["encryption_enabled"])
    needed_remote = encrypted_size(expected_plain, settings.chunk_size) if encrypt else expected_plain
    backend = await db.select_writable_backend_for_user(
        owner_user["id"], needed_bytes=needed_remote
    )
    if not backend:
        raise HTTPException(
            status_code=507,
            detail="No active writable storage backend bound to bucket owner has sufficient quota",
        )

    segment_id = str(uuid.uuid4())
    rel_path = make_segment_rel_path(segment_id)

    async def _stream():
        async for chunk in request.stream():
            if chunk:
                yield chunk

    write_res = await storage.write_stream(
        backend,
        rel_path,
        _stream(),
        segment_id=rel_path,
        encrypt=encrypt,
        chunk_size=settings.chunk_size,
    )

    if expected_plain == 0 and write_res.plain_size > 0:
        try:
            await check_user_quota_or_413(db, owner_user, write_res.plain_size)
        except HTTPException:
            await storage.delete_remote_files([(backend["id"], write_res.remote_path)])
            raise

    content_type = request.headers.get("content-type", "application/octet-stream")
    obj, orphans = await db.put_object_with_segments(
        bucket=bucket_row["name"],
        key=clean_key,
        size=write_res.plain_size,
        etag=write_res.etag,
        content_type=content_type,
        metadata={},
        segments=[
            {
                "id": segment_id,
                "segment_index": 0,
                "plain_offset": 0,
                "plain_size": write_res.plain_size,
                "remote_size": write_res.remote_size,
                "backend_id": backend["id"],
                "remote_path": write_res.remote_path,
                "encrypted": write_res.encrypted,
                "wrapped_dek": write_res.wrapped_dek,
                "nonce_prefix_b64": write_res.nonce_prefix_b64,
                "chunk_size": write_res.chunk_size,
            }
        ],
    )
    if orphans:
        await storage.delete_remote_files(orphans)
    return obj


async def create_folder_marker(
    settings: Settings,
    db: Database,
    storage: StorageManager,
    bucket_row: dict[str, Any],
    owner_user: dict[str, Any],
    folder: str,
) -> dict[str, Any]:
    clean = folder.strip("/")
    if not clean:
        raise HTTPException(status_code=400, detail="Folder name cannot be empty")
    folder_key = f"{clean}/"
    existing = await db.get_object(bucket_row["name"], folder_key)
    if existing:
        return existing

    backend = await db.select_writable_backend_for_user(owner_user["id"], needed_bytes=0)
    if not backend:
        raise HTTPException(
            status_code=507,
            detail="No active writable storage backend bound to bucket owner",
        )

    segment_id = str(uuid.uuid4())
    rel_path = make_segment_rel_path(segment_id)

    async def _empty():
        if False:
            yield b""

    write_res = await storage.write_stream(
        backend,
        rel_path,
        _empty(),
        segment_id=rel_path,
        encrypt=bool(owner_user["encryption_enabled"]),
        chunk_size=settings.chunk_size,
    )
    obj, orphans = await db.put_object_with_segments(
        bucket=bucket_row["name"],
        key=folder_key,
        size=0,
        etag=write_res.etag,
        content_type="application/x-directory",
        metadata={},
        segments=[
            {
                "id": segment_id,
                "segment_index": 0,
                "plain_offset": 0,
                "plain_size": 0,
                "remote_size": write_res.remote_size,
                "backend_id": backend["id"],
                "remote_path": write_res.remote_path,
                "encrypted": write_res.encrypted,
                "wrapped_dek": write_res.wrapped_dek,
                "nonce_prefix_b64": write_res.nonce_prefix_b64,
                "chunk_size": write_res.chunk_size,
            }
        ],
    )
    if orphans:
        await storage.delete_remote_files(orphans)
    return obj


async def delete_batch_keys_and_prefixes(
    db: Database,
    storage: StorageManager,
    bucket: str,
    keys: list[str],
    prefixes: list[str],
) -> int:
    deleted_count = 0
    all_orphans: list[tuple[str, str]] = []
    for k in keys:
        ok, orphans = await db.delete_object(bucket, k)
        if ok:
            deleted_count += 1
        all_orphans.extend(orphans)
    for p in prefixes:
        if not p:
            continue
        cnt, orphans = await db.delete_objects_by_prefix(bucket, p)
        deleted_count += cnt
        all_orphans.extend(orphans)
    if all_orphans:
        await storage.delete_remote_files(all_orphans)
    return deleted_count


def build_share_urls(
    request: Request,
    settings: Settings,
    crypto: CryptoService,
    bucket_row: dict[str, Any],
    owner_user: dict[str, Any],
    key: str,
    expires_seconds: int,
) -> dict[str, Optional[str]]:
    from urllib.parse import quote

    base_url = str(request.base_url).rstrip("/")
    host_header = request.headers.get("host") or f"{settings.host}:{settings.port}"
    secret_key = crypto.decrypt_secret(owner_user["secret_key_enc"])
    presigned_url = generate_presigned_v4_url(
        base_url=base_url,
        host_header=host_header,
        bucket=bucket_row["name"],
        key=key,
        access_key=owner_user["access_key"],
        secret_key=secret_key,
        region=settings.region,
        expires_seconds=expires_seconds,
    )
    public_url: Optional[str] = None
    if bucket_row.get("acl") == "public-read":
        encoded_key = "/".join(quote(seg, safe="-_.~") for seg in key.lstrip("/").split("/"))
        public_url = f"{base_url}/{quote(bucket_row['name'], safe='-_.~')}/{encoded_key}"
    return {"presigned_url": presigned_url, "public_url": public_url}


async def stream_object_response(
    db: Database,
    storage: StorageManager,
    bucket: str,
    key: str,
    *,
    inline: bool = False,
) -> Response:
    found = await db.get_object_with_segments(bucket, key)
    if not found:
        raise HTTPException(status_code=404, detail="Object not found")
    obj, segs = found
    size = int(obj["size"])
    filename = key.rstrip("/").rsplit("/", 1)[-1] or "download"
    ascii_fallback = "".join(ch if 32 <= ord(ch) < 127 and ch not in '"\\' else "_" for ch in filename) or "download"
    disp = "inline" if inline else "attachment"
    ctype = obj["content_type"] or "application/octet-stream"
    headers = {
        "Content-Length": str(size),
        "Content-Disposition": f"{disp}; filename=\"{ascii_fallback}\"; filename*=UTF-8''{quote(filename)}",
    }
    if size == 0:
        return Response(content=b"", status_code=200, media_type=ctype, headers=headers)
    return StreamingResponse(
        storage.stream_object_range(segs, 0, size - 1),
        media_type=ctype,
        headers=headers,
    )


async def rename_bucket_object(
    db: Database, bucket: str, old_key: str, new_key: str
) -> dict[str, Any]:
    clean_old = old_key.lstrip("/")
    clean_new = new_key.lstrip("/")
    if not clean_old or not clean_new:
        raise HTTPException(status_code=400, detail="Source and target keys cannot be empty")
    try:
        updated = await db.rename_object(bucket, clean_old, clean_new)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="Source object not found")
    return updated


async def init_web_multipart(
    db: Database,
    bucket_row: dict[str, Any],
    owner_user: dict[str, Any],
    key: str,
    content_type: str = "application/octet-stream",
    total_size: int = 0,
) -> dict[str, Any]:
    clean_key = key.lstrip("/")
    if not clean_key:
        raise HTTPException(status_code=400, detail="Object key cannot be empty")
    if total_size > 0:
        await check_user_quota_or_413(db, owner_user, total_size)
    upload = await db.create_multipart_upload(
        bucket=bucket_row["name"],
        key=clean_key,
        user_id=owner_user["id"],
        content_type=content_type or "application/octet-stream",
        metadata={},
    )
    return {"upload_id": upload["upload_id"], "key": clean_key}


async def upload_web_multipart_part(
    request: Request,
    settings: Settings,
    db: Database,
    storage: StorageManager,
    bucket_row: dict[str, Any],
    owner_user: dict[str, Any],
    upload_id: str,
    part_number: int,
) -> dict[str, Any]:
    if part_number < 1 or part_number > 10000:
        raise HTTPException(status_code=400, detail="part_number must be between 1 and 10000")
    upload = await db.get_multipart_upload(upload_id)
    if not upload or upload["bucket"] != bucket_row["name"]:
        raise HTTPException(status_code=404, detail="Multipart upload not found")

    len_hdr = request.headers.get("content-length")
    expected_plain = int(len_hdr) if len_hdr and len_hdr.isdigit() else 0
    encrypt = bool(owner_user["encryption_enabled"])
    needed_remote = encrypted_size(expected_plain, settings.chunk_size) if encrypt else expected_plain
    backend = await db.select_writable_backend_for_user(
        owner_user["id"], needed_bytes=needed_remote
    )
    if not backend:
        raise HTTPException(
            status_code=507,
            detail="No active writable storage backend bound to bucket owner has sufficient quota",
        )

    part_id = str(uuid.uuid4())
    rel_path = f"parts/{upload_id}/{part_number:05d}_{part_id}"

    async def _stream():
        async for chunk in request.stream():
            if chunk:
                yield chunk

    write_res = await storage.write_stream(
        backend,
        rel_path,
        _stream(),
        segment_id=rel_path,
        encrypt=encrypt,
        chunk_size=settings.chunk_size,
    )
    orphans = await db.upsert_multipart_part(
        part_id=part_id,
        upload_id=upload_id,
        part_number=part_number,
        etag=write_res.etag,
        plain_size=write_res.plain_size,
        remote_size=write_res.remote_size,
        backend_id=backend["id"],
        remote_path=write_res.remote_path,
        encrypted=write_res.encrypted,
        wrapped_dek=write_res.wrapped_dek,
        nonce_prefix_b64=write_res.nonce_prefix_b64,
        chunk_size=write_res.chunk_size,
    )
    if orphans:
        await storage.delete_remote_files(orphans)
    return {"part_number": part_number, "etag": write_res.etag, "size": write_res.plain_size}


async def complete_web_multipart(
    db: Database,
    storage: StorageManager,
    bucket_row: dict[str, Any],
    owner_user: dict[str, Any],
    upload_id: str,
) -> dict[str, Any]:
    upload = await db.get_multipart_upload(upload_id)
    if not upload or upload["bucket"] != bucket_row["name"]:
        raise HTTPException(status_code=404, detail="Multipart upload not found")
    parts = await db.list_multipart_parts(upload_id)
    if not parts:
        raise HTTPException(status_code=400, detail="No parts uploaded")

    total_size = sum(int(p["plain_size"]) for p in parts)
    await check_user_quota_or_413(db, owner_user, total_size)

    md5_concat = bytearray()
    for p in parts:
        md5_concat.extend(bytes.fromhex(p["etag"]))
    final_etag = f"{hashlib.md5(bytes(md5_concat)).hexdigest()}-{len(parts)}"
    obj, orphans = await db.complete_multipart_upload(
        upload=upload, selected_parts=parts, etag=final_etag
    )
    if orphans:
        await storage.delete_remote_files(orphans)
    return obj


async def abort_web_multipart(
    db: Database,
    storage: StorageManager,
    bucket_name: str,
    upload_id: str,
) -> dict[str, Any]:
    upload = await db.get_multipart_upload(upload_id)
    if not upload or upload["bucket"] != bucket_name:
        raise HTTPException(status_code=404, detail="Multipart upload not found")
    _, orphans = await db.abort_multipart_upload(upload_id)
    if orphans:
        await storage.delete_remote_files(orphans)
    return {"ok": True}
