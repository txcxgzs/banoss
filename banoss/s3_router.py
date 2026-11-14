"""S3-compatible REST API router (Path-Style & Virtual-Hosted Style, Multipart, Range, Copy)."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import formatdate
from typing import Any, Optional
from urllib.parse import parse_qsl, quote, unquote
from xml.sax.saxutils import escape

from fastapi import APIRouter, Request, Response
from fastapi.responses import RedirectResponse, StreamingResponse

from banoss.config import Settings
from banoss.crypto import CryptoService, encrypted_size
from banoss.db import Database
from banoss.s3_auth import (
    AuthenticatedUser,
    S3AuthError,
    has_s3_auth,
    iter_request_payload,
    verify_s3_request,
)
from banoss.storage import StorageManager, make_segment_rel_path

_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


def _xml_error(code: str, message: str, resource: str = "", status_code: int = 400) -> Response:
    req_id = uuid.uuid4().hex[:16]
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<Error>"
        f"<Code>{escape(code)}</Code>"
        f"<Message>{escape(message)}</Message>"
        f"<Resource>{escape(resource)}</Resource>"
        f"<RequestId>{req_id}</RequestId>"
        "</Error>"
    )
    return Response(content=body, status_code=status_code, media_type="application/xml")


def _http_date(iso_str: str) -> str:
    try:
        dt = datetime.strptime(iso_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        dt = datetime.now(timezone.utc)
    return formatdate(dt.timestamp(), usegmt=True)


def _extract_user_metadata(request: Request) -> dict[str, str]:
    meta: dict[str, str] = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk.startswith("x-amz-meta-"):
            meta[lk[len("x-amz-meta-") :]] = v
    return meta


def _parse_bucket_and_key(request: Request, full_path: str, base_domains: list[str]) -> tuple[str, str]:
    """Resolve (bucket, key) supporting both Virtual-Hosted Style and Path Style."""
    host_header = (request.headers.get("host") or "").split(":")[0].lower()
    clean_path = unquote(full_path.lstrip("/"))

    for bd in base_domains:
        bd_low = bd.lower().strip()
        if bd_low and host_header != bd_low and host_header.endswith("." + bd_low):
            bucket = host_header[: -len("." + bd_low)]
            return bucket, clean_path

    if not clean_path:
        return "", ""
    if "/" not in clean_path:
        return clean_path, ""
    bucket, key = clean_path.split("/", 1)
    return bucket, key


def _parse_range_header(range_header: str, total_size: int) -> Optional[tuple[int, int]]:
    """Parse HTTP Range header 'bytes=start-end' into inclusive (start, end)."""
    if not range_header.startswith("bytes="):
        return None
    spec = range_header[len("bytes=") :].strip()
    if "," in spec or "-" not in spec:
        return None
    start_s, end_s = spec.split("-", 1)
    if total_size == 0:
        return None
    if start_s == "":
        # Suffix range: bytes=-N
        suffix = int(end_s)
        if suffix <= 0:
            return None
        start = max(0, total_size - suffix)
        return start, total_size - 1
    start = int(start_s)
    if start < 0 or start >= total_size:
        return None
    if end_s == "":
        return start, total_size - 1
    end = min(int(end_s), total_size - 1)
    if end < start:
        return None
    return start, end


def _match_cors_rule(
    rules: list[dict[str, Any]], origin: str, method: str
) -> Optional[dict[str, Any]]:
    for rule in rules:
        origins = rule.get("allowed_origins") or []
        methods = [m.upper() for m in (rule.get("allowed_methods") or [])]
        if ("*" in origins or origin in origins) and (not methods or method.upper() in methods):
            return rule
    return None


def _apply_cors_headers(
    response: Response, request: Request, bucket_row: Optional[dict[str, Any]], req_method: Optional[str] = None
) -> Response:
    origin = request.headers.get("origin")
    if not origin or not bucket_row:
        return response
    rules = bucket_row.get("cors_rules") or []
    rule = _match_cors_rule(rules, origin, req_method or request.method)
    if not rule:
        return response
    origins = rule.get("allowed_origins") or []
    response.headers["Access-Control-Allow-Origin"] = "*" if "*" in origins else origin
    response.headers["Access-Control-Allow-Methods"] = ", ".join(
        rule.get("allowed_methods") or ["GET", "HEAD", "PUT", "POST", "DELETE"]
    )
    allow_hdrs = rule.get("allowed_headers") or ["*"]
    response.headers["Access-Control-Allow-Headers"] = ", ".join(allow_hdrs)
    expose = rule.get("expose_headers") or ["ETag", "Content-Length", "Content-Range", "Accept-Ranges"]
    response.headers["Access-Control-Expose-Headers"] = ", ".join(expose)
    max_age = rule.get("max_age_seconds")
    if max_age is not None:
        response.headers["Access-Control-Max-Age"] = str(max_age)
    if "*" not in origins:
        response.headers["Vary"] = "Origin"
    return response


def create_s3_router(
    settings: Settings,
    db: Database,
    crypto: CryptoService,
    storage: StorageManager,
) -> APIRouter:
    router = APIRouter()

    @router.api_route("/{full_path:path}", methods=["GET", "PUT", "POST", "DELETE", "HEAD", "OPTIONS"])
    async def s3_dispatch(request: Request, full_path: str = "") -> Response:
        bucket, key = _parse_bucket_and_key(request, full_path, settings.base_domains)
        qp = dict(parse_qsl(request.url.query, keep_blank_values=True))
        method = request.method.upper()

        # Browser landing on '/' without S3 credentials -> redirect to OSS Console
        if not bucket and method == "GET" and not has_s3_auth(request):
            if "text/html" in (request.headers.get("accept") or "").lower():
                return RedirectResponse(url="/console", status_code=302)

        bucket_row = await db.get_bucket(bucket) if bucket else None

        # CORS preflight
        if method == "OPTIONS":
            req_method = request.headers.get("access-control-request-method", "GET")
            resp = Response(status_code=200)
            return _apply_cors_headers(resp, request, bucket_row, req_method=req_method)

        # Anonymous public-read for GET/HEAD object
        auth: Optional[AuthenticatedUser] = None
        if (
            bucket
            and key
            and method in ("GET", "HEAD")
            and "uploadId" not in qp
            and not has_s3_auth(request)
        ):
            if not bucket_row:
                resp = (
                    Response(status_code=404)
                    if method == "HEAD"
                    else _xml_error("NoSuchBucket", "The specified bucket does not exist", f"/{bucket}", 404)
                )
                return _apply_cors_headers(resp, request, None)
            if bucket_row.get("acl") != "public-read":
                resp = (
                    Response(status_code=403)
                    if method == "HEAD"
                    else _xml_error("AccessDenied", "Access Denied", f"/{bucket}/{key}", 403)
                )
                return _apply_cors_headers(resp, request, bucket_row)
        else:
            try:
                auth = await verify_s3_request(
                    request, db, crypto, clock_skew_seconds=settings.clock_skew_seconds
                )
            except S3AuthError as exc:
                return _apply_cors_headers(
                    _xml_error(exc.code, exc.message, request.url.path, exc.status_code),
                    request,
                    bucket_row,
                )

        # Service-level: ListBuckets
        if not bucket:
            if method == "GET" and auth is not None:
                return await _handle_list_buckets(db, auth)
            return _xml_error("MethodNotAllowed", "Method not allowed on service root", "/", 405)

        resp: Response
        # Bucket-level
        if not key:
            assert auth is not None
            if method == "HEAD":
                resp = await _handle_head_bucket(db, auth, bucket)
            elif method == "PUT":
                if "acl" in qp:
                    resp = await _handle_put_bucket_acl(request, db, auth, bucket)
                elif "cors" in qp:
                    resp = await _handle_put_bucket_cors(request, db, auth, bucket)
                else:
                    resp = await _handle_create_bucket(request, db, auth, bucket)
            elif method == "DELETE":
                if "cors" in qp:
                    resp = await _handle_delete_bucket_cors(db, auth, bucket)
                else:
                    resp = await _handle_delete_bucket(db, auth, bucket)
            elif method == "GET":
                if "acl" in qp:
                    resp = await _handle_get_bucket_acl(db, auth, bucket)
                elif "cors" in qp:
                    resp = await _handle_get_bucket_cors(db, auth, bucket)
                elif "uploads" in qp:
                    resp = await _handle_list_multipart_uploads(db, auth, bucket, qp)
                elif qp.get("list-type") == "2":
                    resp = await _handle_list_objects_v2(db, auth, bucket, qp)
                else:
                    resp = await _handle_list_objects_v1(db, auth, bucket, qp)
            elif method == "POST" and "delete" in qp:
                resp = await _handle_delete_objects_batch(request, db, storage, auth, bucket)
            else:
                resp = _xml_error("MethodNotAllowed", f"Unsupported bucket method {method}", f"/{bucket}", 405)
            return _apply_cors_headers(resp, request, bucket_row)

        # Object-level
        if method == "HEAD":
            resp = await _handle_head_object(db, auth, bucket, key)
        elif method == "GET":
            if "uploadId" in qp:
                assert auth is not None
                resp = await _handle_list_parts(db, auth, bucket, key, qp["uploadId"])
            else:
                resp = await _handle_get_object(request, db, storage, auth, bucket, key)
        elif method == "PUT":
            assert auth is not None
            if "partNumber" in qp and "uploadId" in qp:
                resp = await _handle_upload_part(
                    request, settings, db, storage, auth, bucket, key, qp
                )
            elif "x-amz-copy-source" in request.headers:
                resp = await _handle_copy_object(request, db, storage, auth, bucket, key)
            else:
                resp = await _handle_put_object(request, settings, db, storage, auth, bucket, key)
        elif method == "POST":
            assert auth is not None
            if "uploads" in qp:
                resp = await _handle_create_multipart_upload(request, db, auth, bucket, key)
            elif "uploadId" in qp:
                resp = await _handle_complete_multipart_upload(
                    request, db, storage, auth, bucket, key, qp["uploadId"]
                )
            else:
                resp = _xml_error("MethodNotAllowed", f"Unsupported object method {method}", f"/{bucket}/{key}", 405)
        elif method == "DELETE":
            assert auth is not None
            if "uploadId" in qp:
                resp = await _handle_abort_multipart_upload(
                    db, storage, auth, bucket, key, qp["uploadId"]
                )
            else:
                resp = await _handle_delete_object(db, storage, auth, bucket, key)
        else:
            resp = _xml_error("MethodNotAllowed", f"Unsupported object method {method}", f"/{bucket}/{key}", 405)

        return _apply_cors_headers(resp, request, bucket_row)

    return router


# ----------------------------------------------------------------------
# Bucket Handlers
# ----------------------------------------------------------------------
async def _require_owned_bucket(
    db: Database, auth: Optional[AuthenticatedUser], bucket: str
) -> tuple[Optional[dict[str, Any]], Optional[Response]]:
    b = await db.get_bucket(bucket)
    if not b:
        return None, _xml_error("NoSuchBucket", "The specified bucket does not exist", f"/{bucket}", 404)
    if auth is None:
        if b.get("acl") != "public-read":
            return None, _xml_error("AccessDenied", "Access Denied", f"/{bucket}", 403)
    elif b["owner_user_id"] != auth.user["id"]:
        return None, _xml_error("AccessDenied", "Access Denied", f"/{bucket}", 403)
    return b, None


async def _handle_list_buckets(db: Database, auth: AuthenticatedUser) -> Response:
    buckets = await db.list_buckets(owner_user_id=auth.user["id"])
    items = "".join(
        f"<Bucket><Name>{escape(b['name'])}</Name><CreationDate>{escape(b['created_at'])}</CreationDate></Bucket>"
        for b in buckets
    )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"<Owner><ID>{escape(auth.user['id'])}</ID><DisplayName>{escape(auth.user['username'])}</DisplayName></Owner>"
        f"<Buckets>{items}</Buckets>"
        "</ListAllMyBucketsResult>"
    )
    return Response(content=xml, status_code=200, media_type="application/xml")


async def _handle_head_bucket(db: Database, auth: AuthenticatedUser, bucket: str) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return Response(status_code=err.status_code)
    return Response(status_code=200)


async def _handle_create_bucket(
    request: Request, db: Database, auth: AuthenticatedUser, bucket: str
) -> Response:
    if not _BUCKET_RE.match(bucket):
        return _xml_error("InvalidBucketName", "The specified bucket is not valid", f"/{bucket}", 400)
    existing = await db.get_bucket(bucket)
    if existing:
        if existing["owner_user_id"] == auth.user["id"]:
            return _xml_error("BucketAlreadyOwnedByYou", "Your previous request to create the named bucket succeeded", f"/{bucket}", 409)
        return _xml_error("BucketAlreadyExists", "The requested bucket name is not available", f"/{bucket}", 409)
    raw_acl = (request.headers.get("x-amz-acl") or "private").strip().lower()
    acl = "public-read" if raw_acl == "public-read" else "private"
    quota_info = await db.get_user_opaque_quota_info(auth.user["id"])
    if not quota_info["has_storage_pool"]:
        return _xml_error(
            "AccessDenied",
            "Storage quota has not been approved for this account yet",
            f"/{bucket}",
            403,
        )
    await db.create_bucket(bucket, auth.user["id"], acl=acl)
    return Response(status_code=200, headers={"Location": f"/{bucket}"})


async def _handle_get_bucket_acl(db: Database, auth: AuthenticatedUser, bucket: str) -> Response:
    b, err = await _require_owned_bucket(db, auth, bucket)
    if err or not b:
        return err  # type: ignore[return-value]
    public_grant = ""
    if b.get("acl") == "public-read":
        public_grant = (
            "<Grant>"
            '<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">'
            "<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>"
            "</Grantee>"
            "<Permission>READ</Permission>"
            "</Grant>"
        )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"<Owner><ID>{escape(auth.user['id'])}</ID><DisplayName>{escape(auth.user['username'])}</DisplayName></Owner>"
        "<AccessControlList>"
        "<Grant>"
        '<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">'
        f"<ID>{escape(auth.user['id'])}</ID><DisplayName>{escape(auth.user['username'])}</DisplayName>"
        "</Grantee>"
        "<Permission>FULL_CONTROL</Permission>"
        "</Grant>"
        f"{public_grant}"
        "</AccessControlList>"
        "</AccessControlPolicy>"
    )
    return Response(content=xml, status_code=200, media_type="application/xml")


async def _handle_put_bucket_acl(
    request: Request, db: Database, auth: AuthenticatedUser, bucket: str
) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return err
    canned = (request.headers.get("x-amz-acl") or "").strip().lower()
    if canned in ("private", "public-read"):
        acl = canned
    else:
        body = (await request.body()).decode("utf-8", errors="ignore")
        acl = "public-read" if "groups/global/AllUsers" in body and ">READ<" in body else "private"
    await db.update_bucket(bucket, acl=acl)
    return Response(status_code=200)


async def _handle_get_bucket_cors(db: Database, auth: AuthenticatedUser, bucket: str) -> Response:
    b, err = await _require_owned_bucket(db, auth, bucket)
    if err or not b:
        return err  # type: ignore[return-value]
    rules = b.get("cors_rules") or []
    if not rules:
        return _xml_error("NoSuchCORSConfiguration", "The CORS configuration does not exist", f"/{bucket}", 404)
    rules_xml = ""
    for r in rules:
        origins = "".join(f"<AllowedOrigin>{escape(x)}</AllowedOrigin>" for x in (r.get("allowed_origins") or []))
        methods = "".join(f"<AllowedMethod>{escape(x)}</AllowedMethod>" for x in (r.get("allowed_methods") or []))
        hdrs = "".join(f"<AllowedHeader>{escape(x)}</AllowedHeader>" for x in (r.get("allowed_headers") or []))
        exps = "".join(f"<ExposeHeader>{escape(x)}</ExposeHeader>" for x in (r.get("expose_headers") or []))
        max_age = f"<MaxAgeSeconds>{int(r['max_age_seconds'])}</MaxAgeSeconds>" if r.get("max_age_seconds") is not None else ""
        rules_xml += f"<CORSRule>{origins}{methods}{hdrs}{exps}{max_age}</CORSRule>"
    xml = f'<?xml version="1.0" encoding="UTF-8"?>\n<CORSConfiguration>{rules_xml}</CORSConfiguration>'
    return Response(content=xml, status_code=200, media_type="application/xml")


async def _handle_put_bucket_cors(
    request: Request, db: Database, auth: AuthenticatedUser, bucket: str
) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return err
    raw = await request.body()
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return _xml_error("MalformedXML", "Malformed CORS XML", f"/{bucket}", 400)
    rules: list[dict[str, Any]] = []
    for r_el in root.findall(".//{*}CORSRule"):
        max_age_txt = r_el.findtext("{*}MaxAgeSeconds")
        rules.append(
            {
                "allowed_origins": [el.text for el in r_el.findall("{*}AllowedOrigin") if el.text],
                "allowed_methods": [el.text for el in r_el.findall("{*}AllowedMethod") if el.text],
                "allowed_headers": [el.text for el in r_el.findall("{*}AllowedHeader") if el.text],
                "expose_headers": [el.text for el in r_el.findall("{*}ExposeHeader") if el.text],
                "max_age_seconds": int(max_age_txt) if max_age_txt and max_age_txt.isdigit() else 3600,
            }
        )
    await db.update_bucket(bucket, cors_rules=rules)
    return Response(status_code=200)


async def _handle_delete_bucket_cors(db: Database, auth: AuthenticatedUser, bucket: str) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return err
    await db.update_bucket(bucket, cors_rules=[])
    return Response(status_code=204)


async def _handle_delete_bucket(db: Database, auth: AuthenticatedUser, bucket: str) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return err
    if await db.count_bucket_objects(bucket) > 0:
        return _xml_error("BucketNotEmpty", "The bucket you tried to delete is not empty", f"/{bucket}", 409)
    await db.delete_bucket(bucket)
    return Response(status_code=204)


async def _handle_list_objects_v2(
    db: Database, auth: AuthenticatedUser, bucket: str, qp: dict[str, str]
) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return err

    prefix = qp.get("prefix", "")
    delimiter = qp.get("delimiter", "")
    start_after = qp.get("continuation-token") or qp.get("start-after") or ""
    max_keys = max(1, min(1000, int(qp.get("max-keys", "1000") or "1000")))
    enc_type = qp.get("encoding-type", "")

    res = await db.list_objects(
        bucket, prefix=prefix, delimiter=delimiter, start_after=start_after, max_keys=max_keys
    )

    def _enc(val: str) -> str:
        return quote(val, safe="/-_.~") if enc_type == "url" else val

    contents_xml = "".join(
        "<Contents>"
        f"<Key>{escape(_enc(o['key']))}</Key>"
        f"<LastModified>{escape(o['updated_at'])}</LastModified>"
        f"<ETag>\"{escape(o['etag'])}\"</ETag>"
        f"<Size>{int(o['size'])}</Size>"
        "<StorageClass>STANDARD</StorageClass>"
        "</Contents>"
        for o in res["contents"]
    )
    cp_xml = "".join(
        f"<CommonPrefixes><Prefix>{escape(_enc(cp))}</Prefix></CommonPrefixes>"
        for cp in res["common_prefixes"]
    )
    next_xml = (
        f"<NextContinuationToken>{escape(res['next_continuation_token'])}</NextContinuationToken>"
        if res["next_continuation_token"]
        else ""
    )
    cont_xml = f"<ContinuationToken>{escape(qp['continuation-token'])}</ContinuationToken>" if qp.get("continuation-token") else ""
    delim_xml = f"<Delimiter>{escape(_enc(delimiter))}</Delimiter>" if delimiter else ""
    enc_xml = f"<EncodingType>{escape(enc_type)}</EncodingType>" if enc_type else ""

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"<Name>{escape(bucket)}</Name>"
        f"<Prefix>{escape(_enc(prefix))}</Prefix>"
        f"{delim_xml}{enc_xml}{cont_xml}"
        f"<KeyCount>{res['key_count']}</KeyCount>"
        f"<MaxKeys>{max_keys}</MaxKeys>"
        f"<IsTruncated>{'true' if res['is_truncated'] else 'false'}</IsTruncated>"
        f"{next_xml}{contents_xml}{cp_xml}"
        "</ListBucketResult>"
    )
    return Response(content=xml, status_code=200, media_type="application/xml")


async def _handle_list_objects_v1(
    db: Database, auth: AuthenticatedUser, bucket: str, qp: dict[str, str]
) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return err

    prefix = qp.get("prefix", "")
    delimiter = qp.get("delimiter", "")
    marker = qp.get("marker", "")
    max_keys = max(1, min(1000, int(qp.get("max-keys", "1000") or "1000")))

    res = await db.list_objects(
        bucket, prefix=prefix, delimiter=delimiter, start_after=marker, max_keys=max_keys
    )
    contents_xml = "".join(
        "<Contents>"
        f"<Key>{escape(o['key'])}</Key>"
        f"<LastModified>{escape(o['updated_at'])}</LastModified>"
        f"<ETag>\"{escape(o['etag'])}\"</ETag>"
        f"<Size>{int(o['size'])}</Size>"
        "<StorageClass>STANDARD</StorageClass>"
        "</Contents>"
        for o in res["contents"]
    )
    cp_xml = "".join(
        f"<CommonPrefixes><Prefix>{escape(cp)}</Prefix></CommonPrefixes>"
        for cp in res["common_prefixes"]
    )
    next_marker = (
        f"<NextMarker>{escape(res['next_continuation_token'])}</NextMarker>"
        if res["is_truncated"] and res["next_continuation_token"]
        else ""
    )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"<Name>{escape(bucket)}</Name>"
        f"<Prefix>{escape(prefix)}</Prefix>"
        f"<Marker>{escape(marker)}</Marker>"
        f"<MaxKeys>{max_keys}</MaxKeys>"
        f"<IsTruncated>{'true' if res['is_truncated'] else 'false'}</IsTruncated>"
        f"{next_marker}{contents_xml}{cp_xml}"
        "</ListBucketResult>"
    )
    return Response(content=xml, status_code=200, media_type="application/xml")


async def _handle_delete_objects_batch(
    request: Request,
    db: Database,
    storage: StorageManager,
    auth: AuthenticatedUser,
    bucket: str,
) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return err
    raw_body = await request.body()
    try:
        root = ET.fromstring(raw_body)
    except ET.ParseError:
        return _xml_error("MalformedXML", "The XML you provided was not well-formed", f"/{bucket}", 400)

    quiet = (root.findtext("Quiet") or "").lower() == "true"
    deleted_keys: list[str] = []
    all_orphans: list[tuple[str, str]] = []

    for obj_el in root.findall(".//{*}Object"):
        k_el = obj_el.find("{*}Key")
        if k_el is None or k_el.text is None:
            continue
        k = k_el.text
        _, orphans = await db.delete_object(bucket, k)
        all_orphans.extend(orphans)
        deleted_keys.append(k)

    if all_orphans:
        await storage.delete_remote_files(all_orphans)

    items = "" if quiet else "".join(f"<Deleted><Key>{escape(k)}</Key></Deleted>" for k in deleted_keys)
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"{items}</DeleteResult>"
    )
    return Response(content=xml, status_code=200, media_type="application/xml")


# ----------------------------------------------------------------------
# Object Handlers
# ----------------------------------------------------------------------
def _object_headers(obj: dict[str, Any]) -> dict[str, str]:
    headers = {
        "Content-Type": obj["content_type"] or "application/octet-stream",
        "ETag": f'"{obj["etag"]}"',
        "Last-Modified": _http_date(obj["updated_at"]),
        "Accept-Ranges": "bytes",
    }
    for mk, mv in (obj.get("metadata") or {}).items():
        headers[f"x-amz-meta-{mk}"] = str(mv)
    return headers


async def _handle_head_object(
    db: Database, auth: Optional[AuthenticatedUser], bucket: str, key: str
) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return Response(status_code=err.status_code)
    obj = await db.get_object(bucket, key)
    if not obj:
        return Response(status_code=404)
    headers = _object_headers(obj)
    headers["Content-Length"] = str(obj["size"])
    return Response(status_code=200, headers=headers)


async def _handle_get_object(
    request: Request,
    db: Database,
    storage: StorageManager,
    auth: Optional[AuthenticatedUser],
    bucket: str,
    key: str,
) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return err
    found = await db.get_object_with_segments(bucket, key)
    if not found:
        return _xml_error("NoSuchKey", "The specified key does not exist", f"/{bucket}/{key}", 404)

    obj, segments = found
    total_size = int(obj["size"])
    etag_quoted = f'"{obj["etag"]}"'

    if_match = request.headers.get("if-match")
    if if_match and if_match.strip() not in (etag_quoted, obj["etag"], "*"):
        return _xml_error("PreconditionFailed", "At least one pre-condition failed", f"/{bucket}/{key}", 412)
    if_none_match = request.headers.get("if-none-match")
    if if_none_match and if_none_match.strip() in (etag_quoted, obj["etag"], "*"):
        return Response(status_code=304, headers=_object_headers(obj))

    headers = _object_headers(obj)
    range_hdr = request.headers.get("range")
    if range_hdr:
        parsed = _parse_range_header(range_hdr, total_size)
        if parsed is None:
            return _xml_error(
                "InvalidRange",
                "The requested range is not satisfiable",
                f"/{bucket}/{key}",
                416,
            )
        start, end = parsed
        headers["Content-Range"] = f"bytes {start}-{end}/{total_size}"
        headers["Content-Length"] = str(end - start + 1)
        return StreamingResponse(
            storage.stream_object_range(segments, start, end),
            status_code=206,
            headers=headers,
        )

    headers["Content-Length"] = str(total_size)
    if total_size == 0:
        return Response(content=b"", status_code=200, headers=headers)

    return StreamingResponse(
        storage.stream_object_range(segments, 0, total_size - 1),
        status_code=200,
        headers=headers,
    )


async def _check_user_quota(db: Database, user: dict[str, Any], incoming_bytes: int) -> Optional[Response]:
    quota = int(user["quota_bytes"])
    if quota <= 0:
        return None
    used = await db.get_user_logical_used_bytes(user["id"])
    if used + max(0, incoming_bytes) > quota:
        return _xml_error("QuotaExceeded", "User storage quota exceeded", "/", 507)
    return None


async def _handle_put_object(
    request: Request,
    settings: Settings,
    db: Database,
    storage: StorageManager,
    auth: AuthenticatedUser,
    bucket: str,
    key: str,
) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return err

    decoded_len_hdr = request.headers.get("x-amz-decoded-content-length") or request.headers.get("content-length")
    expected_plain = int(decoded_len_hdr) if decoded_len_hdr and decoded_len_hdr.isdigit() else 0

    quota_err = await _check_user_quota(db, auth.user, expected_plain)
    if quota_err:
        return quota_err

    encrypt = bool(auth.user["encryption_enabled"])
    needed_remote = encrypted_size(expected_plain, settings.chunk_size) if encrypt else expected_plain

    backend = await db.select_writable_backend_for_user(auth.user["id"], needed_bytes=needed_remote)
    if not backend:
        return _xml_error(
            "InsufficientStorage",
            "No active writable storage backend bound to this user has sufficient quota",
            f"/{bucket}/{key}",
            507,
        )

    segment_id = str(uuid.uuid4())
    rel_path = make_segment_rel_path(segment_id)
    write_res = await storage.write_stream(
        backend,
        rel_path,
        iter_request_payload(request),
        segment_id=rel_path,
        encrypt=encrypt,
        chunk_size=settings.chunk_size,
    )

    # Re-check user quota for chunked uploads where Content-Length wasn't known upfront
    if expected_plain == 0 and write_res.plain_size > 0:
        q2 = await _check_user_quota(db, auth.user, write_res.plain_size)
        if q2:
            await storage.delete_remote_files([(backend["id"], write_res.remote_path)])
            return q2

    content_type = request.headers.get("content-type", "application/octet-stream")
    metadata = _extract_user_metadata(request)

    _, orphans = await db.put_object_with_segments(
        bucket=bucket,
        key=key,
        size=write_res.plain_size,
        etag=write_res.etag,
        content_type=content_type,
        metadata=metadata,
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

    return Response(status_code=200, headers={"ETag": f'"{write_res.etag}"'})


async def _handle_copy_object(
    request: Request,
    db: Database,
    storage: StorageManager,
    auth: AuthenticatedUser,
    dst_bucket: str,
    dst_key: str,
) -> Response:
    _, err = await _require_owned_bucket(db, auth, dst_bucket)
    if err:
        return err

    raw_src = unquote(request.headers["x-amz-copy-source"]).lstrip("/")
    raw_src = raw_src.split("?", 1)[0]
    if "/" not in raw_src:
        return _xml_error("InvalidArgument", "Invalid x-amz-copy-source", f"/{dst_bucket}/{dst_key}", 400)
    src_bucket, src_key = raw_src.split("/", 1)

    _, src_err = await _require_owned_bucket(db, auth, src_bucket)
    if src_err:
        return src_err

    found = await db.get_object_with_segments(src_bucket, src_key)
    if not found:
        return _xml_error("NoSuchKey", "Copy source does not exist", f"/{src_bucket}/{src_key}", 404)
    src_obj, src_segs = found

    directive = request.headers.get("x-amz-metadata-directive", "COPY").upper()
    if directive == "REPLACE":
        content_type = request.headers.get("content-type", "application/octet-stream")
        metadata = _extract_user_metadata(request)
    else:
        content_type = src_obj["content_type"]
        metadata = src_obj["metadata"]

    new_segments = [
        {
            "id": str(uuid.uuid4()),
            "segment_index": seg["segment_index"],
            "plain_offset": seg["plain_offset"],
            "plain_size": seg["plain_size"],
            "remote_size": seg["remote_size"],
            "backend_id": seg["backend_id"],
            "remote_path": seg["remote_path"],
            "encrypted": bool(seg["encrypted"]),
            "wrapped_dek": seg["wrapped_dek"],
            "nonce_prefix_b64": seg["nonce_prefix_b64"],
            "chunk_size": seg["chunk_size"],
        }
        for seg in src_segs
    ]
    copied_obj, orphans = await db.put_object_with_segments(
        bucket=dst_bucket,
        key=dst_key,
        size=int(src_obj["size"]),
        etag=src_obj["etag"],
        content_type=content_type,
        metadata=metadata,
        segments=new_segments,
    )
    if orphans:
        await storage.delete_remote_files(orphans)

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"<LastModified>{escape(copied_obj['updated_at'])}</LastModified>"
        f"<ETag>\"{escape(copied_obj['etag'])}\"</ETag>"
        "</CopyObjectResult>"
    )
    return Response(content=xml, status_code=200, media_type="application/xml")


async def _handle_delete_object(
    db: Database,
    storage: StorageManager,
    auth: AuthenticatedUser,
    bucket: str,
    key: str,
) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return err
    _, orphans = await db.delete_object(bucket, key)
    if orphans:
        await storage.delete_remote_files(orphans)
    return Response(status_code=204)


# ----------------------------------------------------------------------
# Multipart Handlers
# ----------------------------------------------------------------------
async def _handle_create_multipart_upload(
    request: Request,
    db: Database,
    auth: AuthenticatedUser,
    bucket: str,
    key: str,
) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return err
    content_type = request.headers.get("content-type", "application/octet-stream")
    metadata = _extract_user_metadata(request)
    upload = await db.create_multipart_upload(
        bucket=bucket,
        key=key,
        user_id=auth.user["id"],
        content_type=content_type,
        metadata=metadata,
    )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"<Bucket>{escape(bucket)}</Bucket>"
        f"<Key>{escape(key)}</Key>"
        f"<UploadId>{escape(upload['upload_id'])}</UploadId>"
        "</InitiateMultipartUploadResult>"
    )
    return Response(content=xml, status_code=200, media_type="application/xml")


async def _handle_upload_part(
    request: Request,
    settings: Settings,
    db: Database,
    storage: StorageManager,
    auth: AuthenticatedUser,
    bucket: str,
    key: str,
    qp: dict[str, str],
) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return err
    upload_id = qp["uploadId"]
    try:
        part_number = int(qp["partNumber"])
    except ValueError:
        return _xml_error("InvalidArgument", "Invalid partNumber", f"/{bucket}/{key}", 400)
    if part_number < 1 or part_number > 10000:
        return _xml_error("InvalidArgument", "partNumber must be between 1 and 10000", f"/{bucket}/{key}", 400)

    upload = await db.get_multipart_upload(upload_id)
    if not upload or upload["bucket"] != bucket or upload["key"] != key:
        return _xml_error("NoSuchUpload", "The specified multipart upload does not exist", f"/{bucket}/{key}", 404)

    decoded_len_hdr = request.headers.get("x-amz-decoded-content-length") or request.headers.get("content-length")
    expected_plain = int(decoded_len_hdr) if decoded_len_hdr and decoded_len_hdr.isdigit() else 0

    encrypt = bool(auth.user["encryption_enabled"])
    needed_remote = encrypted_size(expected_plain, settings.chunk_size) if encrypt else expected_plain

    backend = await db.select_writable_backend_for_user(auth.user["id"], needed_bytes=needed_remote)
    if not backend:
        return _xml_error(
            "InsufficientStorage",
            "No active writable storage backend bound to this user has sufficient quota",
            f"/{bucket}/{key}",
            507,
        )

    part_id = str(uuid.uuid4())
    rel_path = f"parts/{upload_id}/{part_number:05d}_{part_id}"
    write_res = await storage.write_stream(
        backend,
        rel_path,
        iter_request_payload(request),
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

    return Response(status_code=200, headers={"ETag": f'"{write_res.etag}"'})


async def _handle_list_parts(
    db: Database,
    auth: AuthenticatedUser,
    bucket: str,
    key: str,
    upload_id: str,
) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return err
    upload = await db.get_multipart_upload(upload_id)
    if not upload or upload["bucket"] != bucket or upload["key"] != key:
        return _xml_error("NoSuchUpload", "The specified multipart upload does not exist", f"/{bucket}/{key}", 404)
    parts = await db.list_multipart_parts(upload_id)
    parts_xml = "".join(
        "<Part>"
        f"<PartNumber>{int(p['part_number'])}</PartNumber>"
        f"<LastModified>{escape(p['created_at'])}</LastModified>"
        f"<ETag>\"{escape(p['etag'])}\"</ETag>"
        f"<Size>{int(p['plain_size'])}</Size>"
        "</Part>"
        for p in parts
    )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"<Bucket>{escape(bucket)}</Bucket>"
        f"<Key>{escape(key)}</Key>"
        f"<UploadId>{escape(upload_id)}</UploadId>"
        "<StorageClass>STANDARD</StorageClass>"
        "<IsTruncated>false</IsTruncated>"
        f"{parts_xml}"
        "</ListPartsResult>"
    )
    return Response(content=xml, status_code=200, media_type="application/xml")


async def _handle_list_multipart_uploads(
    db: Database, auth: AuthenticatedUser, bucket: str, qp: dict[str, str]
) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return err
    prefix = qp.get("prefix", "")
    uploads = await db.list_multipart_uploads(bucket, prefix=prefix)
    uploads_xml = "".join(
        "<Upload>"
        f"<Key>{escape(u['key'])}</Key>"
        f"<UploadId>{escape(u['upload_id'])}</UploadId>"
        f"<Initiated>{escape(u['created_at'])}</Initiated>"
        "<StorageClass>STANDARD</StorageClass>"
        "</Upload>"
        for u in uploads
    )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"<Bucket>{escape(bucket)}</Bucket>"
        f"<Prefix>{escape(prefix)}</Prefix>"
        "<IsTruncated>false</IsTruncated>"
        f"{uploads_xml}"
        "</ListMultipartUploadsResult>"
    )
    return Response(content=xml, status_code=200, media_type="application/xml")


async def _handle_complete_multipart_upload(
    request: Request,
    db: Database,
    storage: StorageManager,
    auth: AuthenticatedUser,
    bucket: str,
    key: str,
    upload_id: str,
) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return err
    upload = await db.get_multipart_upload(upload_id)
    if not upload or upload["bucket"] != bucket or upload["key"] != key:
        return _xml_error("NoSuchUpload", "The specified multipart upload does not exist", f"/{bucket}/{key}", 404)

    raw_body = await request.body()
    try:
        root = ET.fromstring(raw_body)
    except ET.ParseError:
        return _xml_error("MalformedXML", "The XML you provided was not well-formed", f"/{bucket}/{key}", 400)

    requested_parts: list[tuple[int, str]] = []
    for part_el in root.findall(".//{*}Part"):
        pn_txt = part_el.findtext("{*}PartNumber")
        et_txt = part_el.findtext("{*}ETag") or ""
        if pn_txt is None:
            continue
        requested_parts.append((int(pn_txt), et_txt.strip().strip('"')))

    if not requested_parts:
        return _xml_error("InvalidPart", "No parts provided in CompleteMultipartUpload", f"/{bucket}/{key}", 400)

    # Verify ascending order
    part_nums = [pn for pn, _ in requested_parts]
    if part_nums != sorted(part_nums) or len(set(part_nums)) != len(part_nums):
        return _xml_error("InvalidPartOrder", "The list of parts was not in ascending order", f"/{bucket}/{key}", 400)

    stored_parts = {int(p["part_number"]): p for p in await db.list_multipart_parts(upload_id)}
    selected_parts: list[dict[str, Any]] = []
    md5_concat = bytearray()

    for pn, req_etag in requested_parts:
        sp = stored_parts.get(pn)
        if not sp:
            return _xml_error("InvalidPart", f"Part {pn} not found", f"/{bucket}/{key}", 400)
        if req_etag and req_etag != sp["etag"]:
            return _xml_error("InvalidPart", f"ETag mismatch for part {pn}", f"/{bucket}/{key}", 400)
        selected_parts.append(sp)
        md5_concat.extend(bytes.fromhex(sp["etag"]))

    total_size = sum(int(p["plain_size"]) for p in selected_parts)
    quota_err = await _check_user_quota(db, auth.user, total_size)
    if quota_err:
        return quota_err

    final_etag = f"{hashlib.md5(bytes(md5_concat)).hexdigest()}-{len(selected_parts)}"
    _, orphans = await db.complete_multipart_upload(
        upload=upload, selected_parts=selected_parts, etag=final_etag
    )
    if orphans:
        await storage.delete_remote_files(orphans)

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"<Location>/{escape(bucket)}/{escape(key)}</Location>"
        f"<Bucket>{escape(bucket)}</Bucket>"
        f"<Key>{escape(key)}</Key>"
        f"<ETag>\"{escape(final_etag)}\"</ETag>"
        "</CompleteMultipartUploadResult>"
    )
    return Response(content=xml, status_code=200, media_type="application/xml")


async def _handle_abort_multipart_upload(
    db: Database,
    storage: StorageManager,
    auth: AuthenticatedUser,
    bucket: str,
    key: str,
    upload_id: str,
) -> Response:
    _, err = await _require_owned_bucket(db, auth, bucket)
    if err:
        return err
    upload = await db.get_multipart_upload(upload_id)
    if not upload or upload["bucket"] != bucket or upload["key"] != key:
        return _xml_error("NoSuchUpload", "The specified multipart upload does not exist", f"/{bucket}/{key}", 404)
    _, orphans = await db.abort_multipart_upload(upload_id)
    if orphans:
        await storage.delete_remote_files(orphans)
    return Response(status_code=204)
