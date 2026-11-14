"""AWS Signature Version 4 verification (header + presigned URL) and chunked stream decoding."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Optional
from urllib.parse import parse_qsl, quote, unquote

from fastapi import Request

from banoss.crypto import CryptoService
from banoss.db import Database

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_AUTH_RE = re.compile(
    r"^AWS4-HMAC-SHA256\s+"
    r"Credential=(?P<cred>[^,]+),\s*"
    r"SignedHeaders=(?P<signed>[^,]+),\s*"
    r"Signature=(?P<sig>[0-9a-fA-F]+)$"
)


class S3AuthError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 403) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


@dataclass
class AuthenticatedUser:
    user: dict[str, Any]
    access_key: str
    secret_key: str


def _hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def derive_signing_key(secret_key: str, date_stamp: str, region: str, service: str = "s3") -> bytes:
    k_date = _hmac_sha256(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _hmac_sha256(k_date, region)
    k_service = _hmac_sha256(k_region, service)
    return _hmac_sha256(k_service, "aws4_request")


def _canonical_uri(request: Request) -> str:
    raw_path: bytes = request.scope.get("raw_path") or request.url.path.encode("utf-8")
    path_str = raw_path.decode("utf-8", errors="replace")
    if not path_str.startswith("/"):
        path_str = "/" + path_str
    # Normalize segments per AWS S3 SigV4 (unquote once then quote with safe='/-_.~')
    segments = path_str.split("/")
    encoded = [quote(unquote(seg), safe="-_.~") for seg in segments]
    return "/".join(encoded) or "/"


def _canonical_query_string(raw_query: str, exclude_keys: set[str] | None = None) -> str:
    if not raw_query:
        return ""
    exclude = exclude_keys or set()
    pairs: list[tuple[str, str]] = []
    for k, v in parse_qsl(raw_query, keep_blank_values=True):
        if k in exclude:
            continue
        pairs.append((quote(k, safe="-_.~"), quote(v, safe="-_.~")))
    pairs.sort(key=lambda item: (item[0], item[1]))
    return "&".join(f"{k}={v}" for k, v in pairs)


def _canonical_headers(request: Request, signed_headers: list[str]) -> tuple[str, str]:
    header_map: dict[str, list[str]] = {}
    for raw_k, raw_v in request.headers.raw:
        k = raw_k.decode("latin-1").lower()
        v = " ".join(raw_v.decode("latin-1").strip().split())
        header_map.setdefault(k, []).append(v)

    lines: list[str] = []
    for h in signed_headers:
        h_lower = h.lower()
        vals = header_map.get(h_lower)
        if vals is None:
            raise S3AuthError("AccessDenied", f"Missing signed header: {h_lower}")
        lines.append(f"{h_lower}:{','.join(vals)}")
    return "\n".join(lines) + "\n", ";".join(h.lower() for h in signed_headers)


def _parse_amz_date(date_str: str) -> datetime:
    try:
        return datetime.strptime(date_str, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            from email.utils import parsedate_to_datetime

            dt = parsedate_to_datetime(date_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception as exc:
            raise S3AuthError("AccessDenied", f"Invalid request date: {date_str}") from exc


async def verify_s3_request(
    request: Request,
    db: Database,
    crypto: CryptoService,
    clock_skew_seconds: int = 900,
) -> AuthenticatedUser:
    """Authenticate an incoming S3 request via Header SigV4 or Presigned Query SigV4."""
    raw_query = request.url.query
    query_params = dict(parse_qsl(raw_query, keep_blank_values=True))

    if "X-Amz-Signature" in query_params:
        return await _verify_presigned(request, raw_query, query_params, db, crypto, clock_skew_seconds)
    if "AWSAccessKeyId" in query_params and "Signature" in query_params:
        return await _verify_presigned_v2(request, query_params, db, crypto)

    auth_header = request.headers.get("authorization")
    if not auth_header:
        raise S3AuthError("AccessDenied", "Missing Authorization header")

    m = _AUTH_RE.match(auth_header.strip())
    if not m:
        raise S3AuthError("InvalidRequest", "Unsupported Authorization header format", 400)

    cred_parts = m.group("cred").split("/")
    if len(cred_parts) != 5 or cred_parts[3] != "s3" or cred_parts[4] != "aws4_request":
        raise S3AuthError("AuthorizationHeaderMalformed", "Malformed Credential scope", 400)

    access_key, date_stamp, region, service, _ = cred_parts
    signed_headers = [h.strip().lower() for h in m.group("signed").split(";") if h.strip()]
    provided_sig = m.group("sig").lower()

    amz_date = request.headers.get("x-amz-date") or request.headers.get("date")
    if not amz_date:
        raise S3AuthError("AccessDenied", "Missing x-amz-date or Date header")

    req_dt = _parse_amz_date(amz_date)
    now_dt = datetime.now(timezone.utc)
    if abs((now_dt - req_dt).total_seconds()) > clock_skew_seconds:
        raise S3AuthError("RequestTimeTooSkewed", "The difference between request time and server time is too large")

    user_row = await db.get_user_by_access_key(access_key)
    if not user_row or not user_row["is_active"]:
        raise S3AuthError("InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist or is disabled")

    secret_key = crypto.decrypt_secret(user_row["secret_key_enc"])
    payload_hash = request.headers.get("x-amz-content-sha256")
    if payload_hash is None:
        # Compute hash only when body is empty or buffered
        payload_hash = EMPTY_SHA256

    canonical_headers, signed_headers_str = _canonical_headers(request, signed_headers)
    canonical_request = "\n".join(
        [
            request.method.upper(),
            _canonical_uri(request),
            _canonical_query_string(raw_query),
            canonical_headers,
            signed_headers_str,
            payload_hash,
        ]
    )
    amz_iso = req_dt.strftime("%Y%m%dT%H%M%SZ")
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_iso,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signing_key = derive_signing_key(secret_key, date_stamp, region, service)
    expected_sig = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_sig, provided_sig):
        raise S3AuthError(
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided",
        )

    return AuthenticatedUser(user=user_row, access_key=access_key, secret_key=secret_key)


async def _verify_presigned(
    request: Request,
    raw_query: str,
    qp: dict[str, str],
    db: Database,
    crypto: CryptoService,
    clock_skew_seconds: int,
) -> AuthenticatedUser:
    if qp.get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256":
        raise S3AuthError("AuthorizationQueryParametersError", "Unsupported X-Amz-Algorithm", 400)

    cred_parts = qp.get("X-Amz-Credential", "").split("/")
    if len(cred_parts) != 5 or cred_parts[3] != "s3" or cred_parts[4] != "aws4_request":
        raise S3AuthError("AuthorizationQueryParametersError", "Malformed X-Amz-Credential", 400)

    access_key, date_stamp, region, service, _ = cred_parts
    amz_date = qp.get("X-Amz-Date", "")
    expires_str = qp.get("X-Amz-Expires", "0")
    signed_headers = [h.strip().lower() for h in qp.get("X-Amz-SignedHeaders", "").split(";") if h.strip()]
    provided_sig = qp.get("X-Amz-Signature", "").lower()

    req_dt = _parse_amz_date(amz_date)
    try:
        expires = int(expires_str)
    except ValueError as exc:
        raise S3AuthError("AuthorizationQueryParametersError", "Invalid X-Amz-Expires", 400) from exc

    now_ts = datetime.now(timezone.utc).timestamp()
    req_ts = req_dt.timestamp()
    if req_ts - clock_skew_seconds > now_ts or now_ts > req_ts + expires:
        raise S3AuthError("AccessDenied", "Request has expired")

    user_row = await db.get_user_by_access_key(access_key)
    if not user_row or not user_row["is_active"]:
        raise S3AuthError("InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist or is disabled")

    secret_key = crypto.decrypt_secret(user_row["secret_key_enc"])
    canonical_headers, signed_headers_str = _canonical_headers(request, signed_headers)
    canonical_request = "\n".join(
        [
            request.method.upper(),
            _canonical_uri(request),
            _canonical_query_string(raw_query, exclude_keys={"X-Amz-Signature"}),
            canonical_headers,
            signed_headers_str,
            "UNSIGNED-PAYLOAD",
        ]
    )
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signing_key = derive_signing_key(secret_key, date_stamp, region, service)
    expected_sig = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_sig, provided_sig):
        raise S3AuthError(
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided",
        )
    return AuthenticatedUser(user=user_row, access_key=access_key, secret_key=secret_key)


async def _verify_presigned_v2(
    request: Request,
    qp: dict[str, str],
    db: Database,
    crypto: CryptoService,
) -> AuthenticatedUser:
    access_key = qp.get("AWSAccessKeyId", "")
    provided_sig = qp.get("Signature", "")
    expires_str = qp.get("Expires", "0")
    try:
        expires = int(expires_str)
    except ValueError as exc:
        raise S3AuthError("AccessDenied", "Invalid Expires parameter", 403) from exc

    now_ts = datetime.now(timezone.utc).timestamp()
    if now_ts > expires:
        raise S3AuthError("AccessDenied", "Request has expired")

    user_row = await db.get_user_by_access_key(access_key)
    if not user_row or not user_row["is_active"]:
        raise S3AuthError("InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist or is disabled")

    secret_key = crypto.decrypt_secret(user_row["secret_key_enc"])
    content_md5 = request.headers.get("content-md5", "")
    content_type = request.headers.get("content-type", "")
    amz_headers = sorted(
        (k.lower(), " ".join(v.strip().split()))
        for k, v in request.headers.items()
        if k.lower().startswith("x-amz-")
    )
    amz_block = "".join(f"{k}:{v}\n" for k, v in amz_headers)
    resource = _canonical_uri(request)
    string_to_sign = f"{request.method.upper()}\n{content_md5}\n{content_type}\n{expires_str}\n{amz_block}{resource}"
    expected_sig = base64.b64encode(
        hmac.new(secret_key.encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha1).digest()
    ).decode("ascii")

    if not hmac.compare_digest(expected_sig, provided_sig):
        raise S3AuthError(
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided",
        )
    return AuthenticatedUser(user=user_row, access_key=access_key, secret_key=secret_key)


def has_s3_auth(request: Request) -> bool:
    """Return True if the request carries an S3 Authorization header or query signature."""
    if request.headers.get("authorization"):
        return True
    qp = dict(parse_qsl(request.url.query, keep_blank_values=True))
    return "X-Amz-Signature" in qp or ("AWSAccessKeyId" in qp and "Signature" in qp)


def generate_presigned_v4_url(
    *,
    base_url: str,
    host_header: str,
    bucket: str,
    key: str,
    access_key: str,
    secret_key: str,
    region: str = "us-east-1",
    expires_seconds: int = 3600,
    method: str = "GET",
) -> str:
    """Generate a path-style AWS SigV4 presigned URL compatible with BanOSS."""
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    scope = f"{date_stamp}/{region}/s3/aws4_request"

    encoded_key = "/".join(quote(seg, safe="-_.~") for seg in key.lstrip("/").split("/"))
    canonical_uri = f"/{quote(bucket, safe='-_.~')}/{encoded_key}"

    params = {
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": f"{access_key}/{scope}",
        "X-Amz-Date": amz_date,
        "X-Amz-Expires": str(expires_seconds),
        "X-Amz-SignedHeaders": "host",
    }
    canonical_qs = "&".join(
        f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}"
        for k, v in sorted(params.items())
    )
    canonical_headers = f"host:{host_header}\n"
    canonical_request = "\n".join(
        [
            method.upper(),
            canonical_uri,
            canonical_qs,
            canonical_headers,
            "host",
            "UNSIGNED-PAYLOAD",
        ]
    )
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signing_key = derive_signing_key(secret_key, date_stamp, region, "s3")
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{base_url.rstrip('/')}{canonical_uri}?{canonical_qs}&X-Amz-Signature={signature}"


def _is_aws_chunked_request(request: Request) -> bool:
    """Return True when the request body uses AWS aws-chunked streaming framing."""
    content_sha = (request.headers.get("x-amz-content-sha256") or "").strip().upper()
    if content_sha.startswith("STREAMING-"):
        return True
    content_enc = (request.headers.get("content-encoding") or "").lower()
    encodings = [part.strip() for part in content_enc.split(",") if part.strip()]
    return "aws-chunked" in encodings


async def iter_request_payload(request: Request) -> AsyncIterator[bytes]:
    """Yield raw object payload bytes, transparently decoding all aws-chunked streaming uploads."""
    if not _is_aws_chunked_request(request):
        async for chunk in request.stream():
            if chunk:
                yield chunk
        return

    # Decode AWS aws-chunked encoding (signed or unsigned, with or without trailing headers):
    #   <hex-size>[;chunk-signature=<sig>]\r\n<data>\r\n ... 0[;chunk-signature=<sig>]\r\n[trailers\r\n]\r\n
    buf = bytearray()
    stream_iter = request.stream()

    async def _fill(min_bytes: int = 1) -> bool:
        while len(buf) < min_bytes:
            try:
                nxt = await stream_iter.__anext__()
            except StopAsyncIteration:
                return False
            if nxt:
                buf.extend(nxt)
        return True

    while True:
        while True:
            crlf = buf.find(b"\r\n")
            if crlf != -1:
                header_line = bytes(buf[:crlf]).decode("ascii", errors="replace")
                del buf[: crlf + 2]
                break
            if not await _fill(len(buf) + 1):
                return

        size_hex = header_line.split(";", 1)[0].strip()
        if not size_hex:
            continue
        chunk_len = int(size_hex, 16)
        if chunk_len == 0:
            # Drain any trailing headers (e.g. x-amz-checksum-crc32) and terminating CRLF
            async for _ in stream_iter:
                pass
            return

        remaining = chunk_len
        while remaining > 0:
            if not buf and not await _fill(1):
                return
            take = min(len(buf), remaining)
            yield bytes(buf[:take])
            del buf[:take]
            remaining -= take

        while len(buf) < 2:
            if not await _fill(2):
                break
        if buf[:2] == b"\r\n":
            del buf[:2]
