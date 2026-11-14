"""Storage backend manager for SFTP (with bounded concurrency & idle reaper) and Local backends."""

from __future__ import annotations

import asyncio
import hashlib
import os
import posixpath
import re
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Optional

import asyncssh

from banoss.crypto import (
    GCM_TAG_SIZE,
    CryptoService,
    encrypted_size,
    remote_chunk_span,
)
from banoss.db import Database


@dataclass
class WriteResult:
    plain_size: int
    remote_size: int
    etag: str
    remote_path: str
    encrypted: bool
    wrapped_dek: str
    nonce_prefix_b64: str
    chunk_size: int


def make_segment_rel_path(segment_id: str) -> str:
    """Return a balanced 1-level (256-bucket) relative storage path for a segment UUID."""
    prefix = segment_id[:2] if len(segment_id) >= 2 else "00"
    return f"objs/{prefix}/{segment_id}"


class _PoolEntry:
    def __init__(self, backend_id: str, max_connections: int, idle_timeout_sec: int) -> None:
        self.backend_id = backend_id
        self.max_connections = max(1, max_connections)
        self.idle_timeout_sec = max(0, idle_timeout_sec)
        self.semaphore = asyncio.Semaphore(self.max_connections)
        self.idle_conns: list[tuple[asyncssh.SSHClientConnection, asyncssh.SFTPClient, float]] = []
        self.active_count = 0


class StorageManager:
    """Manages SFTP connection pools and streaming encrypted/plaintext I/O across backends."""

    def __init__(self, db: Database, crypto: CryptoService, default_chunk_size: int) -> None:
        self.db = db
        self.crypto = crypto
        self.default_chunk_size = default_chunk_size
        self._pools: dict[str, _PoolEntry] = {}
        self._known_dirs: set[tuple[str, str]] = set()
        self._bg_tasks: set[asyncio.Task[None]] = set()
        self._reaper_task: Optional[asyncio.Task[None]] = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        if self._reaper_task is None:
            self._reaper_task = asyncio.create_task(self._idle_reaper_loop())
        self._spawn_bg_task(self._warm_active_backends_bg())

    async def stop(self) -> None:
        for task in list(self._bg_tasks):
            task.cancel()
        for task in list(self._bg_tasks):
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._bg_tasks.clear()
        if self._reaper_task is not None:
            self._reaper_task.cancel()
            try:
                await self._reaper_task
            except asyncio.CancelledError:
                pass
            self._reaper_task = None
        await self.close_all_pools()

    def _spawn_bg_task(self, coro: Awaitable[None]) -> None:
        task: asyncio.Task[None] = asyncio.create_task(coro)  # type: ignore[arg-type]
        self._bg_tasks.add(task)
        task.add_done_callback(lambda t: self._bg_tasks.discard(t))

    async def _warm_active_backends_bg(self) -> None:
        try:
            backends = await self.db.list_backends(active_only=True)
        except Exception:
            return
        for backend in backends:
            if backend.get("protocol") == "sftp" and int(backend.get("idle_timeout_sec", 600)) > 0:
                await self.warm_backend(backend)

    async def warm_backend(self, backend: dict[str, Any]) -> None:
        """Pre-warm one idle SFTP connection and cache base_dir in the background."""
        if not backend.get("is_active") or backend.get("protocol") != "sftp":
            return
        if int(backend.get("idle_timeout_sec", 600)) <= 0:
            return
        bid = backend["id"]
        entry = await self._get_pool(backend)
        if entry.idle_conns or entry.active_count > 0:
            return
        try:
            async with self.acquire_sftp(backend) as sftp:
                base_dir = (backend.get("base_path") or "/").rstrip("/") or "/"
                if (bid, base_dir) not in self._known_dirs:
                    await sftp.makedirs(base_dir, exist_ok=True)
                    self._known_dirs.add((bid, base_dir))
        except Exception:
            pass

    def schedule_warm_backend(self, backend: dict[str, Any]) -> None:
        """Schedule non-blocking SFTP pre-warming for a created/updated backend."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return
        self._spawn_bg_task(self.warm_backend(backend))

    async def close_all_pools(self) -> None:
        async with self._lock:
            entries = list(self._pools.values())
            self._pools.clear()
            self._known_dirs.clear()
        for entry in entries:
            for ssh_conn, sftp, _ in entry.idle_conns:
                await _safe_close_sftp(ssh_conn, sftp)
            entry.idle_conns.clear()

    async def invalidate_backend_pool(self, backend_id: str) -> None:
        async with self._lock:
            entry = self._pools.pop(backend_id, None)
            self._known_dirs = {pair for pair in self._known_dirs if pair[0] != backend_id}
        if entry:
            for ssh_conn, sftp, _ in entry.idle_conns:
                await _safe_close_sftp(ssh_conn, sftp)
            entry.idle_conns.clear()

    async def _idle_reaper_loop(self) -> None:
        while True:
            await asyncio.sleep(15)
            now = time.monotonic()
            to_close: list[tuple[asyncssh.SSHClientConnection, asyncssh.SFTPClient]] = []
            async with self._lock:
                for entry in self._pools.values():
                    if entry.idle_timeout_sec <= 0:
                        continue
                    kept = []
                    for ssh_conn, sftp, last_used in entry.idle_conns:
                        if now - last_used >= entry.idle_timeout_sec:
                            to_close.append((ssh_conn, sftp))
                        else:
                            kept.append((ssh_conn, sftp, last_used))
                    entry.idle_conns = kept
            for ssh_conn, sftp in to_close:
                await _safe_close_sftp(ssh_conn, sftp)

    async def _get_pool(self, backend: dict[str, Any]) -> _PoolEntry:
        bid = backend["id"]
        max_c = max(1, int(backend.get("max_connections", 3)))
        idle_t = max(0, int(backend.get("idle_timeout_sec", 60)))
        async with self._lock:
            entry = self._pools.get(bid)
            if (
                entry is None
                or entry.max_connections != max_c
                or entry.idle_timeout_sec != idle_t
            ):
                if entry is not None:
                    for ssh_conn, sftp, _ in entry.idle_conns:
                        asyncio.create_task(_safe_close_sftp(ssh_conn, sftp))
                entry = _PoolEntry(bid, max_c, idle_t)
                self._pools[bid] = entry
            return entry

    def get_pool_snapshot(self) -> dict[str, dict[str, int]]:
        return {
            bid: {
                "active": entry.active_count,
                "idle": len(entry.idle_conns),
                "max_connections": entry.max_connections,
            }
            for bid, entry in self._pools.items()
        }

    async def _open_sftp(
        self, backend: dict[str, Any]
    ) -> tuple[asyncssh.SSHClientConnection, asyncssh.SFTPClient]:
        auth_type = backend.get("auth_type", "key")
        cred = self.crypto.decrypt_secret(backend.get("credential_enc", ""))
        passphrase = self.crypto.decrypt_secret(backend.get("passphrase_enc", "")) or None

        connect_kwargs: dict[str, Any] = {
            "host": backend["host"],
            "port": int(backend.get("port", 22)),
            "username": backend["username"],
            "known_hosts": None,
            "connect_timeout": 15,
            "keepalive_interval": 20,
            "keepalive_count_max": 3,
        }
        if auth_type == "key" and cred:
            connect_kwargs["client_keys"] = [_load_client_key(cred, passphrase)]
        elif auth_type == "password":
            connect_kwargs["password"] = cred

        ssh_conn = await asyncssh.connect(**connect_kwargs)
        try:
            sftp = await ssh_conn.start_sftp_client()
        except Exception:
            ssh_conn.close()
            raise
        return ssh_conn, sftp

    @asynccontextmanager
    async def acquire_sftp(self, backend: dict[str, Any]) -> AsyncIterator[asyncssh.SFTPClient]:
        entry = await self._get_pool(backend)
        await entry.semaphore.acquire()
        entry.active_count += 1
        ssh_conn: Optional[asyncssh.SSHClientConnection] = None
        sftp: Optional[asyncssh.SFTPClient] = None
        broken = False
        try:
            while entry.idle_conns:
                c_ssh, c_sftp, _ = entry.idle_conns.pop()
                if not c_ssh.is_closed():
                    ssh_conn, sftp = c_ssh, c_sftp
                    break
                await _safe_close_sftp(c_ssh, c_sftp)

            if ssh_conn is None or sftp is None:
                ssh_conn, sftp = await self._open_sftp(backend)

            yield sftp
        except (asyncssh.Error, OSError):
            broken = True
            raise
        finally:
            entry.active_count = max(0, entry.active_count - 1)
            if ssh_conn is not None and sftp is not None:
                if broken or entry.idle_timeout_sec <= 0 or ssh_conn.is_closed():
                    await _safe_close_sftp(ssh_conn, sftp)
                else:
                    entry.idle_conns.append((ssh_conn, sftp, time.monotonic()))
            entry.semaphore.release()

    # ------------------------------------------------------------------
    # Write / Read / Delete / Probe Operations
    # ------------------------------------------------------------------
    async def _ensure_sftp_dir(
        self,
        sftp: asyncssh.SFTPClient,
        backend_id: str,
        base_dir: str,
        rel_path: str,
        *,
        force: bool = False,
    ) -> None:
        """Create only uncached subdirs under base_dir instead of walking from '/'."""
        if force or (backend_id, base_dir) not in self._known_dirs:
            await sftp.makedirs(base_dir, exist_ok=True)
            self._known_dirs.add((backend_id, base_dir))

        rel_dir = posixpath.dirname(rel_path).strip("/")
        if not rel_dir or rel_dir == ".":
            return

        cur = base_dir
        for part in rel_dir.split("/"):
            if not part or part == ".":
                continue
            cur = posixpath.join(cur, part)
            if not force and (backend_id, cur) in self._known_dirs:
                continue
            try:
                await sftp.mkdir(cur)
            except asyncssh.SFTPFileAlreadyExists:
                pass
            except asyncssh.SFTPFailure:
                if not await sftp.isdir(cur):
                    raise
            self._known_dirs.add((backend_id, cur))

    async def write_stream(
        self,
        backend: dict[str, Any],
        rel_path: str,
        chunk_iter: AsyncIterator[bytes],
        *,
        segment_id: str,
        encrypt: bool,
        chunk_size: Optional[int] = None,
    ) -> WriteResult:
        """Stream incoming bytes, optionally chunk-encrypt with AES-256-GCM, and write atomically."""
        c_size = chunk_size or self.default_chunk_size
        crypto_meta = self.crypto.new_segment_key(segment_id) if encrypt else None

        md5_hasher = hashlib.md5()
        plain_total = 0
        remote_total = 0
        buf = bytearray()
        chunk_idx = 0

        async def _encrypt_or_pass(data: bytes) -> bytes:
            nonlocal chunk_idx
            if not encrypt or crypto_meta is None:
                return data
            out = self.crypto.encrypt_chunk(
                crypto_meta.dek, crypto_meta.nonce_prefix, segment_id, chunk_idx, data
            )
            chunk_idx += 1
            return out

        if backend["protocol"] == "local":
            full_path = _resolve_local_path(backend["base_path"], rel_path)
            full_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = full_path.with_name(f"{full_path.name}.tmp.{uuid.uuid4().hex[:8]}")
            try:
                with open(tmp_path, "wb") as f:
                    async for incoming in chunk_iter:
                        if not incoming:
                            continue
                        md5_hasher.update(incoming)
                        plain_total += len(incoming)
                        buf.extend(incoming)
                        while len(buf) >= c_size:
                            piece = bytes(buf[:c_size])
                            del buf[:c_size]
                            out = await _encrypt_or_pass(piece)
                            f.write(out)
                            remote_total += len(out)
                    if buf:
                        out = await _encrypt_or_pass(bytes(buf))
                        f.write(out)
                        remote_total += len(out)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, full_path)
            except Exception:
                tmp_path.unlink(missing_ok=True)
                raise
        else:
            # SFTP atomic write with cached directory hierarchy
            base_dir = backend["base_path"].rstrip("/") or "/"
            full_path = posixpath.join(base_dir, rel_path)
            parent_dir = posixpath.dirname(full_path)
            tmp_path = f"{full_path}.tmp.{uuid.uuid4().hex[:8]}"
            bid = backend["id"]

            async with self.acquire_sftp(backend) as sftp:
                if (bid, parent_dir) not in self._known_dirs:
                    await self._ensure_sftp_dir(sftp, bid, base_dir, rel_path)
                try:
                    try:
                        fh = await sftp.open(tmp_path, "wb", block_size=32768)
                    except asyncssh.SFTPNoSuchFile:
                        # External dir cleanup invalidated our cache; force-recreate & retry once
                        await self._ensure_sftp_dir(sftp, bid, base_dir, rel_path, force=True)
                        fh = await sftp.open(tmp_path, "wb", block_size=32768)
                    async with fh as f:
                        async for incoming in chunk_iter:
                            if not incoming:
                                continue
                            md5_hasher.update(incoming)
                            plain_total += len(incoming)
                            buf.extend(incoming)
                            while len(buf) >= c_size:
                                piece = bytes(buf[:c_size])
                                del buf[:c_size]
                                out = await _encrypt_or_pass(piece)
                                await f.write(out)
                                remote_total += len(out)
                        if buf:
                            out = await _encrypt_or_pass(bytes(buf))
                            await f.write(out)
                            remote_total += len(out)
                    try:
                        await sftp.posix_rename(tmp_path, full_path)
                    except asyncssh.Error:
                        await sftp.rename(tmp_path, full_path)
                except Exception:
                    try:
                        await sftp.remove(tmp_path)
                    except Exception:
                        pass
                    raise

        return WriteResult(
            plain_size=plain_total,
            remote_size=remote_total,
            etag=md5_hasher.hexdigest(),
            remote_path=rel_path,
            encrypted=encrypt,
            wrapped_dek=crypto_meta.wrapped_dek if crypto_meta else "",
            nonce_prefix_b64=crypto_meta.nonce_prefix_b64 if crypto_meta else "",
            chunk_size=c_size,
        )

    async def stream_object_range(
        self,
        segments: list[dict[str, Any]],
        range_start: int,
        range_end_inclusive: int,
    ) -> AsyncIterator[bytes]:
        """Yield decrypted plaintext bytes for [range_start, range_end_inclusive] across segments."""
        if range_end_inclusive < range_start:
            return

        backends_cache: dict[str, dict[str, Any]] = {}

        for seg in segments:
            seg_start = int(seg["plain_offset"])
            seg_len = int(seg["plain_size"])
            seg_end = seg_start + seg_len - 1
            if seg_len == 0 or seg_end < range_start or seg_start > range_end_inclusive:
                continue

            local_start = max(0, range_start - seg_start)
            local_end = min(seg_len - 1, range_end_inclusive - seg_start)

            backend_id = seg["backend_id"]
            backend = backends_cache.get(backend_id)
            if backend is None:
                backend = await self.db.get_backend(backend_id)
                if backend is None:
                    raise FileNotFoundError(f"Backend {backend_id} missing")
                backends_cache[backend_id] = backend

            async for chunk in self._stream_segment_slice(backend, seg, local_start, local_end):
                yield chunk

    async def _stream_segment_slice(
        self,
        backend: dict[str, Any],
        seg: dict[str, Any],
        local_start: int,
        local_end_inclusive: int,
    ) -> AsyncIterator[bytes]:
        plain_total = int(seg["plain_size"])
        c_size = int(seg["chunk_size"])
        encrypted = bool(seg["encrypted"])

        if not encrypted:
            need = local_end_inclusive - local_start + 1
            if backend["protocol"] == "local":
                full_path = _resolve_local_path(backend["base_path"], seg["remote_path"])
                with open(full_path, "rb") as f:
                    f.seek(local_start)
                    remaining = need
                    while remaining > 0:
                        data = f.read(min(262144, remaining))
                        if not data:
                            break
                        remaining -= len(data)
                        yield data
            else:
                base_dir = backend["base_path"].rstrip("/") or "/"
                full_path = posixpath.join(base_dir, seg["remote_path"])
                async with self.acquire_sftp(backend) as sftp:
                    async with sftp.open(full_path, "rb", block_size=32768) as f:
                        await f.seek(local_start)
                        remaining = need
                        while remaining > 0:
                            data = await f.read(min(262144, remaining))
                            if not data:
                                break
                            remaining -= len(data)
                            yield data
            return

        # Encrypted chunked AES-256-GCM random-access streaming
        import base64

        crypto_id = seg["remote_path"]
        dek = self.crypto.unwrap_dek(crypto_id, seg["wrapped_dek"])
        nonce_prefix = base64.urlsafe_b64decode(seg["nonce_prefix_b64"].encode("ascii"))
        first_chunk, last_chunk, remote_offset, _ = remote_chunk_span(
            local_start, local_end_inclusive, plain_total, c_size
        )

        def _slice_decrypted(chunk_idx: int, plain_chunk: bytes) -> bytes:
            c_plain_start = chunk_idx * c_size
            c_plain_end = c_plain_start + len(plain_chunk) - 1
            s = max(local_start, c_plain_start) - c_plain_start
            e = min(local_end_inclusive, c_plain_end) - c_plain_start
            return plain_chunk[s : e + 1]

        if backend["protocol"] == "local":
            full_path = _resolve_local_path(backend["base_path"], seg["remote_path"])
            with open(full_path, "rb") as f:
                f.seek(remote_offset)
                for chunk_idx in range(first_chunk, last_chunk + 1):
                    plain_len = min(c_size, plain_total - chunk_idx * c_size)
                    enc_len = plain_len + GCM_TAG_SIZE
                    ct = _read_exact_sync(f, enc_len)
                    if len(ct) != enc_len:
                        raise EOFError(f"Truncated encrypted chunk {chunk_idx} on local backend")
                    pt = self.crypto.decrypt_chunk(dek, nonce_prefix, crypto_id, chunk_idx, ct)
                    out = _slice_decrypted(chunk_idx, pt)
                    if out:
                        yield out
        else:
            base_dir = backend["base_path"].rstrip("/") or "/"
            full_path = posixpath.join(base_dir, seg["remote_path"])
            async with self.acquire_sftp(backend) as sftp:
                async with sftp.open(full_path, "rb", block_size=32768) as f:
                    await f.seek(remote_offset)
                    for chunk_idx in range(first_chunk, last_chunk + 1):
                        plain_len = min(c_size, plain_total - chunk_idx * c_size)
                        enc_len = plain_len + GCM_TAG_SIZE
                        ct = await _read_exact_async(f, enc_len)
                        if len(ct) != enc_len:
                            raise EOFError(f"Truncated encrypted chunk {chunk_idx} on SFTP backend")
                        pt = self.crypto.decrypt_chunk(dek, nonce_prefix, crypto_id, chunk_idx, ct)
                        out = _slice_decrypted(chunk_idx, pt)
                        if out:
                            yield out

    async def delete_remote_files(self, orphans: list[tuple[str, str]]) -> None:
        """Best-effort cleanup of unreferenced files on storage backends."""
        by_backend: dict[str, list[str]] = {}
        for bid, rpath in orphans:
            by_backend.setdefault(bid, []).append(rpath)

        for bid, paths in by_backend.items():
            backend = await self.db.get_backend(bid)
            if not backend:
                continue
            if backend["protocol"] == "local":
                for rel in paths:
                    try:
                        _resolve_local_path(backend["base_path"], rel).unlink(missing_ok=True)
                    except OSError:
                        pass
            else:
                base_dir = backend["base_path"].rstrip("/") or "/"
                try:
                    async with self.acquire_sftp(backend) as sftp:
                        for rel in paths:
                            try:
                                await sftp.remove(posixpath.join(base_dir, rel))
                            except asyncssh.Error:
                                pass
                except Exception:
                    pass

    async def probe_backend(
        self, backend: dict[str, Any], *, persist_status: bool = True
    ) -> dict[str, Any]:
        """Test connectivity, read/write permissions, and filesystem free space."""
        t0 = time.monotonic()
        probe_rel = f".banoss_probe_{uuid.uuid4().hex[:8]}"
        probe_payload = b"banoss-health-check"
        fs_total: Optional[int] = None
        fs_free: Optional[int] = None

        try:
            if backend["protocol"] == "local":
                base = Path(backend["base_path"]).resolve()
                base.mkdir(parents=True, exist_ok=True)
                p = base / probe_rel
                p.write_bytes(probe_payload)
                got = p.read_bytes()
                p.unlink(missing_ok=True)
                if got != probe_payload:
                    raise RuntimeError("Local readback mismatch")
                import shutil

                usage = shutil.disk_usage(base)
                fs_total = usage.total
                fs_free = usage.free
            else:
                base_dir = backend["base_path"].rstrip("/") or "/"
                probe_full = posixpath.join(base_dir, probe_rel)
                async with self.acquire_sftp(backend) as sftp:
                    await sftp.makedirs(base_dir, exist_ok=True)
                    async with sftp.open(probe_full, "wb") as f:
                        await f.write(probe_payload)
                    async with sftp.open(probe_full, "rb") as f:
                        got = await f.read()
                    await sftp.remove(probe_full)
                    if got != probe_payload:
                        raise RuntimeError("SFTP readback mismatch")
                    try:
                        vfs = await sftp.statvfs(base_dir)
                        bsize = vfs.frsize or vfs.bsize
                        fs_total = int(vfs.blocks) * int(bsize)
                        fs_free = int(vfs.bavail) * int(bsize)
                    except asyncssh.Error:
                        pass

            latency_ms = round((time.monotonic() - t0) * 1000, 1)
            msg = f"OK ({latency_ms} ms)"
            if fs_free is not None and fs_total is not None:
                msg += f" | FS free {fs_free / (1024**3):.2f} / {fs_total / (1024**3):.2f} GiB"
            if persist_status:
                await self.db.update_backend(
                    backend["id"],
                    {
                        "last_status": "healthy",
                        "last_message": msg,
                        "last_checked_at": _utc_iso(),
                    },
                )
            return {
                "ok": True,
                "latency_ms": latency_ms,
                "fs_total_bytes": fs_total,
                "fs_free_bytes": fs_free,
                "message": msg,
            }
        except Exception as exc:
            err_msg = str(exc)
            if persist_status:
                await self.db.update_backend(
                    backend["id"],
                    {
                        "last_status": "error",
                        "last_message": err_msg[:300],
                        "last_checked_at": _utc_iso(),
                    },
                )
            return {"ok": False, "message": err_msg}
        finally:
            if not persist_status and backend.get("id"):
                await self.invalidate_backend_pool(backend["id"])


def _resolve_local_path(base_path: str, rel_path: str) -> Path:
    base = Path(base_path).resolve()
    target = (base / rel_path).resolve()
    if not target.is_relative_to(base):
        raise ValueError("Path escapes backend base directory")
    return target


def _read_exact_sync(f: Any, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = f.read(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


async def _read_exact_async(f: Any, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = await f.read(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


async def _safe_close_sftp(
    ssh_conn: asyncssh.SSHClientConnection, sftp: asyncssh.SFTPClient
) -> None:
    try:
        sftp.exit()
    except Exception:
        pass
    try:
        ssh_conn.close()
        await ssh_conn.wait_closed()
    except Exception:
        pass


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_CERT_LINE_RE = re.compile(r"^\S+-cert-v01@openssh\.com\s+\S+.*$", re.MULTILINE)
_AUTH_ERROR_HINT_RE = re.compile(
    r"(permission denied|authentication|unable to authenticate|public key|password|expired|key.*decrypt)",
    re.IGNORECASE,
)


def _split_key_and_certificate(cred: str) -> tuple[str, Optional[str]]:
    """Separate an embedded OpenSSH certificate line from a private key PEM block if both exist."""
    text = (cred or "").strip()
    m = _CERT_LINE_RE.search(text)
    if not m:
        return text, None
    cert_line = m.group(0).strip()
    key_text = (text[: m.start()] + text[m.end() :]).strip()
    return key_text, cert_line


def _load_client_key(cred: str, passphrase: Optional[str]) -> Any:
    key_text, cert_line = _split_key_and_certificate(cred)
    key = asyncssh.import_private_key(key_text or cred, passphrase=passphrase)
    if cert_line:
        cert = asyncssh.import_certificate(cert_line)
        return (key, cert)
    return key


def _epoch_to_iso(epoch: Optional[int]) -> Optional[str]:
    if epoch is None or epoch <= 0 or epoch >= (1 << 62):
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def inspect_ssh_credential(
    cred: str, *, auth_type: str = "key", passphrase: Optional[str] = None
) -> dict[str, Any]:
    """Validate an SSH credential/certificate string and extract metadata & embedded expiry."""
    raw = (cred or "").strip()
    if auth_type == "password":
        return {
            "valid": bool(raw),
            "auth_type": "password",
            "algorithm": "password",
            "fingerprint": None,
            "has_certificate": False,
            "cert_valid_after": None,
            "cert_valid_before": None,
            "needs_passphrase": False,
            "error": None if raw else "密码为空",
        }
    if auth_type != "key":
        return {"valid": True, "auth_type": auth_type, "has_certificate": False}
    if not raw:
        return {"valid": False, "auth_type": "key", "has_certificate": False, "error": "SSH 私钥为空"}

    key_text, cert_line = _split_key_and_certificate(raw)
    cert_after: Optional[str] = None
    cert_before: Optional[str] = None
    if cert_line:
        try:
            cert = asyncssh.import_certificate(cert_line)
            cert_after = _epoch_to_iso(getattr(cert, "_valid_after", None))
            cert_before = _epoch_to_iso(getattr(cert, "_valid_before", None))
        except Exception as exc:
            return {
                "valid": False,
                "auth_type": "key",
                "has_certificate": True,
                "error": f"OpenSSH 证书解析失败: {exc}",
            }

    if not key_text:
        return {
            "valid": bool(cert_line),
            "auth_type": "key",
            "algorithm": "openssh-cert-only",
            "fingerprint": None,
            "has_certificate": bool(cert_line),
            "cert_valid_after": cert_after,
            "cert_valid_before": cert_before,
            "needs_passphrase": False,
            "error": "仅检测到证书内容，请同时包含对应的私钥 PEM" if cert_line else "SSH 私钥为空",
        }

    try:
        key = asyncssh.import_private_key(key_text, passphrase=passphrase or None)
        return {
            "valid": True,
            "auth_type": "key",
            "algorithm": key.get_algorithm(),
            "fingerprint": key.get_fingerprint("sha256"),
            "has_certificate": bool(cert_line),
            "cert_valid_after": cert_after,
            "cert_valid_before": cert_before,
            "needs_passphrase": False,
            "error": None,
        }
    except asyncssh.KeyEncryptionError:
        return {
            "valid": False,
            "auth_type": "key",
            "algorithm": None,
            "fingerprint": None,
            "has_certificate": bool(cert_line),
            "cert_valid_after": cert_after,
            "cert_valid_before": cert_before,
            "needs_passphrase": True,
            "error": "私钥受口令保护或口令错误，请填写 Passphrase",
        }
    except Exception as exc:
        return {
            "valid": False,
            "auth_type": "key",
            "algorithm": None,
            "fingerprint": None,
            "has_certificate": bool(cert_line),
            "cert_valid_after": cert_after,
            "cert_valid_before": cert_before,
            "needs_passphrase": False,
            "error": f"私钥格式无效: {exc}",
        }


def compute_credential_status(
    backend: dict[str, Any], *, warn_hours: int = 24
) -> dict[str, Any]:
    """Compute credential expiration status, remaining seconds, and SSH auth-failure hints."""
    expires_at = backend.get("credential_expires_at") or None
    updated_at = backend.get("credential_updated_at") or None
    auth_error = (
        backend.get("protocol") == "sftp"
        and backend.get("last_status") == "error"
        and bool(_AUTH_ERROR_HINT_RE.search(backend.get("last_message") or ""))
    )
    if backend.get("protocol") == "local" or not expires_at:
        return {
            "credential_updated_at": updated_at,
            "credential_expires_at": expires_at,
            "credential_remaining_seconds": None,
            "credential_status": "none",
            "credential_auth_error": auth_error,
        }
    try:
        dt = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        rem = int((dt - datetime.now(timezone.utc)).total_seconds())
    except Exception:
        return {
            "credential_updated_at": updated_at,
            "credential_expires_at": expires_at,
            "credential_remaining_seconds": None,
            "credential_status": "none",
            "credential_auth_error": auth_error,
        }

    if rem <= 0:
        status = "expired"
    elif rem <= warn_hours * 3600:
        status = "expiring_soon"
    else:
        status = "valid"
    return {
        "credential_updated_at": updated_at,
        "credential_expires_at": expires_at,
        "credential_remaining_seconds": rem,
        "credential_status": status,
        "credential_auth_error": auth_error,
    }
