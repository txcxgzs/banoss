"""SQLite metadata repository for users, backends, bindings, buckets, objects, and multipart state."""

from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Optional

import aiosqlite


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    access_key TEXT UNIQUE NOT NULL,
    secret_key_enc TEXT NOT NULL,
    password_hash TEXT NOT NULL DEFAULT '',
    register_note TEXT NOT NULL DEFAULT '',
    is_active INTEGER NOT NULL DEFAULT 1,
    encryption_enabled INTEGER NOT NULL DEFAULT 1,
    quota_bytes INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS backends (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    protocol TEXT NOT NULL CHECK(protocol IN ('sftp', 'local')),
    host TEXT NOT NULL DEFAULT '',
    port INTEGER NOT NULL DEFAULT 22,
    username TEXT NOT NULL DEFAULT '',
    auth_type TEXT NOT NULL DEFAULT 'key' CHECK(auth_type IN ('key', 'password', 'none')),
    credential_enc TEXT NOT NULL DEFAULT '',
    passphrase_enc TEXT NOT NULL DEFAULT '',
    base_path TEXT NOT NULL,
    max_connections INTEGER NOT NULL DEFAULT 3,
    idle_timeout_sec INTEGER NOT NULL DEFAULT 60,
    quota_bytes INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    read_only INTEGER NOT NULL DEFAULT 0,
    last_status TEXT NOT NULL DEFAULT 'unknown',
    last_message TEXT NOT NULL DEFAULT '',
    last_checked_at TEXT,
    credential_updated_at TEXT,
    credential_expires_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_backends (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    backend_id TEXT NOT NULL REFERENCES backends(id) ON DELETE CASCADE,
    priority INTEGER NOT NULL DEFAULT 100,
    quota_bytes INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    UNIQUE(user_id, backend_id)
);

CREATE TABLE IF NOT EXISTS buckets (
    name TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    acl TEXT NOT NULL DEFAULT 'private' CHECK(acl IN ('private', 'public-read')),
    cors_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS objects (
    id TEXT PRIMARY KEY,
    bucket TEXT NOT NULL REFERENCES buckets(name) ON DELETE CASCADE,
    key TEXT NOT NULL,
    size INTEGER NOT NULL,
    etag TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(bucket, key)
);

CREATE TABLE IF NOT EXISTS object_segments (
    id TEXT PRIMARY KEY,
    object_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
    segment_index INTEGER NOT NULL,
    plain_offset INTEGER NOT NULL,
    plain_size INTEGER NOT NULL,
    remote_size INTEGER NOT NULL,
    backend_id TEXT NOT NULL REFERENCES backends(id) ON DELETE RESTRICT,
    remote_path TEXT NOT NULL,
    encrypted INTEGER NOT NULL DEFAULT 1,
    wrapped_dek TEXT NOT NULL DEFAULT '',
    nonce_prefix_b64 TEXT NOT NULL DEFAULT '',
    chunk_size INTEGER NOT NULL DEFAULT 1048576,
    UNIQUE(object_id, segment_index)
);

CREATE TABLE IF NOT EXISTS multipart_uploads (
    upload_id TEXT PRIMARY KEY,
    bucket TEXT NOT NULL REFERENCES buckets(name) ON DELETE CASCADE,
    key TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS multipart_parts (
    id TEXT PRIMARY KEY,
    upload_id TEXT NOT NULL REFERENCES multipart_uploads(upload_id) ON DELETE CASCADE,
    part_number INTEGER NOT NULL,
    etag TEXT NOT NULL,
    plain_size INTEGER NOT NULL,
    remote_size INTEGER NOT NULL,
    backend_id TEXT NOT NULL REFERENCES backends(id) ON DELETE RESTRICT,
    remote_path TEXT NOT NULL,
    encrypted INTEGER NOT NULL DEFAULT 1,
    wrapped_dek TEXT NOT NULL DEFAULT '',
    nonce_prefix_b64 TEXT NOT NULL DEFAULT '',
    chunk_size INTEGER NOT NULL DEFAULT 1048576,
    created_at TEXT NOT NULL,
    UNIQUE(upload_id, part_number)
);

CREATE TABLE IF NOT EXISTS bucket_requests (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bucket_name TEXT NOT NULL,
    acl TEXT NOT NULL DEFAULT 'private' CHECK(acl IN ('private', 'public-read')),
    requested_quota_bytes INTEGER NOT NULL DEFAULT 0,
    reason TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected')),
    admin_note TEXT NOT NULL DEFAULT '',
    reviewed_at TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_objects_bucket_key ON objects(bucket, key);
CREATE INDEX IF NOT EXISTS idx_segments_object ON object_segments(object_id, segment_index);
CREATE INDEX IF NOT EXISTS idx_segments_remote ON object_segments(backend_id, remote_path);
CREATE INDEX IF NOT EXISTS idx_parts_upload ON multipart_parts(upload_id, part_number);
CREATE INDEX IF NOT EXISTS idx_parts_remote ON multipart_parts(backend_id, remote_path);
CREATE INDEX IF NOT EXISTS idx_user_backends_user ON user_backends(user_id, priority);
CREATE INDEX IF NOT EXISTS idx_bucket_requests_user ON bucket_requests(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bucket_requests_status ON bucket_requests(status, created_at DESC);
"""


class Database:
    """Async SQLite repository wrapping all BanOSS metadata operations."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(SCHEMA_SQL)
        # Idempotent schema migrations for existing databases
        async with self._conn.execute("PRAGMA table_info(buckets)") as cur:
            cols = {r["name"] for r in await cur.fetchall()}
        if "acl" not in cols:
            await self._conn.execute("ALTER TABLE buckets ADD COLUMN acl TEXT NOT NULL DEFAULT 'private'")
        if "cors_json" not in cols:
            await self._conn.execute("ALTER TABLE buckets ADD COLUMN cors_json TEXT NOT NULL DEFAULT '[]'")
        async with self._conn.execute("PRAGMA table_info(backends)") as cur:
            bcols = {r["name"] for r in await cur.fetchall()}
        if "credential_updated_at" not in bcols:
            await self._conn.execute("ALTER TABLE backends ADD COLUMN credential_updated_at TEXT")
        if "credential_expires_at" not in bcols:
            await self._conn.execute("ALTER TABLE backends ADD COLUMN credential_expires_at TEXT")
        async with self._conn.execute("PRAGMA table_info(users)") as cur:
            ucols = {r["name"] for r in await cur.fetchall()}
        if "password_hash" not in ucols:
            await self._conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''")
        if "register_note" not in ucols:
            await self._conn.execute("ALTER TABLE users ADD COLUMN register_note TEXT NOT NULL DEFAULT ''")
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database is not connected")
        return self._conn

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[aiosqlite.Connection]:
        await self.conn.execute("BEGIN")
        try:
            yield self.conn
            await self.conn.commit()
        except Exception:
            await self.conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------
    async def create_user(
        self,
        username: str,
        access_key: str,
        secret_key_enc: str,
        *,
        password_hash: str = "",
        register_note: str = "",
        encryption_enabled: bool = True,
        quota_bytes: int = 0,
        is_active: bool = True,
    ) -> dict[str, Any]:
        user_id = str(uuid.uuid4())
        now = utcnow_iso()
        await self.conn.execute(
            """
            INSERT INTO users (id, username, access_key, secret_key_enc, password_hash, register_note, is_active, encryption_enabled, quota_bytes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                username,
                access_key,
                secret_key_enc,
                password_hash,
                register_note,
                int(is_active),
                int(encryption_enabled),
                quota_bytes,
                now,
            ),
        )
        await self.conn.commit()
        return await self.get_user(user_id)  # type: ignore[return-value]

    async def get_user(self, user_id: str) -> Optional[dict[str, Any]]:
        async with self.conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def get_user_by_username(self, username: str) -> Optional[dict[str, Any]]:
        async with self.conn.execute("SELECT * FROM users WHERE username = ?", (username,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def get_user_by_access_key(self, access_key: str) -> Optional[dict[str, Any]]:
        async with self.conn.execute(
            "SELECT * FROM users WHERE access_key = ?", (access_key,)
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def list_users(self) -> list[dict[str, Any]]:
        sql = """
        SELECT u.*,
               COALESCE((
                   SELECT SUM(o.size)
                   FROM objects o
                   JOIN buckets b ON b.name = o.bucket
                   WHERE b.owner_user_id = u.id
               ), 0) AS used_bytes,
               COALESCE((
                   SELECT COUNT(*)
                   FROM buckets b
                   WHERE b.owner_user_id = u.id
               ), 0) AS bucket_count,
               COALESCE((
                   SELECT COUNT(*)
                   FROM user_backends ub
                   WHERE ub.user_id = u.id AND ub.is_active = 1
               ), 0) AS bound_backend_count
        FROM users u
        ORDER BY u.created_at DESC
        """
        async with self.conn.execute(sql) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def update_user(
        self,
        user_id: str,
        *,
        is_active: Optional[bool] = None,
        encryption_enabled: Optional[bool] = None,
        quota_bytes: Optional[int] = None,
        access_key: Optional[str] = None,
        secret_key_enc: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        fields: list[str] = []
        values: list[Any] = []
        if is_active is not None:
            fields.append("is_active = ?")
            values.append(int(is_active))
        if encryption_enabled is not None:
            fields.append("encryption_enabled = ?")
            values.append(int(encryption_enabled))
        if quota_bytes is not None:
            fields.append("quota_bytes = ?")
            values.append(quota_bytes)
        if access_key is not None:
            fields.append("access_key = ?")
            values.append(access_key)
        if secret_key_enc is not None:
            fields.append("secret_key_enc = ?")
            values.append(secret_key_enc)
        if not fields:
            return await self.get_user(user_id)
        values.append(user_id)
        await self.conn.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", values)
        await self.conn.commit()
        return await self.get_user(user_id)

    async def delete_user(self, user_id: str) -> list[tuple[str, str]]:
        """Delete user and return any orphaned remote files to clean up."""
        async with self.conn.execute(
            """
            SELECT DISTINCT s.backend_id, s.remote_path
            FROM object_segments s
            JOIN objects o ON o.id = s.object_id
            JOIN buckets b ON b.name = o.bucket
            WHERE b.owner_user_id = ?
            UNION
            SELECT DISTINCT mp.backend_id, mp.remote_path
            FROM multipart_parts mp
            JOIN multipart_uploads mu ON mu.upload_id = mp.upload_id
            WHERE mu.user_id = ?
            """,
            (user_id, user_id),
        ) as cur:
            candidates = [(r["backend_id"], r["remote_path"]) for r in await cur.fetchall()]

        await self.conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await self.conn.commit()
        return await self.filter_unreferenced_remotes(candidates)

    async def get_user_logical_used_bytes(self, user_id: str) -> int:
        async with self.conn.execute(
            """
            SELECT COALESCE(SUM(o.size), 0) AS total
            FROM objects o
            JOIN buckets b ON b.name = o.bucket
            WHERE b.owner_user_id = ?
            """,
            (user_id,),
        ) as cur:
            row = await cur.fetchone()
            return int(row["total"]) if row else 0

    # ------------------------------------------------------------------
    # Backends
    # ------------------------------------------------------------------
    async def create_backend(
        self,
        *,
        name: str,
        protocol: str,
        host: str = "",
        port: int = 22,
        username: str = "",
        auth_type: str = "key",
        credential_enc: str = "",
        passphrase_enc: str = "",
        base_path: str,
        max_connections: int = 3,
        idle_timeout_sec: int = 60,
        quota_bytes: int = 0,
        is_active: bool = True,
        read_only: bool = False,
        credential_updated_at: Optional[str] = None,
        credential_expires_at: Optional[str] = None,
    ) -> dict[str, Any]:
        backend_id = str(uuid.uuid4())
        now = utcnow_iso()
        cred_updated = credential_updated_at if credential_updated_at is not None else (now if credential_enc else None)
        await self.conn.execute(
            """
            INSERT INTO backends (
                id, name, protocol, host, port, username, auth_type,
                credential_enc, passphrase_enc, base_path, max_connections,
                idle_timeout_sec, quota_bytes, is_active, read_only,
                credential_updated_at, credential_expires_at, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                backend_id,
                name,
                protocol,
                host,
                port,
                username,
                auth_type,
                credential_enc,
                passphrase_enc,
                base_path,
                max_connections,
                idle_timeout_sec,
                quota_bytes,
                int(is_active),
                int(read_only),
                cred_updated,
                credential_expires_at,
                now,
            ),
        )
        await self.conn.commit()
        return await self.get_backend(backend_id)  # type: ignore[return-value]

    async def get_backend(self, backend_id: str) -> Optional[dict[str, Any]]:
        async with self.conn.execute("SELECT * FROM backends WHERE id = ?", (backend_id,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def list_backends(self) -> list[dict[str, Any]]:
        async with self.conn.execute("SELECT * FROM backends ORDER BY created_at DESC") as cur:
            rows = [dict(r) for r in await cur.fetchall()]
        for row in rows:
            row["used_bytes"] = await self.get_backend_used_bytes(row["id"])
        return rows

    async def get_backend_used_bytes(self, backend_id: str) -> int:
        sql = """
        SELECT COALESCE(SUM(remote_size), 0) AS total FROM (
            SELECT remote_path, MAX(remote_size) AS remote_size
            FROM object_segments
            WHERE backend_id = ?
            GROUP BY remote_path
            UNION ALL
            SELECT remote_path, MAX(remote_size) AS remote_size
            FROM multipart_parts
            WHERE backend_id = ?
            GROUP BY remote_path
        )
        """
        async with self.conn.execute(sql, (backend_id, backend_id)) as cur:
            row = await cur.fetchone()
            return int(row["total"]) if row else 0

    async def update_backend(self, backend_id: str, updates: dict[str, Any]) -> Optional[dict[str, Any]]:
        allowed = {
            "name",
            "protocol",
            "host",
            "port",
            "username",
            "auth_type",
            "credential_enc",
            "passphrase_enc",
            "base_path",
            "max_connections",
            "idle_timeout_sec",
            "quota_bytes",
            "is_active",
            "read_only",
            "last_status",
            "last_message",
            "last_checked_at",
            "credential_updated_at",
            "credential_expires_at",
        }
        fields = []
        values = []
        for k, v in updates.items():
            if k in allowed:
                fields.append(f"{k} = ?")
                values.append(int(v) if isinstance(v, bool) else v)
        if not fields:
            return await self.get_backend(backend_id)
        values.append(backend_id)
        await self.conn.execute(f"UPDATE backends SET {', '.join(fields)} WHERE id = ?", values)
        await self.conn.commit()
        return await self.get_backend(backend_id)

    async def delete_backend(self, backend_id: str) -> None:
        await self.conn.execute("DELETE FROM backends WHERE id = ?", (backend_id,))
        await self.conn.commit()

    # ------------------------------------------------------------------
    # User-Backend Bindings
    # ------------------------------------------------------------------
    async def upsert_user_backend(
        self,
        *,
        user_id: str,
        backend_id: str,
        priority: int = 100,
        quota_bytes: int = 0,
        is_active: bool = True,
    ) -> dict[str, Any]:
        now = utcnow_iso()
        async with self.conn.execute(
            "SELECT id FROM user_backends WHERE user_id = ? AND backend_id = ?",
            (user_id, backend_id),
        ) as cur:
            existing = await cur.fetchone()
        if existing:
            await self.conn.execute(
                """
                UPDATE user_backends
                SET priority = ?, quota_bytes = ?, is_active = ?
                WHERE id = ?
                """,
                (priority, quota_bytes, int(is_active), existing["id"]),
            )
            binding_id = existing["id"]
        else:
            binding_id = str(uuid.uuid4())
            await self.conn.execute(
                """
                INSERT INTO user_backends (id, user_id, backend_id, priority, quota_bytes, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (binding_id, user_id, backend_id, priority, quota_bytes, int(is_active), now),
            )
        await self.conn.commit()
        async with self.conn.execute("SELECT * FROM user_backends WHERE id = ?", (binding_id,)) as cur:
            row = await cur.fetchone()
            return dict(row)  # type: ignore[arg-type]

    async def delete_user_backend(self, user_id: str, backend_id: str) -> None:
        await self.conn.execute(
            "DELETE FROM user_backends WHERE user_id = ? AND backend_id = ?",
            (user_id, backend_id),
        )
        await self.conn.commit()

    async def list_user_backends(self, user_id: Optional[str] = None) -> list[dict[str, Any]]:
        sql = """
        SELECT ub.*,
               u.username AS user_username,
               b.name AS backend_name,
               b.protocol AS backend_protocol,
               b.host AS backend_host,
               b.port AS backend_port,
               b.base_path AS backend_base_path,
               b.quota_bytes AS backend_quota_bytes,
               b.is_active AS backend_is_active,
               b.read_only AS backend_read_only
        FROM user_backends ub
        JOIN users u ON u.id = ub.user_id
        JOIN backends b ON b.id = ub.backend_id
        """
        params: tuple[Any, ...] = ()
        if user_id is not None:
            sql += " WHERE ub.user_id = ?"
            params = (user_id,)
        sql += " ORDER BY ub.priority ASC, ub.created_at ASC"
        async with self.conn.execute(sql, params) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
        for r in rows:
            r["backend_used_bytes"] = await self.get_backend_used_bytes(r["backend_id"])
            r["user_backend_used_bytes"] = await self.get_user_backend_used_bytes(
                r["user_id"], r["backend_id"]
            )
        return rows

    async def get_user_backend_used_bytes(self, user_id: str, backend_id: str) -> int:
        sql = """
        SELECT COALESCE(SUM(remote_size), 0) AS total FROM (
            SELECT s.remote_path, MAX(s.remote_size) AS remote_size
            FROM object_segments s
            JOIN objects o ON o.id = s.object_id
            JOIN buckets b ON b.name = o.bucket
            WHERE b.owner_user_id = ? AND s.backend_id = ?
            GROUP BY s.remote_path
            UNION ALL
            SELECT mp.remote_path, MAX(mp.remote_size) AS remote_size
            FROM multipart_parts mp
            JOIN multipart_uploads mu ON mu.upload_id = mp.upload_id
            WHERE mu.user_id = ? AND mp.backend_id = ?
            GROUP BY mp.remote_path
        )
        """
        async with self.conn.execute(sql, (user_id, backend_id, user_id, backend_id)) as cur:
            row = await cur.fetchone()
            return int(row["total"]) if row else 0

    async def select_writable_backend_for_user(
        self, user_id: str, needed_bytes: int = 0
    ) -> Optional[dict[str, Any]]:
        """Choose the best active writable backend bound to this user."""
        sql = """
        SELECT b.*, ub.priority AS binding_priority, ub.quota_bytes AS binding_quota_bytes
        FROM user_backends ub
        JOIN backends b ON b.id = ub.backend_id
        WHERE ub.user_id = ?
          AND ub.is_active = 1
          AND b.is_active = 1
          AND b.read_only = 0
        ORDER BY ub.priority ASC, ub.created_at ASC
        """
        async with self.conn.execute(sql, (user_id,)) as cur:
            candidates = [dict(r) for r in await cur.fetchall()]

        eligible: list[tuple[int, float, dict[str, Any]]] = []
        for b in candidates:
            b_used = await self.get_backend_used_bytes(b["id"])
            b_quota = int(b["quota_bytes"])
            if b_quota > 0 and (b_used + needed_bytes) > b_quota:
                continue

            ub_quota = int(b["binding_quota_bytes"])
            if ub_quota > 0:
                ub_used = await self.get_user_backend_used_bytes(user_id, b["id"])
                if (ub_used + needed_bytes) > ub_quota:
                    continue

            # Prefer lower binding_priority; break ties by largest remaining capacity
            if b_quota > 0:
                rem_score = float(b_quota - b_used)
            elif ub_quota > 0:
                rem_score = float(ub_quota)
            else:
                rem_score = float(10**18 - b_used)
            eligible.append((int(b["binding_priority"]), -rem_score, b))

        if not eligible:
            return None
        eligible.sort(key=lambda item: (item[0], item[1]))
        return eligible[0][2]

    # ------------------------------------------------------------------
    # Buckets
    # ------------------------------------------------------------------
    async def create_bucket(
        self, name: str, owner_user_id: str, acl: str = "private"
    ) -> dict[str, Any]:
        now = utcnow_iso()
        await self.conn.execute(
            "INSERT INTO buckets (name, owner_user_id, acl, cors_json, created_at) VALUES (?, ?, ?, '[]', ?)",
            (name, owner_user_id, acl, now),
        )
        await self.conn.commit()
        return {
            "name": name,
            "owner_user_id": owner_user_id,
            "acl": acl,
            "cors_rules": [],
            "created_at": now,
        }

    async def get_bucket(self, name: str) -> Optional[dict[str, Any]]:
        async with self.conn.execute("SELECT * FROM buckets WHERE name = ?", (name,)) as cur:
            row = await cur.fetchone()
            if not row:
                return None
            b = dict(row)
            b["cors_rules"] = json.loads(b.get("cors_json") or "[]")
            return b

    async def update_bucket(
        self,
        name: str,
        *,
        acl: Optional[str] = None,
        cors_rules: Optional[list[dict[str, Any]]] = None,
    ) -> Optional[dict[str, Any]]:
        fields: list[str] = []
        values: list[Any] = []
        if acl is not None:
            fields.append("acl = ?")
            values.append(acl)
        if cors_rules is not None:
            fields.append("cors_json = ?")
            values.append(json.dumps(cors_rules))
        if fields:
            values.append(name)
            await self.conn.execute(f"UPDATE buckets SET {', '.join(fields)} WHERE name = ?", values)
            await self.conn.commit()
        return await self.get_bucket(name)

    async def list_buckets(self, owner_user_id: Optional[str] = None) -> list[dict[str, Any]]:
        sql = """
        SELECT b.*,
               u.username AS owner_username,
               COALESCE((SELECT COUNT(*) FROM objects o WHERE o.bucket = b.name), 0) AS object_count,
               COALESCE((SELECT SUM(o.size) FROM objects o WHERE o.bucket = b.name), 0) AS total_size
        FROM buckets b
        JOIN users u ON u.id = b.owner_user_id
        """
        params: tuple[Any, ...] = ()
        if owner_user_id is not None:
            sql += " WHERE b.owner_user_id = ?"
            params = (owner_user_id,)
        sql += " ORDER BY b.created_at ASC"
        async with self.conn.execute(sql, params) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
        for r in rows:
            r["cors_rules"] = json.loads(r.get("cors_json") or "[]")
        return rows

    async def delete_bucket(self, name: str) -> None:
        await self.conn.execute("DELETE FROM buckets WHERE name = ?", (name,))
        await self.conn.commit()

    async def count_bucket_objects(self, bucket: str) -> int:
        async with self.conn.execute(
            "SELECT COUNT(*) AS cnt FROM objects WHERE bucket = ?", (bucket,)
        ) as cur:
            row = await cur.fetchone()
            return int(row["cnt"]) if row else 0

    # ------------------------------------------------------------------
    # Objects & Segments
    # ------------------------------------------------------------------
    async def get_object(self, bucket: str, key: str) -> Optional[dict[str, Any]]:
        async with self.conn.execute(
            "SELECT * FROM objects WHERE bucket = ? AND key = ?", (bucket, key)
        ) as cur:
            row = await cur.fetchone()
            if not row:
                return None
            obj = dict(row)
            obj["metadata"] = json.loads(obj.get("metadata_json") or "{}")
            return obj

    async def get_object_with_segments(
        self, bucket: str, key: str
    ) -> Optional[tuple[dict[str, Any], list[dict[str, Any]]]]:
        obj = await self.get_object(bucket, key)
        if not obj:
            return None
        async with self.conn.execute(
            "SELECT * FROM object_segments WHERE object_id = ? ORDER BY segment_index ASC",
            (obj["id"],),
        ) as cur:
            segs = [dict(r) for r in await cur.fetchall()]
        return obj, segs

    async def list_objects(
        self,
        bucket: str,
        *,
        prefix: str = "",
        delimiter: str = "",
        start_after: str = "",
        max_keys: int = 1000,
    ) -> dict[str, Any]:
        """List objects with S3 prefix + delimiter folding directly from SQLite."""
        sql = "SELECT * FROM objects WHERE bucket = ?"
        params: list[Any] = [bucket]
        if prefix:
            # Escape LIKE wildcards using ESCAPE '\'
            escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            sql += " AND key LIKE ? ESCAPE '\\'"
            params.append(f"{escaped}%")
        if start_after:
            sql += " AND key > ?"
            params.append(start_after)
        sql += " ORDER BY key ASC"

        async with self.conn.execute(sql, params) as cur:
            rows = [dict(r) for r in await cur.fetchall()]

        contents: list[dict[str, Any]] = []
        common_prefixes_set: set[str] = set()
        common_prefixes: list[str] = []
        is_truncated = False
        next_token: Optional[str] = None
        last_returned_key: Optional[str] = None
        count = 0

        for row in rows:
            key = row["key"]
            if delimiter:
                rest = key[len(prefix) :]
                idx = rest.find(delimiter)
                if idx != -1:
                    cp = prefix + rest[: idx + len(delimiter)]
                    if cp not in common_prefixes_set:
                        if count >= max_keys:
                            is_truncated = True
                            next_token = last_returned_key or key
                            break
                        common_prefixes_set.add(cp)
                        common_prefixes.append(cp)
                        last_returned_key = key
                        count += 1
                    continue

            if count >= max_keys:
                is_truncated = True
                next_token = last_returned_key or key
                break
            contents.append(row)
            last_returned_key = key
            count += 1

        return {
            "contents": contents,
            "common_prefixes": common_prefixes,
            "is_truncated": is_truncated,
            "next_continuation_token": next_token if is_truncated else None,
            "key_count": len(contents) + len(common_prefixes),
        }

    async def put_object_with_segments(
        self,
        *,
        bucket: str,
        key: str,
        size: int,
        etag: str,
        content_type: str,
        metadata: dict[str, str],
        segments: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], list[tuple[str, str]]]:
        """Insert or replace an object and return orphaned remote files to clean up."""
        now = utcnow_iso()
        old_candidates: list[tuple[str, str]] = []

        async with self.transaction() as conn:
            async with conn.execute(
                "SELECT id FROM objects WHERE bucket = ? AND key = ?", (bucket, key)
            ) as cur:
                existing = await cur.fetchone()
            if existing:
                async with conn.execute(
                    "SELECT backend_id, remote_path FROM object_segments WHERE object_id = ?",
                    (existing["id"],),
                ) as cur:
                    old_candidates = [
                        (r["backend_id"], r["remote_path"]) for r in await cur.fetchall()
                    ]
                await conn.execute("DELETE FROM objects WHERE id = ?", (existing["id"],))

            object_id = str(uuid.uuid4())
            await conn.execute(
                """
                INSERT INTO objects (id, bucket, key, size, etag, content_type, metadata_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    object_id,
                    bucket,
                    key,
                    size,
                    etag,
                    content_type,
                    json.dumps(metadata),
                    now,
                    now,
                ),
            )
            for seg in segments:
                await conn.execute(
                    """
                    INSERT INTO object_segments (
                        id, object_id, segment_index, plain_offset, plain_size,
                        remote_size, backend_id, remote_path, encrypted,
                        wrapped_dek, nonce_prefix_b64, chunk_size
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        seg["id"],
                        object_id,
                        seg["segment_index"],
                        seg["plain_offset"],
                        seg["plain_size"],
                        seg["remote_size"],
                        seg["backend_id"],
                        seg["remote_path"],
                        int(seg["encrypted"]),
                        seg["wrapped_dek"],
                        seg["nonce_prefix_b64"],
                        seg["chunk_size"],
                    ),
                )

        orphans = await self.filter_unreferenced_remotes(old_candidates)
        obj = await self.get_object(bucket, key)
        return obj, orphans  # type: ignore[return-value]

    async def delete_object(self, bucket: str, key: str) -> tuple[bool, list[tuple[str, str]]]:
        async with self.conn.execute(
            "SELECT id FROM objects WHERE bucket = ? AND key = ?", (bucket, key)
        ) as cur:
            existing = await cur.fetchone()
        if not existing:
            return False, []
        async with self.conn.execute(
            "SELECT backend_id, remote_path FROM object_segments WHERE object_id = ?",
            (existing["id"],),
        ) as cur:
            candidates = [(r["backend_id"], r["remote_path"]) for r in await cur.fetchall()]
        await self.conn.execute("DELETE FROM objects WHERE id = ?", (existing["id"],))
        await self.conn.commit()
        orphans = await self.filter_unreferenced_remotes(candidates)
        return True, orphans

    async def rename_object(
        self, bucket: str, old_key: str, new_key: str
    ) -> Optional[dict[str, Any]]:
        """Atomically rename an object key in-place without moving remote segments."""
        now = utcnow_iso()
        async with self.transaction() as conn:
            async with conn.execute(
                "SELECT id FROM objects WHERE bucket = ? AND key = ?", (bucket, old_key)
            ) as cur:
                src = await cur.fetchone()
            if not src:
                return None
            if old_key != new_key:
                async with conn.execute(
                    "SELECT id FROM objects WHERE bucket = ? AND key = ?", (bucket, new_key)
                ) as cur:
                    if await cur.fetchone():
                        raise ValueError("Target object key already exists")
            await conn.execute(
                "UPDATE objects SET key = ?, updated_at = ? WHERE id = ?",
                (new_key, now, src["id"]),
            )
        return await self.get_object(bucket, new_key)

    async def delete_objects_by_prefix(
        self, bucket: str, prefix: str
    ) -> tuple[int, list[tuple[str, str]]]:
        escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"{escaped}%"
        async with self.conn.execute(
            "SELECT id FROM objects WHERE bucket = ? AND key LIKE ? ESCAPE '\\'",
            (bucket, pattern),
        ) as cur:
            ids = [r["id"] for r in await cur.fetchall()]
        if not ids:
            return 0, []
        placeholders = ",".join("?" for _ in ids)
        async with self.conn.execute(
            f"SELECT backend_id, remote_path FROM object_segments WHERE object_id IN ({placeholders})",
            ids,
        ) as cur:
            candidates = [(r["backend_id"], r["remote_path"]) for r in await cur.fetchall()]
        await self.conn.execute(
            f"DELETE FROM objects WHERE id IN ({placeholders})",
            ids,
        )
        await self.conn.commit()
        orphans = await self.filter_unreferenced_remotes(candidates)
        return len(ids), orphans

    async def filter_unreferenced_remotes(
        self, candidates: list[tuple[str, str]]
    ) -> list[tuple[str, str]]:
        orphans: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for backend_id, remote_path in candidates:
            if (backend_id, remote_path) in seen or not remote_path:
                continue
            seen.add((backend_id, remote_path))
            async with self.conn.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM object_segments WHERE backend_id = ? AND remote_path = ?)
                    +
                    (SELECT COUNT(*) FROM multipart_parts WHERE backend_id = ? AND remote_path = ?)
                AS ref_count
                """,
                (backend_id, remote_path, backend_id, remote_path),
            ) as cur:
                row = await cur.fetchone()
                if row and int(row["ref_count"]) == 0:
                    orphans.append((backend_id, remote_path))
        return orphans

    # ------------------------------------------------------------------
    # Multipart Uploads
    # ------------------------------------------------------------------
    async def create_multipart_upload(
        self,
        *,
        bucket: str,
        key: str,
        user_id: str,
        content_type: str,
        metadata: dict[str, str],
    ) -> dict[str, Any]:
        upload_id = uuid.uuid4().hex
        now = utcnow_iso()
        await self.conn.execute(
            """
            INSERT INTO multipart_uploads (upload_id, bucket, key, user_id, content_type, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (upload_id, bucket, key, user_id, content_type, json.dumps(metadata), now),
        )
        await self.conn.commit()
        return await self.get_multipart_upload(upload_id)  # type: ignore[return-value]

    async def get_multipart_upload(self, upload_id: str) -> Optional[dict[str, Any]]:
        async with self.conn.execute(
            "SELECT * FROM multipart_uploads WHERE upload_id = ?", (upload_id,)
        ) as cur:
            row = await cur.fetchone()
            if not row:
                return None
            d = dict(row)
            d["metadata"] = json.loads(d.get("metadata_json") or "{}")
            return d

    async def list_multipart_uploads(
        self, bucket: str, prefix: str = ""
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM multipart_uploads WHERE bucket = ?"
        params: list[Any] = [bucket]
        if prefix:
            escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            sql += " AND key LIKE ? ESCAPE '\\'"
            params.append(f"{escaped}%")
        sql += " ORDER BY created_at ASC"
        async with self.conn.execute(sql, params) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def upsert_multipart_part(
        self,
        *,
        part_id: str,
        upload_id: str,
        part_number: int,
        etag: str,
        plain_size: int,
        remote_size: int,
        backend_id: str,
        remote_path: str,
        encrypted: bool,
        wrapped_dek: str,
        nonce_prefix_b64: str,
        chunk_size: int,
    ) -> list[tuple[str, str]]:
        now = utcnow_iso()
        old_candidates: list[tuple[str, str]] = []
        async with self.transaction() as conn:
            async with conn.execute(
                "SELECT backend_id, remote_path FROM multipart_parts WHERE upload_id = ? AND part_number = ?",
                (upload_id, part_number),
            ) as cur:
                existing = await cur.fetchone()
            if existing:
                old_candidates.append((existing["backend_id"], existing["remote_path"]))
                await conn.execute(
                    "DELETE FROM multipart_parts WHERE upload_id = ? AND part_number = ?",
                    (upload_id, part_number),
                )
            await conn.execute(
                """
                INSERT INTO multipart_parts (
                    id, upload_id, part_number, etag, plain_size, remote_size,
                    backend_id, remote_path, encrypted, wrapped_dek,
                    nonce_prefix_b64, chunk_size, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    part_id,
                    upload_id,
                    part_number,
                    etag,
                    plain_size,
                    remote_size,
                    backend_id,
                    remote_path,
                    int(encrypted),
                    wrapped_dek,
                    nonce_prefix_b64,
                    chunk_size,
                    now,
                ),
            )
        return await self.filter_unreferenced_remotes(old_candidates)

    async def list_multipart_parts(self, upload_id: str) -> list[dict[str, Any]]:
        async with self.conn.execute(
            "SELECT * FROM multipart_parts WHERE upload_id = ? ORDER BY part_number ASC",
            (upload_id,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def complete_multipart_upload(
        self,
        *,
        upload: dict[str, Any],
        selected_parts: list[dict[str, Any]],
        etag: str,
    ) -> tuple[dict[str, Any], list[tuple[str, str]]]:
        """Promote uploaded parts into object_segments atomically with zero SFTP re-transfer."""
        now = utcnow_iso()
        bucket = upload["bucket"]
        key = upload["key"]
        upload_id = upload["upload_id"]
        old_candidates: list[tuple[str, str]] = []

        selected_ids = {p["id"] for p in selected_parts}
        all_parts = await self.list_multipart_parts(upload_id)
        for p in all_parts:
            if p["id"] not in selected_ids:
                old_candidates.append((p["backend_id"], p["remote_path"]))

        total_size = sum(int(p["plain_size"]) for p in selected_parts)

        async with self.transaction() as conn:
            async with conn.execute(
                "SELECT id FROM objects WHERE bucket = ? AND key = ?", (bucket, key)
            ) as cur:
                existing = await cur.fetchone()
            if existing:
                async with conn.execute(
                    "SELECT backend_id, remote_path FROM object_segments WHERE object_id = ?",
                    (existing["id"],),
                ) as cur:
                    old_candidates.extend(
                        (r["backend_id"], r["remote_path"]) for r in await cur.fetchall()
                    )
                await conn.execute("DELETE FROM objects WHERE id = ?", (existing["id"],))

            object_id = str(uuid.uuid4())
            await conn.execute(
                """
                INSERT INTO objects (id, bucket, key, size, etag, content_type, metadata_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    object_id,
                    bucket,
                    key,
                    total_size,
                    etag,
                    upload["content_type"],
                    upload["metadata_json"],
                    now,
                    now,
                ),
            )

            offset = 0
            for idx, part in enumerate(selected_parts):
                p_size = int(part["plain_size"])
                await conn.execute(
                    """
                    INSERT INTO object_segments (
                        id, object_id, segment_index, plain_offset, plain_size,
                        remote_size, backend_id, remote_path, encrypted,
                        wrapped_dek, nonce_prefix_b64, chunk_size
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        part["id"],
                        object_id,
                        idx,
                        offset,
                        p_size,
                        part["remote_size"],
                        part["backend_id"],
                        part["remote_path"],
                        part["encrypted"],
                        part["wrapped_dek"],
                        part["nonce_prefix_b64"],
                        part["chunk_size"],
                    ),
                )
                offset += p_size

            await conn.execute(
                "DELETE FROM multipart_uploads WHERE upload_id = ?", (upload_id,)
            )

        orphans = await self.filter_unreferenced_remotes(old_candidates)
        obj = await self.get_object(bucket, key)
        return obj, orphans  # type: ignore[return-value]

    async def abort_multipart_upload(self, upload_id: str) -> tuple[bool, list[tuple[str, str]]]:
        upload = await self.get_multipart_upload(upload_id)
        if not upload:
            return False, []
        parts = await self.list_multipart_parts(upload_id)
        candidates = [(p["backend_id"], p["remote_path"]) for p in parts]
        await self.conn.execute(
            "DELETE FROM multipart_uploads WHERE upload_id = ?", (upload_id,)
        )
        await self.conn.commit()
        return True, await self.filter_unreferenced_remotes(candidates)

    # ------------------------------------------------------------------
    # Admin Overview Stats
    # ------------------------------------------------------------------
    async def get_stats(self) -> dict[str, Any]:
        async with self.conn.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM users) AS users,
                (SELECT COUNT(*) FROM backends) AS backends,
                (SELECT COUNT(*) FROM buckets) AS buckets,
                (SELECT COUNT(*) FROM objects) AS objects,
                (SELECT COALESCE(SUM(size), 0) FROM objects) AS logical_bytes,
                (SELECT COUNT(*) FROM multipart_uploads) AS active_multiparts,
                (SELECT COUNT(*) FROM bucket_requests WHERE status = 'pending') AS pending_bucket_requests
            """
        ) as cur:
            row = dict(await cur.fetchone())  # type: ignore[arg-type]
        async with self.conn.execute(
            """
            SELECT COALESCE(SUM(remote_size), 0) AS total FROM (
                SELECT backend_id, remote_path, MAX(remote_size) AS remote_size
                FROM object_segments
                GROUP BY backend_id, remote_path
                UNION ALL
                SELECT backend_id, remote_path, MAX(remote_size) AS remote_size
                FROM multipart_parts
                GROUP BY backend_id, remote_path
            )
            """
        ) as cur:
            r2 = await cur.fetchone()
            row["physical_bytes"] = int(r2["total"]) if r2 else 0
        return row

    # ------------------------------------------------------------------
    # Bucket Access Requests (Self-service User Applications -> Admin Approval)
    # ------------------------------------------------------------------
    async def create_bucket_request(
        self,
        user_id: str,
        bucket_name: str,
        *,
        acl: str = "private",
        requested_quota_bytes: int = 0,
        reason: str = "",
    ) -> dict[str, Any]:
        req_id = str(uuid.uuid4())
        now = utcnow_iso()
        await self.conn.execute(
            """
            INSERT INTO bucket_requests (
                id, user_id, bucket_name, acl, requested_quota_bytes, reason, status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
            """,
            (req_id, user_id, bucket_name, acl, requested_quota_bytes, reason, now),
        )
        await self.conn.commit()
        return await self.get_bucket_request(req_id)  # type: ignore[return-value]

    async def get_bucket_request(self, request_id: str) -> Optional[dict[str, Any]]:
        sql = """
        SELECT br.*, u.username AS username, u.access_key AS user_access_key,
               u.quota_bytes AS user_quota_bytes,
               (SELECT COUNT(*) FROM user_backends ub WHERE ub.user_id = br.user_id AND ub.is_active = 1) AS user_bound_count
        FROM bucket_requests br
        JOIN users u ON u.id = br.user_id
        WHERE br.id = ?
        """
        async with self.conn.execute(sql, (request_id,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def get_pending_bucket_request_by_name(self, bucket_name: str) -> Optional[dict[str, Any]]:
        async with self.conn.execute(
            "SELECT * FROM bucket_requests WHERE bucket_name = ? AND status = 'pending'",
            (bucket_name,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def list_bucket_requests(
        self, *, user_id: Optional[str] = None, status: Optional[str] = None
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if user_id:
            clauses.append("br.user_id = ?")
            params.append(user_id)
        if status:
            clauses.append("br.status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
        SELECT br.*, u.username AS username, u.access_key AS user_access_key,
               u.quota_bytes AS user_quota_bytes,
               (SELECT COUNT(*) FROM user_backends ub WHERE ub.user_id = br.user_id AND ub.is_active = 1) AS user_bound_count
        FROM bucket_requests br
        JOIN users u ON u.id = br.user_id
        {where}
        ORDER BY CASE WHEN br.status = 'pending' THEN 0 ELSE 1 END, br.created_at DESC
        """
        async with self.conn.execute(sql, params) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def update_bucket_request_status(
        self, request_id: str, status: str, *, admin_note: str = ""
    ) -> Optional[dict[str, Any]]:
        now = utcnow_iso()
        await self.conn.execute(
            "UPDATE bucket_requests SET status = ?, admin_note = ?, reviewed_at = ? WHERE id = ?",
            (status, admin_note, now, request_id),
        )
        await self.conn.commit()
        return await self.get_bucket_request(request_id)

    async def get_user_opaque_quota_info(self, user_id: str) -> dict[str, Any]:
        """Return aggregated user capacity flags without revealing backend identities."""
        user = await self.get_user(user_id)
        if not user:
            return {"has_storage_pool": False, "effective_quota_bytes": 0, "used_bytes": 0}
        used = await self.get_user_logical_used_bytes(user_id)
        bindings = await self.list_user_backends(user_id=user_id)
        active_writable = [
            b for b in bindings if b["is_active"] and b["backend_is_active"] and not b["backend_read_only"]
        ]
        user_quota = int(user.get("quota_bytes") or 0)
        eff_quota = user_quota
        if eff_quota <= 0 and active_writable:
            qs = [int(b["quota_bytes"] or b["backend_quota_bytes"] or 0) for b in active_writable]
            eff_quota = sum(qs) if all(q > 0 for q in qs) else 0
        return {
            "has_storage_pool": len(active_writable) > 0 or len(bindings) > 0,
            "effective_quota_bytes": eff_quota,
            "used_bytes": used,
        }
