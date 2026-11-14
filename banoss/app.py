"""FastAPI application factory wiring Admin Console, S3 Router, SQLite DB, and SFTP Storage Pool."""

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI

from banoss.admin_router import create_admin_router
from banoss.config import Settings
from banoss.console_router import create_console_router
from banoss.crypto import CryptoService
from banoss.db import Database
from banoss.s3_router import create_s3_router
from banoss.storage import StorageManager


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    cfg = settings or Settings()
    db_path = cfg.resolve_db_path()
    master_key = cfg.resolve_master_key_bytes()
    admin_token = cfg.resolve_admin_token()

    crypto = CryptoService(master_key)
    db = Database(db_path)
    storage = StorageManager(db, crypto, default_chunk_size=cfg.chunk_size)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        await db.connect()
        await storage.start()
        try:
            yield
        finally:
            await storage.stop()
            await db.close()

    app = FastAPI(title="BanOSS", version="0.1.0", lifespan=lifespan)
    app.state.settings = cfg
    app.state.db = db
    app.state.crypto = crypto
    app.state.storage = storage
    app.state.admin_token = admin_token

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # Mount Admin & Console routes BEFORE the catch-all S3 router
    session_key = hashlib.sha256(b"banoss-session:" + master_key).digest()
    app.include_router(create_admin_router(cfg, admin_token, db, crypto, storage))
    app.include_router(create_console_router(cfg, session_key, db, crypto, storage))
    app.include_router(create_s3_router(cfg, db, crypto, storage))
    return app
