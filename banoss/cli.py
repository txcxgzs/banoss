"""CLI entrypoint for launching BanOSS and managing encrypted disaster-recovery vaults."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

import uvicorn

from banoss.app import create_app
from banoss.backup import create_vault_bytes, restore_vault_bytes
from banoss.config import Settings


def _cmd_serve(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description="BanOSS S3-to-SFTP Gateway")
    parser.add_argument("--host", default=None, help="Bind host (default from BANOSS_HOST or 0.0.0.0)")
    parser.add_argument("--port", type=int, default=None, help="Bind port (default from BANOSS_PORT or 9000)")
    parser.add_argument("--data-dir", default=None, help="Data directory for SQLite and keys")
    args = parser.parse_args(argv)

    overrides = {}
    if args.host is not None:
        overrides["host"] = args.host
    if args.port is not None:
        overrides["port"] = args.port
    if args.data_dir is not None:
        overrides["data_dir"] = args.data_dir

    settings = Settings(**overrides)
    app = create_app(settings)
    display_host = "127.0.0.1" if settings.host == "0.0.0.0" else settings.host
    print(f"BanOSS S3 Endpoint  : http://{display_host}:{settings.port}")
    print(f"BanOSS User Console : http://{display_host}:{settings.port}/console")
    print(f"BanOSS Admin Panel  : http://{display_host}:{settings.port}/admin")
    print(f"BanOSS Admin Token  : {app.state.admin_token}")
    print(f"SQLite Database     : {settings.resolve_db_path()}")

    uvicorn.run(app, host=settings.host, port=settings.port, log_level="info")


def _cmd_backup(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(prog="banoss backup", description="Export encrypted disaster-recovery vault")
    parser.add_argument("--data-dir", default="./data", help="Source BanOSS data directory")
    parser.add_argument("--out", required=True, help="Output .vault file path")
    parser.add_argument("--passphrase", default=None, help="Encryption passphrase (min 8 chars)")
    args = parser.parse_args(argv)

    pw = args.passphrase or getpass.getpass("Enter vault passphrase (min 8 chars): ")
    settings = Settings(data_dir=Path(args.data_dir))
    vault = create_vault_bytes(settings.data_dir, settings.resolve_db_path(), pw)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(vault)
    print(f"Vault exported to {out} ({len(vault)} bytes)")


def _cmd_restore(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(prog="banoss restore", description="Restore BanOSS data directory from vault")
    parser.add_argument("--vault", required=True, help="Path to .vault file")
    parser.add_argument("--data-dir", default="./data", help="Target BanOSS data directory")
    parser.add_argument("--passphrase", default=None, help="Vault decryption passphrase")
    args = parser.parse_args(argv)

    pw = args.passphrase or getpass.getpass("Enter vault passphrase: ")
    vault_bytes = Path(args.vault).read_bytes()
    restored = restore_vault_bytes(vault_bytes, pw, Path(args.data_dir))
    print("Restored files:")
    for item in restored:
        print(f"  - {item}")


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] == "backup":
        _cmd_backup(argv[1:])
    elif argv and argv[0] == "restore":
        _cmd_restore(argv[1:])
    elif argv and argv[0] == "serve":
        _cmd_serve(argv[1:])
    else:
        _cmd_serve(argv)


if __name__ == "__main__":
    main()
