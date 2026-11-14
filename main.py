"""ASGI entrypoint for Baota Python Project Manager / Uvicorn / Gunicorn."""

from banoss.app import create_app

app = create_app()
