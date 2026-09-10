"""Pytest bootstrap: put the project root on sys.path and offer a temp SQLite file."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    """Point pipeline.store at an empty temp database for isolation."""
    from pipeline import store

    db = tmp_path / "test.db"
    store.set_db_path(db)
    store.init_db()
    return db
