"""Historique des analyses (SQLite) : chaque URL analysée est enregistrée."""
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

import tldextract

_extract = tldextract.TLDExtract(suffix_list_urls=())


def _db_path() -> Path:
    return Path(os.getenv("PHISHGUARD_DB", "data/phishguard.db"))


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with closing(_connect()) as conn, conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT,
                prediction TEXT NOT NULL,
                probability REAL NOT NULL,
                model_version TEXT,
                features TEXT,
                status TEXT NOT NULL DEFAULT 'predicted',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain)")


def save_scan(url, probability, prediction, model_version, features) -> int:
    domain = _extract(url).top_domain_under_public_suffix
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with closing(_connect()) as conn, conn:
        cur = conn.execute(
            "INSERT INTO scans (url, domain, prediction, probability,"
            " model_version, features, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (url, domain, prediction, probability, model_version,
             json.dumps(features), now),
        )
        return cur.lastrowid


def history(limit: int = 50, suspicious_only: bool = False) -> list[dict]:
    query = "SELECT id, url, domain, prediction, probability, status, created_at FROM scans"
    if suspicious_only:
        query += " WHERE prediction = 'phishing'"
    query += " ORDER BY id DESC LIMIT ?"
    with closing(_connect()) as conn:
        return [dict(r) for r in conn.execute(query, (limit,)).fetchall()]
