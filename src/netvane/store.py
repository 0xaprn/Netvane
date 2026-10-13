"""Dedup backends. SQLite uses a temporary file and bounded index memory."""
from __future__ import annotations
import os
import sqlite3
import tempfile


class Deduper:
    def __init__(self, mode: str = 'memory'):
        self.mode = mode
        self._seen: set[tuple[str, str]] = set()
        self._conn = None
        self._path = None
        if mode == 'sqlite':
            fd, self._path = tempfile.mkstemp(prefix='netvane-', suffix='.db')
            os.close(fd)
            self._conn = sqlite3.connect(self._path)
            self._conn.execute('CREATE TABLE entries (kind TEXT, value TEXT, PRIMARY KEY(kind,value)) WITHOUT ROWID')

    def add(self, kind: str, value: str) -> bool:
        if self._conn is None:
            key = (kind, value)
            if key in self._seen:
                return False
            self._seen.add(key)
            return True
        cur = self._conn.execute('INSERT OR IGNORE INTO entries VALUES (?, ?)', (kind, value))
        return cur.rowcount == 1

    def close(self):
        if self._conn is not None:
            self._conn.close()
        if self._path:
            try:
                os.unlink(self._path)
            except FileNotFoundError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
