"""Persistence layer.

PromptShield AI stores *documents* (JSON records) inside logical
*collections*: `users`, `scans`, `threats`, `batches`, `audit`, `approvals`,
`settings`, `test_runs`.

Two interchangeable backends implement the same tiny interface:

* ``MongoStore``  – used when ``MONGODB_URI`` is configured (production).
* ``SqliteStore`` – embedded fallback so the prototype runs with no
  external service. One table keeps the JSON payload plus indexed
  collection/created_at columns.

Collection documents use an application generated string ``id``; Mongo maps it
to ``_id`` and the SQLite backend keeps it as a primary-key column, so callers
never care which backend is active.
"""
from __future__ import annotations

import datetime as _dt
import json
import sqlite3
import threading
import uuid
from typing import Any, Callable, Iterable, Optional

from .config import DATA_DIR, MONGODB_DB, MONGODB_URI


def utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str = "") -> str:
    raw = uuid.uuid4().hex[:24]
    return f"{prefix}_{raw}" if prefix else raw


class Store:
    """Common document-store contract."""

    backend = "abstract"

    def insert(self, collection: str, doc: dict) -> dict:  # pragma: no cover
        raise NotImplementedError

    def get(self, collection: str, doc_id: str) -> Optional[dict]:  # pragma: no cover
        raise NotImplementedError

    def find(
        self,
        collection: str,
        predicate: Optional[Callable[[dict], bool]] = None,
        limit: int = 200,
        newest_first: bool = True,
    ) -> list[dict]:  # pragma: no cover
        raise NotImplementedError

    def update(self, collection: str, doc_id: str, patch: dict) -> Optional[dict]:  # pragma: no cover
        raise NotImplementedError

    def count(self, collection: str, predicate: Optional[Callable[[dict], bool]] = None) -> int:
        return len(self.find(collection, predicate, limit=100000))

    def health(self) -> dict:
        return {"backend": self.backend, "ok": True}


class SqliteStore(Store):
    backend = "sqlite"

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS documents (
                collection TEXT NOT NULL,
                id         TEXT NOT NULL,
                created_at TEXT NOT NULL,
                payload    TEXT NOT NULL,
                PRIMARY KEY (collection, id)
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_documents_collection_created "
            "ON documents (collection, created_at DESC)"
        )
        self._conn.commit()

    def insert(self, collection: str, doc: dict) -> dict:
        record = dict(doc)
        record.setdefault("id", new_id(collection[:3]))
        record.setdefault("created_at", utcnow())
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO documents (collection, id, created_at, payload) VALUES (?,?,?,?)",
                (collection, record["id"], record["created_at"], json.dumps(record, default=str)),
            )
            self._conn.commit()
        return record

    def get(self, collection: str, doc_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM documents WHERE collection=? AND id=?", (collection, doc_id)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def find(self, collection, predicate=None, limit=200, newest_first=True) -> list[dict]:
        order = "DESC" if newest_first else "ASC"
        with self._lock:
            rows = self._conn.execute(
                f"SELECT payload FROM documents WHERE collection=? ORDER BY created_at {order}",
                (collection,),
            ).fetchall()
        docs = [json.loads(r[0]) for r in rows]
        if predicate is not None:
            docs = [d for d in docs if predicate(d)]
        return docs[:limit]

    def update(self, collection: str, doc_id: str, patch: dict) -> Optional[dict]:
        with self._lock:
            current = self.get(collection, doc_id)
            if current is None:
                return None
            current.update(patch)
            self._conn.execute(
                "UPDATE documents SET payload=? WHERE collection=? AND id=?",
                (json.dumps(current, default=str), collection, doc_id),
            )
            self._conn.commit()
        return current

    def health(self) -> dict:
        return {"backend": "sqlite", "ok": True, "path": self.path}


class MongoStore(Store):
    backend = "mongodb"

    def __init__(self, uri: str, db_name: str):
        from pymongo import MongoClient  # imported lazily: optional dependency

        self._client = MongoClient(uri, serverSelectionTimeoutMS=4000)
        self._db = self._client[db_name]
        self._client.admin.command("ping")
        for name in ("scans", "threats", "batches", "audit", "approvals", "users", "settings", "test_runs"):
            self._db[name].create_index("created_at")

    def _col(self, collection: str):
        return self._db[collection]

    def insert(self, collection: str, doc: dict) -> dict:
        record = dict(doc)
        record.setdefault("id", new_id(collection[:3]))
        record.setdefault("created_at", utcnow())
        payload = dict(record)
        payload["_id"] = payload["id"]
        self._col(collection).insert_one(payload)
        return record

    def get(self, collection: str, doc_id: str) -> Optional[dict]:
        doc = self._col(collection).find_one({"_id": doc_id}, {"_id": 0})
        return doc

    def find(self, collection, predicate=None, limit=200, newest_first=True) -> list[dict]:
        sort = [("created_at", -1 if newest_first else 1)]
        docs = list(self._col(collection).find({}, {"_id": 0}).sort(sort).limit(limit))
        if predicate is not None:
            docs = [d for d in docs if predicate(d)]
        return docs

    def update(self, collection: str, doc_id: str, patch: dict) -> Optional[dict]:
        result = self._col(collection).find_one_and_update(
            {"_id": doc_id}, {"$set": patch}, projection={"_id": 0}, return_document=True
        )
        return result

    def health(self) -> dict:
        try:
            self._client.admin.command("ping")
            return {"backend": "mongodb", "ok": True, "database": MONGODB_DB}
        except Exception as exc:  # pragma: no cover - depends on external service
            return {"backend": "mongodb", "ok": False, "error": str(exc)}


_store: Optional[Store] = None
_store_lock = threading.Lock()


def get_store() -> Store:
    """Return the process-wide store, choosing the backend once."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                if MONGODB_URI:
                    try:
                        _store = MongoStore(MONGODB_URI, MONGODB_DB)
                    except Exception as exc:  # pragma: no cover - external dependency
                        print(f"[promptshield] MongoDB unavailable ({exc}); falling back to SQLite")
                        _store = SqliteStore(str(DATA_DIR / "promptshield.db"))
                else:
                    _store = SqliteStore(str(DATA_DIR / "promptshield.db"))
    return _store


def set_store(store: Store) -> None:
    """Test hook: inject an alternative store."""
    global _store
    _store = store


def audit(actor: dict | str, action: str, detail: str = "", meta: Optional[dict] = None) -> dict:
    """Append a security audit event (who did what, when, from where)."""
    if isinstance(actor, dict):
        actor_label = f"{actor.get('email', 'unknown')}:{actor.get('role', 'unknown')}"
    else:
        actor_label = str(actor)
    return get_store().insert(
        "audit",
        {
            "actor": actor_label,
            "action": action,
            "detail": detail,
            "meta": meta or {},
        },
    )


def ensure_collections() -> Iterable[str]:
    return ("users", "scans", "threats", "batches", "audit", "approvals", "settings", "test_runs")
