import os
import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

SESSION_DIR = Path(os.getenv("ASTAROTH_SESSION_DIR", str(Path(__file__).parent.parent / "sessions")))
ACTIVE_FILE = SESSION_DIR / ".active"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ip            TEXT NOT NULL UNIQUE,
    hostname      TEXT,
    os            TEXT,
    notes         TEXT,
    discovered_at TEXT
);
CREATE TABLE IF NOT EXISTS services (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip   TEXT NOT NULL,
    port      INTEGER,
    protocol  TEXT DEFAULT 'tcp',
    service   TEXT,
    version   TEXT,
    banner    TEXT,
    UNIQUE(host_ip, port, protocol)
);
CREATE TABLE IF NOT EXISTS credentials (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT NOT NULL,
    secret       TEXT,
    secret_type  TEXT DEFAULT 'password',
    domain       TEXT,
    source       TEXT,
    validated    INTEGER DEFAULT 0,
    access_level TEXT,
    discovered_at TEXT,
    UNIQUE(username, secret, domain)
);
CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip       TEXT,
    type          TEXT,
    title         TEXT NOT NULL,
    description   TEXT,
    evidence      TEXT,
    severity      TEXT DEFAULT 'medium',
    status        TEXT DEFAULT 'unconfirmed',
    discovered_at TEXT
);
CREATE TABLE IF NOT EXISTS attack_paths (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    technique  TEXT NOT NULL,
    from_node  TEXT,
    to_node    TEXT,
    status     TEXT DEFAULT 'hypothesized',
    evidence   TEXT,
    notes      TEXT,
    updated_at TEXT,
    UNIQUE(technique, from_node, to_node)
);
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT,
    description TEXT,
    data        TEXT,
    timestamp   TEXT
);
"""

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Session:
    def __init__(self, name: str, db_path: Path):
        self.name = name
        self.db_path = db_path
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # --- meta ---

    def set_meta(self, key: str, value: str):
        self._conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))
        self._conn.commit()

    def get_meta(self, key: str, default: str = "") -> str:
        row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    # --- hosts ---

    def add_host(self, ip: str, hostname: str = "", os_str: str = "", notes: str = "") -> int:
        try:
            cur = self._conn.execute(
                "INSERT INTO hosts (ip, hostname, os, notes, discovered_at) VALUES (?, ?, ?, ?, ?)",
                (ip, hostname or None, os_str or None, notes or None, _now()),
            )
            self._conn.commit()
            return cur.lastrowid
        except sqlite3.IntegrityError:
            if hostname:
                self._conn.execute("UPDATE hosts SET hostname=? WHERE ip=? AND (hostname IS NULL OR hostname='')", (hostname, ip))
            if os_str:
                self._conn.execute("UPDATE hosts SET os=? WHERE ip=? AND (os IS NULL OR os='')", (os_str, ip))
            self._conn.commit()
            return self._conn.execute("SELECT id FROM hosts WHERE ip=?", (ip,)).fetchone()["id"]

    def add_service(self, host_ip: str, port: int, protocol: str = "tcp",
                    service: str = "", version: str = "", banner: str = "") -> int:
        try:
            cur = self._conn.execute(
                "INSERT INTO services (host_ip, port, protocol, service, version, banner) VALUES (?, ?, ?, ?, ?, ?)",
                (host_ip, port, protocol, service or None, version or None, banner or None),
            )
            self._conn.commit()
            return cur.lastrowid
        except sqlite3.IntegrityError:
            return self._conn.execute(
                "SELECT id FROM services WHERE host_ip=? AND port=? AND protocol=?",
                (host_ip, port, protocol),
            ).fetchone()["id"]

    # --- credentials ---

    def add_credential(self, username: str, secret: str, secret_type: str = "password",
                       domain: str = "", source: str = "") -> int:
        try:
            cur = self._conn.execute(
                "INSERT INTO credentials (username, secret, secret_type, domain, source, discovered_at) VALUES (?, ?, ?, ?, ?, ?)",
                (username, secret, secret_type, domain or None, source or None, _now()),
            )
            self._conn.commit()
            return cur.lastrowid
        except sqlite3.IntegrityError:
            return self._conn.execute(
                "SELECT id FROM credentials WHERE username=? AND secret=? AND COALESCE(domain,'')=COALESCE(?,'') ",
                (username, secret, domain),
            ).fetchone()["id"]

    def mark_credential_validated(self, cred_id: int, access_level: str = ""):
        self._conn.execute(
            "UPDATE credentials SET validated=1, access_level=? WHERE id=?",
            (access_level or None, cred_id),
        )
        self._conn.commit()

    # --- findings ---

    def add_finding(self, title: str, description: str = "", evidence: str = "",
                    host_ip: str = "", finding_type: str = "", severity: str = "medium") -> int:
        cur = self._conn.execute(
            "INSERT INTO findings (host_ip, type, title, description, evidence, severity, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (host_ip or None, finding_type or None, title, description or None, evidence or None, severity, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    # --- attack paths ---

    def upsert_path(self, technique: str, from_node: str = "", to_node: str = "",
                    status: str = "hypothesized", evidence: str = "", notes: str = ""):
        try:
            self._conn.execute(
                "INSERT INTO attack_paths (technique, from_node, to_node, status, evidence, notes, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (technique, from_node or None, to_node or None, status, evidence or None, notes or None, _now()),
            )
        except sqlite3.IntegrityError:
            self._conn.execute(
                "UPDATE attack_paths SET status=?, updated_at=? WHERE technique=? AND COALESCE(from_node,'')=COALESCE(?,'') AND COALESCE(to_node,'')=COALESCE(?,'') ",
                (status, _now(), technique, from_node, to_node),
            )
        self._conn.commit()

    # --- events ---

    def log(self, event_type: str, description: str, data: dict = None):
        self._conn.execute(
            "INSERT INTO events (type, description, data, timestamp) VALUES (?, ?, ?, ?)",
            (event_type, description, json.dumps(data or {}), _now()),
        )
        self._conn.commit()

    # --- queries ---

    def get_hosts(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM hosts ORDER BY ip").fetchall()
        result = []
        for row in rows:
            h = dict(row)
            h["services"] = [
                dict(s) for s in self._conn.execute(
                    "SELECT port, protocol, service, version FROM services WHERE host_ip=? ORDER BY port",
                    (h["ip"],),
                ).fetchall()
            ]
            result.append(h)
        return result

    def get_credentials(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM credentials ORDER BY domain, username"
        ).fetchall()]

    def get_findings(self, severity: str = "") -> list[dict]:
        if severity:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE severity=? ORDER BY title", (severity,)
            ).fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM findings").fetchall()
        findings = [dict(r) for r in rows]
        findings.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "medium"), 2))
        return findings

    def get_paths(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM attack_paths ORDER BY status, technique"
        ).fetchall()]

    def summary(self) -> dict:
        hosts = self.get_hosts()
        creds = self.get_credentials()
        findings = self.get_findings()
        paths = self.get_paths()
        services_flat = [s for h in hosts for s in h.get("services", [])]
        return {
            "name": self.name,
            "scope": self.get_meta("scope"),
            "created": self.get_meta("created"),
            "hosts": hosts,
            "services_count": len(services_flat),
            "credentials": creds,
            "findings": findings,
            "paths": paths,
        }

    def close(self):
        self._conn.close()


# --- session lifecycle ---

def create(name: str, scope: str = "") -> "Session":
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    db_path = SESSION_DIR / f"{name}.db"
    s = Session(name, db_path)
    s.set_meta("name", name)
    s.set_meta("scope", scope)
    s.set_meta("created", _now())
    s.log("engagement_started", f"Engagement '{name}' created", {"scope": scope})
    _write_active(name)
    return s


def load(name: str) -> Optional["Session"]:
    db_path = SESSION_DIR / f"{name}.db"
    if not db_path.exists():
        return None
    s = Session(name, db_path)
    _write_active(name)
    return s


def load_active() -> Optional["Session"]:
    if not ACTIVE_FILE.exists():
        return None
    name = ACTIVE_FILE.read_text().strip()
    if not name:
        return None
    return load(name)


def list_sessions() -> list[str]:
    if not SESSION_DIR.exists():
        return []
    return sorted(p.stem for p in SESSION_DIR.glob("*.db"))


def _write_active(name: str):
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    ACTIVE_FILE.write_text(name)
