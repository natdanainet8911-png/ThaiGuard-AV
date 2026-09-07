"""ชั้นจัดการฐานข้อมูล SQLite — thread-safe ด้วย RLock"""
import sqlite3
import threading
import json
from datetime import datetime
from config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS signatures (
    sha256      TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    severity    INTEGER DEFAULT 100,
    source      TEXT DEFAULT 'builtin',
    added_at    TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT,
    scan_type   TEXT,
    started_at  TEXT,
    finished_at TEXT,
    total_files INTEGER DEFAULT 0,
    threats     INTEGER DEFAULT 0,
    suspicious  INTEGER DEFAULT 0,
    errors      INTEGER DEFAULT 0,
    duration    REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS detections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER,
    filepath    TEXT,
    filename    TEXT,
    sha256      TEXT,
    size        INTEGER,
    verdict     TEXT,
    risk_score  REAL,
    detection   TEXT,
    reasons     TEXT,
    action      TEXT DEFAULT 'none',
    detected_at TEXT
);

CREATE TABLE IF NOT EXISTS quarantine (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path  TEXT,
    stored_name    TEXT,
    sha256         TEXT,
    detection      TEXT,
    risk_score     REAL,
    size           INTEGER,
    quarantined_at TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_det_scan ON detections(scan_id);
"""

# ------- Signature เริ่มต้น: ไฟล์ทดสอบมาตรฐาน EICAR (ไม่อันตราย) -------
SEED_SIGNATURES = [
    ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
     "EICAR-Test-File (not-a-virus)", 100),
    ("131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
     "EICAR-Test-File-Variant", 100),
]


class Database:
    def __init__(self, path=DB_PATH):
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()
        self._seed()

    # ---------------------------------------------------------- utils
    def _now(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _seed(self):
        with self._lock:
            for sha, name, sev in SEED_SIGNATURES:
                self.conn.execute(
                    "INSERT OR IGNORE INTO signatures VALUES (?,?,?,?,?)",
                    (sha, name, sev, "builtin", self._now()))
            self.conn.commit()

    def close(self):
        with self._lock:
            self.conn.close()

    # ----------------------------------------------------- signatures
    def lookup_signature(self, sha256: str):
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM signatures WHERE sha256=?", (sha256,)).fetchone()
        return dict(row) if row else None

    def add_signature(self, sha256, name, severity=100, source="user"):
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO signatures VALUES (?,?,?,?,?)",
                (sha256.lower().strip(), name, severity, source, self._now()))
            self.conn.commit()

    def delete_signature(self, sha256):
        with self._lock:
            self.conn.execute("DELETE FROM signatures WHERE sha256=?", (sha256,))
            self.conn.commit()

    def list_signatures(self, keyword=""):
        q = "SELECT * FROM signatures"
        p = ()
        if keyword:
            q += " WHERE name LIKE ? OR sha256 LIKE ?"
            p = (f"%{keyword}%", f"%{keyword}%")
        q += " ORDER BY added_at DESC"
        with self._lock:
            return [dict(r) for r in self.conn.execute(q, p).fetchall()]

    def signature_count(self) -> int:
        with self._lock:
            return self.conn.execute(
                "SELECT COUNT(*) c FROM signatures").fetchone()["c"]

    # ---------------------------------------------------------- scans
    def start_scan(self, target, scan_type) -> int:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO scans (target, scan_type, started_at) VALUES (?,?,?)",
                (target, scan_type, self._now()))
            self.conn.commit()
            return cur.lastrowid

    def finish_scan(self, scan_id, summary: dict):
        with self._lock:
            self.conn.execute("""
                UPDATE scans SET finished_at=?, total_files=?, threats=?,
                       suspicious=?, errors=?, duration=? WHERE id=?""",
                (self._now(), summary.get("total", 0), summary.get("threats", 0),
                 summary.get("suspicious", 0), summary.get("errors", 0),
                 summary.get("duration", 0), scan_id))
            self.conn.commit()

    def list_scans(self, limit=200):
        with self._lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))]

    def clear_history(self):
        with self._lock:
            self.conn.execute("DELETE FROM detections")
            self.conn.execute("DELETE FROM scans")
            self.conn.commit()

    # ----------------------------------------------------- detections
    def add_detection(self, scan_id, r: dict):
        with self._lock:
            self.conn.execute("""
                INSERT INTO detections (scan_id, filepath, filename, sha256, size,
                    verdict, risk_score, detection, reasons, detected_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (scan_id, r["path"], r["name"], r.get("sha256", ""),
                 r.get("size", 0), r["verdict"], r["risk_score"],
                 r.get("detection", ""), json.dumps(r.get("reasons", []),
                 ensure_ascii=False), self._now()))
            self.conn.commit()

    def list_detections(self, scan_id):
        with self._lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT * FROM detections WHERE scan_id=? ORDER BY risk_score DESC",
                (scan_id,))]

    # ----------------------------------------------------- quarantine
    def add_quarantine(self, rec: dict) -> int:
        with self._lock:
            cur = self.conn.execute("""
                INSERT INTO quarantine (original_path, stored_name, sha256,
                    detection, risk_score, size, quarantined_at)
                VALUES (?,?,?,?,?,?,?)""",
                (rec["original_path"], rec["stored_name"], rec["sha256"],
                 rec["detection"], rec["risk_score"], rec["size"], self._now()))
            self.conn.commit()
            return cur.lastrowid

    def list_quarantine(self):
        with self._lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT * FROM quarantine ORDER BY id DESC")]

    def get_quarantine(self, qid):
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM quarantine WHERE id=?", (qid,)).fetchone()
        return dict(row) if row else None

    def delete_quarantine(self, qid):
        with self._lock:
            self.conn.execute("DELETE FROM quarantine WHERE id=?", (qid,))
            self.conn.commit()

    # ------------------------------------------------------- settings
    def get_setting(self, key, default=None):
        with self._lock:
            row = self.conn.execute(
                "SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except Exception:
            return row["value"]

    def set_setting(self, key, value):
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO settings VALUES (?,?)",
                (key, json.dumps(value, ensure_ascii=False)))
            self.conn.commit()
