import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Optional
from contextlib import contextmanager

DB_PATH = Path("bluesentinel.db")

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            module TEXT,
            action TEXT,
            source_ip TEXT,
            source_port INTEGER,
            user_name TEXT,
            http_status INTEGER,
            path TEXT,
            raw TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            rule_id TEXT,
            title TEXT,
            severity TEXT,
            description TEXT,
            context TEXT
        )""")
        conn.commit()

def insert_event(ev: Dict[str, Any]) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute(
            """INSERT INTO events(ts, module, action, source_ip, source_port, user_name, http_status, path, raw)
                 VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                ev.get("@timestamp"),
                ev["event"].get("module"),
                ev["event"].get("action"),
                ev["source"].get("ip"),
                ev["source"].get("port"),
                ev["user"].get("name"),
                ev["http"].get("status_code"),
                ev["http"].get("path"),
                ev["log"].get("original"),
            ),
        )
        conn.commit()
        return c.lastrowid

def select_events(limit: int = 100) -> List[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        rows = c.execute("SELECT id, ts, module, action, source_ip, source_port, user_name, http_status, path, raw FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        cols = ["id","ts","module","action","source_ip","source_port","user_name","http_status","path","raw"]
        return [dict(zip(cols, r)) for r in rows]

def insert_alert(alert: Dict[str, Any]) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute(
            """INSERT INTO alerts(ts, rule_id, title, severity, description, context)
                 VALUES(?,?,?,?,?,?)""",
            (
                alert.get("ts"),
                alert.get("rule_id"),
                alert.get("title"),
                alert.get("severity"),
                alert.get("description"),
                alert.get("context"),
            ),
        )
        conn.commit()
        return c.lastrowid

def select_alerts(limit: int = 100) -> List[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        rows = c.execute("SELECT id, ts, rule_id, title, severity, description, context FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        cols = ["id", "ts", "rule_id", "title", "severity", "description", "context"]
        return [dict(zip(cols, r)) for r in rows]
