#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Automated Log Analyzer & Alerting
---------------------------------
- Local or remote (SSH/SFTP) log tailing
- Regex-based incident detection (failed logins, crashes, suspicious activity)
- Results stored in SQLite and CSV
- Alerts via email and/or Slack when thresholds are crossed
- Continuous scanning with schedule (near real-time demo friendly)

Dependencies:
  pip install paramiko schedule

Run:
  python log_analyzer.py
"""

import csv
import json
import os
import re
import smtplib
import socket
import sqlite3
import ssl
import sys
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import paramiko  # type: ignore
import schedule  # type: ignore


# ============
# CONFIG BLOCK
# ============

CONFIG = {
    # MODE: "local" or "remote" or "mixed"
    "MODE": "local",

    # Local log files or directories (recursive). Examples:
    # - "/var/log/auth.log"
    # - "/var/log" (directory — will watch *.log and *.out)
    "LOCAL_PATHS": [
    	"./test.log",
        "/var/log/auth.log",
        "/var/log/syslog",
        # add more paths here; dirs are allowed
    ],

    # Remote hosts (used when MODE in {"remote","mixed"})
    # Each host can specify explicit file paths to scan on that host.
    "REMOTE_HOSTS": [
        # {
        #     "host": "example.com",
        #     "port": 22,
        #     "username": "ubuntu",
        #     "password": None,        # or use key_filename
        #     "key_filename": "/home/me/.ssh/id_rsa",
        #     "paths": ["/var/log/auth.log", "/var/log/syslog"],
        # },
    ],

    # File name patterns to include when a directory is provided
    "FILENAME_GLOBS": ["*.log", "*.out", "*.txt"],

    # Scan interval (seconds) for schedule
    "SCAN_EVERY_SECONDS": 10,

    # Where to store outputs
    "DATA_DIR": "./data",
    "SQLITE_PATH": "./data/events.db",
    "CSV_PATH": "./data/events.csv",

    # Alerting channels (enable/disable + settings)
    "ALERTS": {
        "EMAIL": {
            "ENABLED": True,
            "SMTP_HOST": "smtp.gmail.com",
            "SMTP_PORT": 587,
            "FROM": "example@gmail.com",
            "TO": ["example@yahoo.com"],
            "USERNAME": "example@gmail.com",
            "PASSWORD": "finl khmb hlyt mxte",
            "USE_TLS": True,
        },
        "SLACK": {
            "ENABLED": False,
            # Create an "Incoming Webhook" in Slack and paste it here
            "WEBHOOK_URL": "https://hooks.slack.com/services/XXX/YYY/ZZZ",
        },
    },

    # Alert thresholds (counts seen in a single scan cycle)
    "THRESHOLDS": {
        "FAILED_LOGIN": 5,
        "CRASH": 1,
        "SUSPICIOUS": 3,
    },

    # Regex patterns to detect incidents
    # Tune/extend as needed for your environment/log formats.
    "PATTERNS": {
        "FAILED_LOGIN": [
            r"Failed password for (invalid user )?\w+ from (?P<ip>\d+\.\d+\.\d+\.\d+)",   # sshd
            r"Invalid user \w+ from (?P<ip>\d+\.\d+\.\d+\.\d+)",                            # sshd invalid user
            r"authentication failure;.*rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)",                   # pam
        ],
        "CRASH": [
            r"\bsegfault\b|\bsegmentation fault\b",
            r"\bkernel panic\b",
            r"Traceback \(most recent call last\):",  # Python tracebacks
            r"\bCRITICAL\b.*\berror\b",
            r"service .* (crashed|exited with code \d+)",
        ],
        "SUSPICIOUS": [
            r"DROP .* IN=(?P<iface>\w+) .* SRC=(?P<ip>\d+\.\d+\.\d+\.\d+)",                 # iptables-style
            r"(\b('|\")?\s*or\s+1=1\b)|(\bunion\b.*\bselect\b)",                            # basic SQLi
            r"(\.\./){2,}",                                                                  # directory traversal attempts
            r"\b403\b|\b401\b|\b404\b .* from (?P<ip>\d+\.\d+\.\d+\.\d+)",                  # repeated errors (approx)
        ],
    },
}


# ===================
# INITIAL PREPARATION
# ===================

Path(CONFIG["DATA_DIR"]).mkdir(parents=True, exist_ok=True)

# Compile regexes once
COMPILED_PATTERNS: Dict[str, List[re.Pattern]] = {
    cat: [re.compile(p, re.IGNORECASE) for p in pats]
    for cat, pats in CONFIG["PATTERNS"].items()
}


# ==============
# DB DEFINITIONS
# ==============

DDL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY,
    host TEXT NOT NULL,             -- "localhost" or remote host
    path TEXT NOT NULL,
    UNIQUE(host, path)
);

CREATE TABLE IF NOT EXISTS checkpoints (
    file_id INTEGER PRIMARY KEY,
    offset INTEGER NOT NULL DEFAULT 0,
    mtime REAL NOT NULL DEFAULT 0,
    FOREIGN KEY(file_id) REFERENCES files(id)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts_utc TEXT NOT NULL,
    host TEXT NOT NULL,
    filepath TEXT NOT NULL,
    category TEXT NOT NULL,
    pattern TEXT NOT NULL,
    line TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_utc);
CREATE INDEX IF NOT EXISTS idx_events_cat ON events(category);
"""


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(CONFIG["SQLITE_PATH"])
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db():
    with db() as conn:
        conn.executescript(DDL)


def upsert_file_id(conn: sqlite3.Connection, host: str, path: str) -> int:
    cur = conn.execute(
        "INSERT OR IGNORE INTO files(host, path) VALUES(?, ?)", (host, path)
    )
    # Now fetch id
    cur = conn.execute("SELECT id FROM files WHERE host=? AND path=?", (host, path))
    row = cur.fetchone()
    return int(row[0])


def get_checkpoint(conn: sqlite3.Connection, file_id: int) -> Tuple[int, float]:
    cur = conn.execute("SELECT offset, mtime FROM checkpoints WHERE file_id=?", (file_id,))
    row = cur.fetchone()
    if not row:
        conn.execute("INSERT INTO checkpoints(file_id, offset, mtime) VALUES (?, 0, 0)", (file_id,))
        return 0, 0.0
    return int(row[0]), float(row[1])


def update_checkpoint(conn: sqlite3.Connection, file_id: int, offset: int, mtime: float):
    conn.execute(
        "INSERT INTO checkpoints(file_id, offset, mtime) VALUES (?, ?, ?) "
        "ON CONFLICT(file_id) DO UPDATE SET offset=excluded.offset, mtime=excluded.mtime",
        (file_id, offset, mtime),
    )


# =============
# CSV WRITER
# =============

def append_csv(rows: List[Tuple[str, str, str, str, str, str]], csv_path: str):
    header = ["ts_utc", "host", "filepath", "category", "pattern", "line"]
    file_exists = os.path.exists(csv_path)
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(header)
        writer.writerows(rows)


# =======================
# ALERTING (EMAIL/SLACK)
# =======================

def send_email(subject: str, body: str):
    email_cfg = CONFIG["ALERTS"]["EMAIL"]
    if not email_cfg["ENABLED"]:
        return

    msg = EmailMessage()
    msg["From"] = email_cfg["FROM"]
    msg["To"] = ", ".join(email_cfg["TO"])
    msg["Subject"] = subject
    msg.set_content(body)

    if email_cfg.get("USE_TLS", True):
        context = ssl.create_default_context()
        with smtplib.SMTP(email_cfg["SMTP_HOST"], email_cfg["SMTP_PORT"]) as server:
            server.starttls(context=context)
            server.login(email_cfg["USERNAME"], email_cfg["PASSWORD"])
            server.send_message(msg)
    else:
        with smtplib.SMTP(email_cfg["SMTP_HOST"], email_cfg["SMTP_PORT"]) as server:
            server.login(email_cfg["USERNAME"], email_cfg["PASSWORD"])
            server.send_message(msg)


def send_slack(text: str):
    slack_cfg = CONFIG["ALERTS"]["SLACK"]
    if not slack_cfg["ENABLED"]:
        return

    import urllib.request
    import urllib.error

    payload = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        slack_cfg["WEBHOOK_URL"],
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except urllib.error.URLError as e:
        print(f"[WARN] Slack webhook failed: {e}")


def alert_if_needed(counts: Dict[str, int], sample_events: Dict[str, List[Tuple[str, str]]]):
    # counts: category -> count this cycle
    # sample_events: category -> [(host, filepath), ...] for context
    lines = []
    trigger = False
    for category, count in counts.items():
        threshold = CONFIG["THRESHOLDS"].get(category, 999999)
        if count >= threshold:
            trigger = True
            examples = ", ".join(f"{h}:{p}" for (h, p) in sample_events.get(category, [])[:5])
            lines.append(f"- {category}: {count} (>= {threshold})  e.g., {examples}")

    if not trigger:
        return

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
    subject = f"[Log Analyzer] Threshold exceeded at {now}"
    body = subject + "\n\n" + "\n".join(lines)

    print(f"[ALERT]\n{body}")
    send_email(subject, body)
    send_slack(body)


# ============
# SCANNING
# ============

def expand_local_paths(paths: List[str], globs: List[str]) -> List[str]:
    final = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for name in files:
                    if any(Path(name).match(g) for g in globs):
                        final.append(os.path.join(root, name))
        else:
            final.append(p)
    # drop non-existent (quietly)
    return [fp for fp in final if os.path.exists(fp)]


def scan_local_file(conn: sqlite3.Connection, filepath: str) -> Tuple[int, List[Tuple[str, str, str, str, str, str]], Dict[str, int], Dict[str, List[Tuple[str, str]]]]:
    """
    Returns:
      events_count,
      csv_rows,
      category_counts,
      sample_events_for_alerting
    """
    host = "localhost"
    file_id = upsert_file_id(conn, host, filepath)
    old_offset, old_mtime = get_checkpoint(conn, file_id)

    try:
        st = os.stat(filepath)
        mtime = st.st_mtime
        size = st.st_size
    except FileNotFoundError:
        return 0, [], {}, {}

    # Handle truncation/rotation
    start_offset = old_offset if (mtime >= old_mtime and old_offset <= size) else 0

    events = []
    counts = {"FAILED_LOGIN": 0, "CRASH": 0, "SUSPICIOUS": 0}
    samples = {k: [] for k in counts.keys()}

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(start_offset)
        for line in f:
            matched = False
            for category, patterns in COMPILED_PATTERNS.items():
                for pat in patterns:
                    if pat.search(line):
                        matched = True
                        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
                        events.append((ts, host, filepath, category, pat.pattern, line.strip()))
                        counts[category] += 1
                        if len(samples[category]) < 5:
                            samples[category].append((host, filepath))
                        break
                if matched:
                    break
        end_offset = f.tell()

    if events:
        conn.executemany(
            "INSERT INTO events(ts_utc, host, filepath, category, pattern, line) VALUES (?, ?, ?, ?, ?, ?)",
            events,
        )
        append_csv(events, CONFIG["CSV_PATH"])

    update_checkpoint(conn, file_id, end_offset, mtime)
    return len(events), events, counts, samples


# ---------------
# REMOTE SCANNING
# ---------------

class SSHClientCache:
    def __init__(self):
        self._clients: Dict[str, paramiko.SSHClient] = {}

    def get_sftp(self, cfg: dict) -> Tuple[str, paramiko.SFTPClient]:
        """
        Returns (host_label, sftp_client).
        host_label is what we use in DB & alerts (host:port).
        """
        host = cfg["host"]
        port = int(cfg.get("port", 22))
        key = f"{host}:{port}:{cfg.get('username')}"
        if key not in self._clients:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=host,
                port=port,
                username=cfg.get("username"),
                password=cfg.get("password"),
                key_filename=cfg.get("key_filename"),
                timeout=10,
                allow_agent=True,
                look_for_keys=True,
            )
            self._clients[key] = client
        return f"{host}:{port}", self._clients[key].open_sftp()

    def close_all(self):
        for client in self._clients.values():
            try:
                client.close()
            except Exception:
                pass
        self._clients.clear()


SSH_CACHE = SSHClientCache()


def scan_remote_file(conn: sqlite3.Connection, host_label: str, sftp: paramiko.SFTPClient, remote_path: str) -> Tuple[int, List[Tuple[str, str, str, str, str, str]], Dict[str, int], Dict[str, List[Tuple[str, str]]]]:
    file_id = upsert_file_id(conn, host_label, remote_path)
    old_offset, old_mtime = get_checkpoint(conn, file_id)

    try:
        st = sftp.stat(remote_path)
        mtime = st.st_mtime
        size = st.st_size
    except IOError:
        return 0, [], {}, {}

    start_offset = old_offset if (mtime >= old_mtime and old_offset <= size) else 0

    events = []
    counts = {"FAILED_LOGIN": 0, "CRASH": 0, "SUSPICIOUS": 0}
    samples = {k: [] for k in counts.keys()}

    # SFTP file-like object supports seek/tell/read
    try:
        f = sftp.open(remote_path, "r")
        f.set_pipelined(True)
        f.seek(start_offset)
        for raw in f:
            try:
                line = raw.decode("utf-8", "ignore") if isinstance(raw, bytes) else raw
            except Exception:
                line = str(raw)
            matched = False
            for category, patterns in COMPILED_PATTERNS.items():
                for pat in patterns:
                    if pat.search(line):
                        matched = True
                        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
                        events.append((ts, host_label, remote_path, category, pat.pattern, line.strip()))
                        counts[category] += 1
                        if len(samples[category]) < 5:
                            samples[category].append((host_label, remote_path))
                        break
                if matched:
                    break
        end_offset = f.tell()
        f.close()
    except Exception as e:
        print(f"[WARN] Remote read failed {host_label}:{remote_path}: {e}")
        return 0, [], {}, {}

    if events:
        conn.executemany(
            "INSERT INTO events(ts_utc, host, filepath, category, pattern, line) VALUES (?, ?, ?, ?, ?, ?)",
            events,
        )
        append_csv(events, CONFIG["CSV_PATH"])

    update_checkpoint(conn, file_id, end_offset, mtime)
    return len(events), events, counts, samples


# ==========
# SCHEDULER
# ==========

def scan_once():
    print(f"[{datetime.now().strftime('%H:%M:%S')}] scanning...")
    total_found = 0
    aggregate_counts = {"FAILED_LOGIN": 0, "CRASH": 0, "SUSPICIOUS": 0}
    sample_events: Dict[str, List[Tuple[str, str]]] = {k: [] for k in aggregate_counts.keys()}

    with db() as conn:
        # LOCAL
        if CONFIG["MODE"] in ("local", "mixed"):
            local_files = expand_local_paths(CONFIG["LOCAL_PATHS"], CONFIG["FILENAME_GLOBS"])
            for fp in local_files:
                try:
                    found, _, counts, samples = scan_local_file(conn, fp)
                    total_found += found
                    for k in aggregate_counts.keys():
                        aggregate_counts[k] += counts.get(k, 0)
                        # only keep a handful to show in alerts
                        for s in samples.get(k, []):
                            if len(sample_events[k]) < 5:
                                sample_events[k].append(s)
                except Exception as e:
                    print(f"[WARN] Local scan failed for {fp}: {e}")

        # REMOTE
        if CONFIG["MODE"] in ("remote", "mixed"):
            for rh in CONFIG["REMOTE_HOSTS"]:
                try:
                    host_label, sftp = SSH_CACHE.get_sftp(rh)
                except Exception as e:
                    print(f"[WARN] SSH connect failed {rh.get('host')}: {e}")
                    continue
                for rpath in rh.get("paths", []):
                    try:
                        found, _, counts, samples = scan_remote_file(conn, host_label, sftp, rpath)
                        total_found += found
                        for k in aggregate_counts.keys():
                            aggregate_counts[k] += counts.get(k, 0)
                            for s in samples.get(k, []):
                                if len(sample_events[k]) < 5:
                                    sample_events[k].append(s)
                    except Exception as e:
                        print(f"[WARN] Remote scan failed {host_label}:{rpath}: {e}")

    print(f"[scan] new events this cycle: {total_found}  | counts {aggregate_counts}")
    alert_if_needed(aggregate_counts, sample_events)


def daily_db_maintenance():
    with db() as conn:
        conn.execute("VACUUM")
        conn.execute("ANALYZE")
    print("[maintenance] SQLite VACUUM + ANALYZE complete.")


def main():
    init_db()

    # quick banner
    print("=" * 60)
    print(" Automated Log Analyzer & Alerting ")
    print("=" * 60)
    print(f"Mode: {CONFIG['MODE']}")
    if CONFIG["MODE"] in ("local", "mixed"):
        print(f"Local paths: {CONFIG['LOCAL_PATHS']}")
    if CONFIG["MODE"] in ("remote", "mixed"):
        rh_hosts = [f"{h.get('host')}:{h.get('port',22)}" for h in CONFIG["REMOTE_HOSTS"]]
        print(f"Remote hosts: {rh_hosts}")
    print(f"Scan interval: {CONFIG['SCAN_EVERY_SECONDS']}s")
    print(f"Output: SQLite={CONFIG['SQLITE_PATH']}  CSV={CONFIG['CSV_PATH']}")
    print("Alerts:",
          f"Email={'ON' if CONFIG['ALERTS']['EMAIL']['ENABLED'] else 'OFF'},",
          f"Slack={'ON' if CONFIG['ALERTS']['SLACK']['ENABLED'] else 'OFF'}")
    print("=" * 60)

    # First immediate scan for demo pop
    scan_once()

    # Schedule recurring scans
    schedule.every(CONFIG["SCAN_EVERY_SECONDS"]).seconds.do(scan_once)
    schedule.every().day.at("03:30").do(daily_db_maintenance)

    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[exit] shutting down...")
    finally:
        SSH_CACHE.close_all()


if __name__ == "__main__":
    # sanity: create data dir
    Path(CONFIG["DATA_DIR"]).mkdir(parents=True, exist_ok=True)
    main()

