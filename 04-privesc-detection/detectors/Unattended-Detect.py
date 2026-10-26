#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Detect unauthorized access to Unattend.xml under C:\Windows\Panther.
Works with pywin32 legacy win32evtlog API (no .Evt).
"""

import win32evtlog
import time
import os
import json
from datetime import datetime

TARGET_FILE = "unattend.xml"
ADMIN_ACCOUNTS = {"administrator", "system", "admin"}  # trusted accounts
LOG_DIR = r"C:\ProgramData\PrivDetect"
JSONL = os.path.join(LOG_DIR, "unattend_access.jsonl")


def ensure_dirs():
    os.makedirs(LOG_DIR, exist_ok=True)


def now_utc():
    return datetime.utcnow().isoformat() + "Z"


def write_event(ev: dict):
    ensure_dirs()
    with open(JSONL, "a", encoding="utf-8") as f:
        f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    print(f"[{ev['time_utc']}] {ev['severity']}: {ev['short']} â€” {ev['message']}")


def is_low_priv(user: str) -> bool:
    return user.lower() not in ADMIN_ACCOUNTS


def monitor_events():
    server = "localhost"
    logtype = "Security"
    h = win32evtlog.OpenEventLog(server, logtype)

    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    # Start from the end of the log
    total = win32evtlog.GetNumberOfEventLogRecords(h)
    print(f"[*] Security log has {total} records. Monitoring only new events...")

    # Discard old records by reading backwards once
    win32evtlog.ReadEventLog(h, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)

    while True:
        events = win32evtlog.ReadEventLog(h, flags, 0)
        if events:
            for ev_obj in events:
                if ev_obj.EventID == 4663 and ev_obj.StringInserts:
                    inserts = ev_obj.StringInserts

                    # Defensive indexing
                    user = inserts[1] if len(inserts) > 1 else "unknown"
                    obj = inserts[6] if len(inserts) > 6 else ""

                    if TARGET_FILE in obj.lower() and is_low_priv(user):
                        ev = {
                            "time_utc": now_utc(),
                            "technique": "UnattendXML Unauthorized Access",
                            "severity": "CRITICAL",
                            "host": os.environ.get("COMPUTERNAME", ""),
                            "user": user,
                            "short": "Unauthorized read of Unattend.xml",
                            "message": f"{user} accessed {obj}",
                        }
                        write_event(ev)
        time.sleep(2)


if __name__ == "__main__":
    try:
        monitor_events()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")

