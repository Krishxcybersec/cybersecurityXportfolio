#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r"""
Detect access to Unattend.xml under C:\Windows\Panther (Event ID 4663).

Requires file-system auditing (a SACL) on the target file, or 4663 is never generated.

Account check: this uses a simple allow-list of trusted accounts (TRUSTED_ACCOUNTS,
overridable via the UNATTEND_TRUSTED_ACCOUNTS env var). Add the accounts that are
EXPECTED to read answer files (build / admin accounts) so they don't alert. A more
robust version would resolve the account's actual group membership instead of matching
names — see README limitations.
"""

import win32evtlog
import time
import os
import json
from datetime import datetime, timezone

TARGET_FILE = "unattend.xml"

# Accounts expected to legitimately access the file. Override with a comma-separated
# UNATTEND_TRUSTED_ACCOUNTS env var, e.g. "administrator,system,builduser".
TRUSTED_ACCOUNTS = {
    a.strip().lower()
    for a in os.environ.get("UNATTEND_TRUSTED_ACCOUNTS", "administrator,system").split(",")
    if a.strip()
}

LOG_DIR = r"C:\ProgramData\PrivDetect"
JSONL = os.path.join(LOG_DIR, "unattend_access.jsonl")


def ensure_dirs():
    os.makedirs(LOG_DIR, exist_ok=True)


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_event(ev: dict):
    ensure_dirs()
    with open(JSONL, "a", encoding="utf-8") as f:
        f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    print(f"[{ev['time_utc']}] {ev['severity']}: {ev['short']} - {ev['message']}")


def is_untrusted(user: str) -> bool:
    # Simple allow-list check. NOTE: name-based, so it treats any account not listed in
    # TRUSTED_ACCOUNTS as untrusted. Keep TRUSTED_ACCOUNTS up to date for this host.
    return user.lower() not in TRUSTED_ACCOUNTS


def monitor_events():
    h = win32evtlog.OpenEventLog("localhost", "Security")
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    total = win32evtlog.GetNumberOfEventLogRecords(h)
    print(f"[*] Security log has {total} records. Monitoring only new events...")
    print(f"[*] Trusted accounts (won't alert): {', '.join(sorted(TRUSTED_ACCOUNTS))}")

    # Discard old records by reading backwards once.
    win32evtlog.ReadEventLog(
        h, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0
    )

    while True:
        try:
            events = win32evtlog.ReadEventLog(h, flags, 0)
        except Exception as e:
            # Surface the error rather than crashing or ignoring it silently.
            print(f"[!] Error reading the Security log: {e}")
            time.sleep(2)
            continue

        if events:
            for ev_obj in events:
                if ev_obj.EventID == 4663 and ev_obj.StringInserts:
                    inserts = ev_obj.StringInserts
                    user = inserts[1] if len(inserts) > 1 else "unknown"
                    obj = inserts[6] if len(inserts) > 6 else ""

                    if TARGET_FILE in obj.lower() and is_untrusted(user):
                        write_event({
                            "time_utc": now_utc(),
                            "technique": "UnattendXML Unauthorized Access",
                            "severity": "CRITICAL",
                            "host": os.environ.get("COMPUTERNAME", ""),
                            "user": user,
                            "short": "Access to Unattend.xml by a non-trusted account",
                            "message": f"{user} accessed {obj}",
                        })
        time.sleep(2)


if __name__ == "__main__":
    try:
        monitor_events()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
