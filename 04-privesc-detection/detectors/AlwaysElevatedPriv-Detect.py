#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r"""
AlwaysInstallElevated Live Detector (Windows 10/11)
Run as Administrator.

Watches:
  HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
  HKEY_USERS\<SID>\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

Logic:
  - CRITICAL: HKLM == 1 AND ANY HKCU == 1 (exploitable)
  - HIGH:     HKLM == 1 XOR ANY HKCU == 1
  - INFO:     none set or both 0
Writes JSONL: C:\ProgramData\AIE_Monitor\events.jsonl
"""

import os, sys, time, json
from datetime import datetime
from pathlib import Path
import winreg

LOG_DIR = r"C:\ProgramData\AIE_Monitor"
JSONL = os.path.join(LOG_DIR, "events.jsonl")
POLL_SEC = 2

HKLM_PATH = r"SOFTWARE\Policies\Microsoft\Windows\Installer"
HKLM_VALUE = "AlwaysInstallElevated"
HKCU_REL  = r"Software\Policies\Microsoft\Windows\Installer"  # under HKEY_USERS\<SID>\...

def now_utc():
    return datetime.utcnow().isoformat() + "Z"

def ensure_dirs():
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True)

def write_event(ev: dict):
    ensure_dirs()
    with open(JSONL, "a", encoding="utf-8") as f:
        f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {ev['severity']}: {ev['short']} — {ev['message']}", flush=True)

def read_dword(root, subkey, value):
    try:
        k = winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        try:
            data, typ = winreg.QueryValueEx(k, value)
            if typ == winreg.REG_DWORD:
                return True, int(data)
            # non-DWORD: treat as present but unknown
            return True, None
        finally:
            winreg.CloseKey(k)
    except FileNotFoundError:
        return False, None
    except Exception:
        return False, None

def list_loaded_user_sids():
    """Enumerate currently loaded user hives under HKEY_USERS (ignores .DEFAULT and Classes)."""
    sids = []
    try:
        root = winreg.OpenKey(winreg.HKEY_USERS, "", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        i = 0
        while True:
            try:
                name = winreg.EnumKey(root, i)
                i += 1
                # Typical SIDs: S-1-5-21-... ; ignore machine classes and default
                if name.upper().endswith("_CLASSES"):
                    continue
                if name.startswith("S-1-5-"):
                    sids.append(name)
            except OSError:
                break
        winreg.CloseKey(root)
    except Exception:
        pass
    return sids

def snapshot_state():
    """Return current state dict: {'HKLM': 0/1/None, 'HKU': {sid: 0/1/None}}."""
    state = {"HKLM": None, "HKU": {}}

    # HKLM
    present, val = read_dword(winreg.HKEY_LOCAL_MACHINE, HKLM_PATH, HKLM_VALUE)
    state["HKLM"] = (val if present else None)

    # HKEY_USERS\<SID>
    for sid in list_loaded_user_sids():
        present, val = read_dword(winreg.HKEY_USERS, rf"{sid}\{HKCU_REL}", HKLM_VALUE)
        state["HKU"][sid] = (val if present else None)

    return state

def compare_states(prev, curr):
    """Yield change events as dictionaries (one per changed key)."""
    # HKLM change
    if prev is None or prev.get("HKLM") != curr.get("HKLM"):
        yield {
            "scope": "HKLM",
            "path": f"HKLM\\{HKLM_PATH}\\{HKLM_VALUE}",
            "old": (None if prev is None else prev.get("HKLM")),
            "new": curr.get("HKLM")
        }

    # HKU per SID
    prev_hku = {} if prev is None else prev.get("HKU", {})
    for sid, newv in curr.get("HKU", {}).items():
        oldv = prev_hku.get(sid, None)
        if oldv != newv:
            yield {
                "scope": "HKU",
                "sid": sid,
                "path": rf"HKEY_USERS\{sid}\{HKCU_REL}\{HKLM_VALUE}",
                "old": oldv,
                "new": newv
            }

    # Detect SIDs removed
    for sid in prev_hku.keys():
        if sid not in curr.get("HKU", {}):
            yield {
                "scope": "HKU",
                "sid": sid,
                "path": rf"HKEY_USERS\{sid}\{HKCU_REL}\{HKLM_VALUE}",
                "old": prev_hku.get(sid),
                "new": None
            }

def classify_overall(state):
    """Return (severity, short, details) for the aggregate posture."""
    hklm = state.get("HKLM")
    hku_vals = [v for v in state.get("HKU", {}).values() if v is not None]
    any_hku_1 = any(v == 1 for v in hku_vals)

    if hklm == 1 and any_hku_1:
        return "CRITICAL", "AlwaysInstallElevated exploitable (HKLM=1 & HKCU=1)", {"hklm": hklm, "hku_any_1": True}
    if hklm == 1 and not any_hku_1:
        return "HIGH", "HKLM AlwaysInstallElevated enabled (HKCU not set/0)", {"hklm": hklm, "hku_any_1": False}
    if hklm != 1 and any_hku_1:
        return "MEDIUM", "HKCU AlwaysInstallElevated enabled for at least one user (HKLM!=1)", {"hklm": hklm, "hku_any_1": True}
    return "INFO", "AlwaysInstallElevated not exploitable (both unset or 0)", {"hklm": hklm, "hku_any_1": any_hku_1}

def emit_posture_event(state):
    sev, short, det = classify_overall(state)
    ev = {
        "time_utc": now_utc(),
        "technique": "AlwaysInstallElevated",
        "severity": sev,
        "host": os.environ.get("COMPUTERNAME", ""),
        "user": os.environ.get("USERNAME", ""),
        "short": short,
        "message": f"HKLM={state.get('HKLM')} | HKU_any_1={det['hku_any_1']}",
        "policy_state": {
            "HKLM": state.get("HKLM"),
            "HKU": state.get("HKU", {})
        }
    }
    write_event(ev)

def main():
    if os.name != "nt":
        print("This detector is intended for Windows.")
        sys.exit(1)

    print("AlwaysInstallElevated Live Detector — running as Admin is required.")
    ensure_dirs()

    prev = None
    # Baseline snapshot + posture emit
    curr = snapshot_state()
    emit_posture_event(curr)
    prev = curr

    while True:
        time.sleep(POLL_SEC)
        curr = snapshot_state()

        # Emit any changes
        for ch in compare_states(prev, curr):
            sev, short, _ = classify_overall(curr)
            ev = {
                "time_utc": now_utc(),
                "technique": "AlwaysInstallElevated",
                "severity": sev if sev in ("CRITICAL","HIGH","MEDIUM") else "INFO",
                "host": os.environ.get("COMPUTERNAME", ""),
                "user": os.environ.get("USERNAME", ""),
                "short": f"Registry change: {ch['path']}",
                "message": f"{ch['old']} -> {ch['new']}",
                "change": ch,
                "policy_state": {
                    "HKLM": curr.get("HKLM"),
                    "HKU": curr.get("HKU", {})
                }
            }
            write_event(ev)

        # Periodically (every loop) also emit aggregate posture if it moved between classes
        prev_sev, _, _ = classify_overall(prev or {})
        curr_sev, _, _ = classify_overall(curr)
        if prev_sev != curr_sev:
            emit_posture_event(curr)

        prev = curr

if __name__ == "__main__":
    main()
