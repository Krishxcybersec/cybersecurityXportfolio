#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Orchestrator: run all privilege-escalation detectors in parallel.

Each detector prints its own alerts. This launcher lets the children inherit the
console (so those alerts are visible and no child can block on an undrained pipe),
reports any detector that exits, and shuts them all down cleanly on Ctrl+C.
"""

import subprocess
import os
import sys
import time

SCRIPTS = [
    "AlwaysElevatedPriv-Detect.py",
    "Ruas-Detect.py",
    "SeBackUpPrivilege-Detection.py",
    "Unattended-Detect.py",
    "Unquoted_escalation-Detect.py",
]


def launch(base_dir, script):
    path = os.path.join(base_dir, script)
    if not os.path.exists(path):
        print(f"[!] Script not found, skipping: {path}")
        return None
    print(f"[*] Launching {script} ...")
    # Inherit the parent's stdout/stderr: the detectors' alerts stay visible, and
    # (unlike the old stdout=PIPE) a child can never block on a full, undrained pipe.
    try:
        return subprocess.Popen([sys.executable, path])
    except Exception as e:
        print(f"[!] Failed to launch {script}: {e}")
        return None


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    procs = {}
    for script in SCRIPTS:
        p = launch(base_dir, script)
        if p is not None:
            procs[script] = p

    if not procs:
        print("[!] No detectors launched. Nothing to monitor.")
        return

    print(f"[*] {len(procs)} detector(s) running. Press Ctrl+C to stop all.")
    try:
        while procs:
            time.sleep(2)
            for script, p in list(procs.items()):
                rc = p.poll()
                if rc is not None:
                    # Report once, then stop tracking it (no repeated spam).
                    level = "exited cleanly" if rc == 0 else f"exited with code {rc}"
                    print(f"[!] {script} {level}.")
                    procs.pop(script, None)
        print("[!] All detectors have exited.")
    except KeyboardInterrupt:
        print("\n[!] Stopping all detectors...")
    finally:
        for p in procs.values():
            if p.poll() is None:
                p.terminate()
        deadline = time.time() + 5
        for script, p in procs.items():
            try:
                p.wait(timeout=max(0, deadline - time.time()))
            except subprocess.TimeoutExpired:
                print(f"[!] Force-killing {script}.")
                p.kill()
        print("[*] All stopped.")


if __name__ == "__main__":
    main()
