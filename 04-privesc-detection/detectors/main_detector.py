#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Main orchestrator to run all privilege escalation detection scripts in parallel.
"""

import subprocess
import os
import sys
import time

# List of detection scripts
SCRIPTS = [
    "AlwaysElevatedPriv-Detect.py",
    "Ruas-Detect.py",
    "SeBackUpPrivilege-Detection.py",
    "Unattended-Detect.py",
    "Unquoted_escalation-Detect.py",
]

def main():
    procs = []
    base_dir = os.path.dirname(os.path.abspath(__file__))

    try:
        for script in SCRIPTS:
            path = os.path.join(base_dir, script)
            if not os.path.exists(path):
                print(f"[!] Script not found: {path}")
                continue

            print(f"[*] Launching {script} ...")
            # Run each script in parallel
            p = subprocess.Popen([sys.executable, path],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            procs.append((script, p))

        print("[*] All detectors launched. Press Ctrl+C to stop.")

        # Keep running until user interrupts
        while True:
            time.sleep(5)
            # Optionally check if any process died
            for script, p in procs:
                if p.poll() is not None:  # process exited
                    print(f"[!] {script} exited unexpectedly.")
    except KeyboardInterrupt:
        print("\n[!] Stopping all detectors...")
        for script, p in procs:
            p.terminate()
        print("[*] All stopped.")

if __name__ == "__main__":
    main()
