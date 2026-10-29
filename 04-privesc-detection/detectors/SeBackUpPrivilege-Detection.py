import os
import sys
import time
import logging

import psutil

# Shared, unit-tested decision logic (see detection_logic.py and ../tests/).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detection_logic import is_suspicious_backup

# Configure logging to file
logging.basicConfig(
    filename="sebackup_detection.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def monitor():
    seen_pids = set()
    print("[*] Monitoring for SeBackupPrivilege-related credential-hive access...")
    print("    (Polling every 3s — very short-lived commands may still be missed; see README limitations.)")

    while True:
        try:
            current_pids = set()

            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    username = proc.info.get('username', 'N/A')
                    cmdline = proc.info.get('cmdline') or []
                    cmdline_str = ' '.join(cmdline)

                    current_pids.add(pid)

                    if is_suspicious_backup(name, cmdline_str) and pid not in seen_pids:
                        seen_pids.add(pid)
                        alert_msg = (
                            f"[!] Possible SeBackupPrivilege abuse:\n"
                            f"    PID   : {pid}\n"
                            f"    Name  : {name}\n"
                            f"    User  : {username}\n"
                            f"    CMD   : {cmdline_str}"
                        )
                        print(f"\n{alert_msg}")
                        logging.info(alert_msg)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Expected: the process ended, or we can't read it. Skip quietly.
                    continue
                except Exception as e:
                    # Unexpected: report it rather than silently ignoring.
                    logging.warning(f"Error inspecting a process: {e}")
                    continue

            # Drop PIDs that are no longer running so a reused PID can alert again.
            seen_pids.intersection_update(current_pids)
            time.sleep(3)

        except KeyboardInterrupt:
            print("\n[+] Monitoring stopped by user.")
            break
        except Exception as e:
            # Keep running, but surface the error instead of hiding it.
            logging.error(f"Monitor loop error: {e}")
            time.sleep(3)


if __name__ == "__main__":
    monitor()
