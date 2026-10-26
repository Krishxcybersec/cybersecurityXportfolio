import psutil
import time
import logging
from datetime import datetime

# Configure logging to file
logging.basicConfig(
    filename="sebackup_detection.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Define suspicious tools typically used with SeBackupPrivilege
suspicious_tools = ['reg.exe', 'diskshadow.exe', 'robocopy.exe']
seen_pids = set()

print("[*] Monitoring for SeBackupPrivilege-related process usage...")

while True:
    try:
        current_pids = set()

        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                name = proc.info['name']
                pid = proc.info['pid']
                username = proc.info.get('username', 'N/A')
                cmdline = proc.info.get('cmdline', [])

                current_pids.add(pid)

                if name and name.lower() in suspicious_tools:
                    if pid not in seen_pids:
                        seen_pids.add(pid)

                        alert_msg = (
                            f"[!] Suspicious process detected:\n"
                            f"    PID   : {pid}\n"
                            f"    Name  : {name}\n"
                            f"    User  : {username}\n"
                            f"    CMD   : {' '.join(cmdline)}"
                        )

                        print(f"\n{alert_msg}")
                        logging.info(alert_msg)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Clean up seen_pids by removing ones no longer running
        seen_pids.intersection_update(current_pids)

        time.sleep(5)

    except KeyboardInterrupt:
        print("\n[+] Monitoring stopped by user.")
        break
