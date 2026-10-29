import psutil
import time
import logging

# Configure logging to file
logging.basicConfig(
    filename="sebackup_detection.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Backup-capable tools that can be abused to read protected files (e.g. the SAM hive)
# when an account holds SeBackupPrivilege. To avoid flagging every benign reg.exe or
# robocopy, we only alert when the COMMAND LINE shows the tool is actually touching
# credential material.
CREDENTIAL_HINTS = (
    "hklm\\sam", "hklm\\system", "hklm\\security",
    "\\config\\sam", "\\config\\system", "\\config\\security",
)


def is_suspicious(name, cmdline_str):
    n = (name or "").lower()
    c = (cmdline_str or "").lower()
    if n == "reg.exe":
        # reg save of a credential hive (e.g. `reg save hklm\sam ...`)
        return "save" in c and any(h in c for h in CREDENTIAL_HINTS)
    if n == "esentutl.exe":
        return any(h in c for h in CREDENTIAL_HINTS)
    if n == "diskshadow.exe":
        # Rarely used interactively on a workstation — worth flagging on sight.
        return True
    if n == "robocopy.exe":
        # Backup mode (/b) copying from the registry config folder.
        return (" /b" in c) and ("\\config" in c)
    return False


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

                if is_suspicious(name, cmdline_str) and pid not in seen_pids:
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
