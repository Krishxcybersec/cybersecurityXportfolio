# Windows Privilege-Escalation Detection

> Windows privilege-escalation detection project, 2025.
> *Analyzing and Mitigating Windows Privilege Escalation Vulnerabilities in Modern Enterprise Environments.*

**This project is five lightweight, rule-based Python detectors** that watch a Windows host for the moment a common privilege-escalation technique is used, and log a structured alert. (On authorship: the scripts were generated with AI assistance — see "What's mine, and what isn't" below.) The idea is a middle ground between a one-off enumeration scan (like WinPEAS) and a heavyweight enterprise logging stack (like Sysmon + a SIEM): continuous, scenario-specific, low-overhead monitoring a defender can actually read.

**Skills shown:** blue-team detection engineering · Windows internals (registry, services, privileges, Event Log) · Python · `pywin32` / WMI / Event Tracing · attack–defence pairing · comparison with Sysmon and WinPEAS

---

## What's mine, and what isn't

I want to be upfront about this, because it matters on a public profile.

- **Mine:** the project itself — choosing the five techniques, building the lab, running the tests, the analysis, and the comparison with existing tools (WinPEAS, Sysmon). The five Python detection scripts and their orchestrator were **generated with AI assistance**; my own contribution is the hands-on testing, the interpretation of results, and the reporting — not independent coding of them.
- **Not mine, and deliberately left out:** the vulnerable-lab setup script. My lab was built on the well-known **Local Privilege Escalation Workshop installer by Sagi Shahar (@s4gi_) and Tib3rius (@tibsec)** — see [sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop). I used it to seed the five misconfigurations; I did not write it, so it is not included here. Credit to the original authors.
- **Third-party tools used during testing** (standard, not my code): WinPEAS and PowerSploit/PowerUp for enumeration, and Metasploit for payload generation.

---

## The five techniques detected

| # | Technique | What the detector watches | Script |
|---|-----------|---------------------------|--------|
| 1 | **SeBackupPrivilege abuse** | `reg save` / backup tools dumping the SAM/SYSTEM hives from a non-admin account | `SeBackUpPrivilege-Detection.py` |
| 2 | **Runas /savecred** | `runas.exe /savecred`, `cmdkey`, and the shell it spawns (Event IDs 4688/4648/4624/4672) | `Ruas-Detect.py` |
| 3 | **AlwaysInstallElevated** | the `HKLM` + `HKCU` Installer policy keys; CRITICAL when both are `1` | `AlwaysElevatedPriv-Detect.py` |
| 4 | **Unquoted service path** | services with unquoted `ImagePath`, plus the hijack binary being run (4688/7036) and any new user/group change (4720/4732) | `Unquoted_escalation-Detect.py` |
| 5 | **Autologon / Unattend creds** | unauthorised reads of `Unattend.xml` under `C:\Windows\Panther` (Event ID 4663) | `Unattended-Detect.py` |

`main_detector.py` launches all five in parallel.

---

## How it works

- **Rule-driven, not ML.** Each detector maps to one technique, aiming for specific,
  low-noise alerts. (Some detectors still have false-positive risks — see Limitations.)
- **Live-only.** Detectors baseline the Event Log at start-up and only report new activity, so they don't re-alert on historical events.
- **Structured output.** Alerts go to the console and to JSON / CSV under `C:\ProgramData\...`, so they can later be shipped into a SIEM.
- **Severity.** For example, AlwaysInstallElevated is `HIGH` when only `HKLM` is set, and `CRITICAL` when both `HKLM` and `HKCU` are `1` (i.e. actually exploitable).

### Example alert output (lab, host name genericised)

```
[15:31:12] CRITICAL: AlwaysInstallElevated exploitable (HKLM=1 & HKCU=1) — HKLM=1 | HKU_any_1=True

[!] Suspicious process detected:
    PID  : 16444
    Name : reg.exe
    User : WIN-LAB\backup_svc
    CMD  : reg save hklm\sam C:\temp\sam1.hive

[ALERT] UnquotedServicePath_Exploit :: Suspicious binary executed:
        'c:\program files\unquoted path service\common.exe'. Possible hijack for service: unquotedsvc.

[2025-09-04T09:59:16Z] CRITICAL: Unauthorized read of Unattend.xml — user accessed C:\Windows\Panther\Unattend.xml
```

JSON event:

```json
{
  "time_utc": "2025-09-04T00:29:42Z",
  "technique": "SeBackupPrivilege",
  "severity": "CRITICAL",
  "host": "WIN-LAB",
  "user": "backup_svc",
  "process": "reg.exe",
  "command": "reg save hklm\\sam C:\\temp\\sam.hive",
  "message": "Suspicious process detected accessing SAM hive"
}
```

---

## Running them

> For a lab VM only. These are defensive monitors; run them as Administrator.

```bash
pip install pywin32 psutil
python detectors/main_detector.py
```

Each detector also runs on its own. They enable command-line process auditing (Event ID 4688 with command line) on start-up where it isn't already on.

---

## Findings

- All five are valid, known-exploitable techniques on a fully-updated Windows 11 host when the misconfiguration is present. In my testing I focused on **detecting** them rather than carrying each through to a full SYSTEM shell — see the [Detection Gap Report](https://github.com/Krishxcybersec/privesc-detection-gap-report) for the precise scope of what was demonstrated per technique.
- Each detector flagged its technique in the lab, with contextual detail (user, command line, registry path, decoded value). **Later testing** (see my [Detection Gap Report](https://github.com/Krishxcybersec/privesc-detection-gap-report)) found an important limitation: the polling-based detectors can **miss very short-lived commands** (a fast `reg save` slipped between polls), and some have false-positive risks. These are honest findings that fed the "future work" below.
- Against Sysmon and WinPEAS, the detectors sit in the useful middle: more targeted and readable than raw Sysmon telemetry, and continuous where WinPEAS is a one-shot snapshot.

## Limitations (honest)

- **Two kinds of polling.** The backup and AlwaysInstallElevated checks poll live state (the process list / registry, every 2–3 s), so very short-lived activity can be missed. The runas and unquoted-service detectors poll the **persisted Windows event log** (every second); a record stays in the log after the process exits, so they don't miss short-lived activity, and they now read every new record each poll. Real-time ETW / WMI subscriptions would remove the polling delay for all of them.
- **Five techniques only** — no token impersonation, DLL hijacking, COM abuse or kernel exploits.
- **Tested in a lab, not an enterprise.** At scale these would need tuning and central log management.
- Best seen as a **proof of concept and a complement** to enterprise EDR, not a replacement.

## Reliability fixes and tests

Two rounds of external code review found real defects. Each one below has been
addressed **for the cases the tests cover**. The decision logic now lives in a
dependency-free module (`detectors/detection_logic.py`), and a pytest suite (`tests/`)
reproduces each original failure, so a regression turns a test red.

| Area | What was wrong before | Now |
|---|---|---|
| Command-line auditing key | Written to `…\Policies\System` instead of `…\Policies\System\Audit`, so it could report success without enabling 4688 command-line telemetry | Uses the documented `…\System\Audit` key |
| Burst event loss | The reader took only the newest 256 events and advanced its baseline past them, permanently dropping larger bursts | Reads back to the baseline; a 300-event burst loses nothing |
| Runas ↔ logon correlation | Linked a 4624 logon to a `runas` by timing alone (unrelated users), then by account name only (same name, different domain), measured on processing time | Requires the same account **and** domain (when both are known), within a window measured on the events' own timestamps |
| Collection failure looked safe | An unreadable AlwaysInstallElevated value, or a failure to list user hives, was classified "not exploitable"; an unreadable extra hive could also downgrade a confirmed CRITICAL | Severity reflects what was confirmed; incomplete visibility is reported separately, and yields `UNKNOWN` instead of "not exploitable" |
| Backup matching | `"save"` matched `saved` or any `save` word in the line, the `HKEY_LOCAL_MACHINE` spelling was missed, and `diskshadow /?` alerted | `save` must be the `reg` subcommand and its argument a credential hive; both hive spellings recognised; help invocations ignored |

**Still not verified, and known remaining limits:**

- The tests cover the decision logic with synthetic inputs. **Live collection on a real
  Windows host and set-up on a fresh machine have not been re-tested** since these fixes.
- Runas correlation still matches on account and domain, not on a logon ID or SID, so it
  is stronger than before but not a hard link between the two events.
- A `runas /user:name@suffix` (UPN) target is matched on the account name only.

Run the tests:

```bash
pip install pytest
cd 04-privesc-detection
pytest
```

## Hardening recommendations

- Don't grant `SeBackupPrivilege` to non-admin accounts.
- Keep `AlwaysInstallElevated` disabled in both `HKLM` and `HKCU`.
- Quote all service binary paths.
- Avoid Autologon; delete unattended setup files after use.
- Monitor continuously — misconfigurations creep back in during maintenance.

## Future work

SIEM integration (Splunk/ELK/Sentinel), event-driven detection via ETW/WMI, a unified supervisor with a dashboard, and extending coverage to more techniques.
