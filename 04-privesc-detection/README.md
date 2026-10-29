# Windows Privilege-Escalation Detection

> Windows privilege-escalation detection project, 2025.
> *Analyzing and Mitigating Windows Privilege Escalation Vulnerabilities in Modern Enterprise Environments.*

**This repo contains my own work: five lightweight, rule-based Python detectors** that watch a Windows host for the moment a common privilege-escalation technique is used, and log a structured alert. The idea is a middle ground between a one-off enumeration scan (like WinPEAS) and a heavyweight enterprise logging stack (like Sysmon + a SIEM): continuous, scenario-specific, low-overhead monitoring a defender can actually read.

**Skills shown:** blue-team detection engineering · Windows internals (registry, services, privileges, Event Log) · Python · `pywin32` / WMI / Event Tracing · attack–defence pairing · comparison with Sysmon and WinPEAS

---

## What's mine, and what isn't

I want to be upfront about this, because it matters on a public profile.

- **Mine (published here):** the five Python detection scripts and their orchestrator, the detection logic, the analysis, and the comparison with existing tools. These were written with AI assistance and then tested and tuned by me.
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

- **Rule-driven, not ML.** Each detector maps to one technique, so alerts are specific and easy to act on, with few false positives.
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

- All five techniques remained **exploitable on a fully-updated Windows 11** host when the misconfiguration was present.
- Each detector reliably flagged its technique in real time, with contextual detail (user, command line, registry path, decoded value) and minimal false positives.
- Against Sysmon and WinPEAS, the detectors sit in the useful middle: more targeted and readable than raw Sysmon telemetry, and continuous where WinPEAS is a one-shot snapshot.

## Limitations (honest)

- **Polling, not event-driven** for some checks (2–3 s interval), so very short-lived changes can be missed. ETW / WMI event consumers would be faster.
- **Five techniques only** — no token impersonation, DLL hijacking, COM abuse or kernel exploits.
- **Tested in a lab, not an enterprise.** At scale these would need tuning and central log management.
- Best seen as a **proof of concept and a complement** to enterprise EDR, not a replacement.

## Hardening recommendations

- Don't grant `SeBackupPrivilege` to non-admin accounts.
- Keep `AlwaysInstallElevated` disabled in both `HKLM` and `HKCU`.
- Quote all service binary paths.
- Avoid Autologon; delete unattended setup files after use.
- Monitor continuously — misconfigurations creep back in during maintenance.

## Future work

SIEM integration (Splunk/ELK/Sentinel), event-driven detection via ETW/WMI, a unified supervisor with a dashboard, and extending coverage to more techniques.
