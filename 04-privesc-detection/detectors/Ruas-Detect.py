# -*- coding: utf-8 -*-
r"""
Live-only detector for runas /savecred escalation (Windows)
- Processes ONLY events that occur AFTER the script starts
- Optional user filter: set the WATCH_USER env var to a low-priv account to focus on
  (default: watch all accounts)
- Alerts written to C:\ProgramData\RunasSaveCred-Detections.csv
Run as Administrator. Requires: pip install pywin32
"""
import os, re, csv, time, datetime as dt, xml.etree.ElementTree as ET
import win32evtlog  # pywin32

OUT_FILE   = r"C:\ProgramData\RunasSaveCred-Detections.csv"
WATCH_USER = os.environ.get("WATCH_USER", "")  # low-priv account to focus on (case-insensitive); "" = watch all. Override via the WATCH_USER env var.
CORR_WINDOW_SEC = 180

def ensure_out():
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    if not os.path.exists(OUT_FILE):
        with open(OUT_FILE, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(["Timestamp","Host","Detector","Details"])

def alert(det, details):
    ts = dt.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    row = [ts, os.environ.get("COMPUTERNAME",""), det, (details or "").replace("\n"," ")]
    with open(OUT_FILE, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(row)
    print(f"[ALERT] {det} :: {details}")

def nsmap(root):
    if root.tag.startswith("{"):
        return {"e": root.tag.split("}")[0].strip("{")}
    return {}

def xfind(elem, path, ns):
    try:
        return elem.find(path if not ns else (path if path.startswith("e:") else f"e:{path}"), ns)
    except Exception:
        return None

def xtext(elem, path, ns, default=None):
    n = xfind(elem, path, ns)
    return n.text if (n is not None and n.text is not None) else default

def parse_event_xml(xml_str):
    root = ET.fromstring(xml_str)
    ns = nsmap(root)

    # System
    system = xfind(root, "System", ns)
    if system is None:
        for c in root.iter():
            if c.tag.endswith("System"):
                system = c; break
    if system is None:
        raise ValueError("No <System> in event")

    # Event basics
    event_id_txt = None
    for c in system:
        if c.tag.endswith("EventID") and (c.text or "").strip():
            event_id_txt = c.text.strip(); break
    event_id = int(event_id_txt) if (event_id_txt and event_id_txt.isdigit()) else -1

    computer = None
    for c in system:
        if c.tag.endswith("Computer"):
            computer = (c.text or ""); break

    # EventRecordID
    record_id = None
    for c in system:
        if c.tag.endswith("EventRecordID") and (c.text or "").strip():
            record_id = int(c.text.strip()); break

    # TimeCreated SystemTime (UTC)
    time_created = None
    for c in system:
        if c.tag.endswith("TimeCreated"):
            t = c.attrib.get("SystemTime")
            if t:
                try:
                    time_created = dt.datetime.fromisoformat(t.replace("Z","+00:00"))
                except Exception:
                    time_created = None
            break

    # EventData map
    data = {}
    for d in root.iter():
        if d.tag.endswith("Data"):
            name = d.attrib.get("Name","")
            if name:
                data.setdefault(name, d.text or "")

    return event_id, computer or "", record_id, time_created, data

def newest_record_id():
    h = win32evtlog.EvtQuery("Security", win32evtlog.EvtQueryReverseDirection,
                             "*[System[(EventID=4688 or EventID=4624 or EventID=4648 or EventID=4672)]]")
    try:
        evts = win32evtlog.EvtNext(h, 1)
        if not evts:
            return 0
        xml = win32evtlog.EvtRender(evts[0], win32evtlog.EvtRenderEventXml)
        _,_,rid,_,_ = parse_event_xml(xml)
        return rid or 0
    except Exception:
        return 0

def main():
    ensure_out()

    # Baselines: only process events strictly newer than these
    baseline_rid   = newest_record_id()
    start_time_utc = dt.datetime.now(dt.timezone.utc)

    # Correlation memory
    recent_runas_times = []

    print(f"[*] Live-only mode. Baseline RecordID={baseline_rid}. StartUTC={start_time_utc.isoformat()}")
    print("[*] Monitoring Security log… Ctrl+C to stop.")

    # Poll by re-querying small batches; process only record IDs > baseline
    query = "*[System[(EventID=4688 or EventID=4624 or EventID=4648 or EventID=4672)]]"

    try:
        while True:
            h = win32evtlog.EvtQuery("Security", win32evtlog.EvtQueryReverseDirection, query)
            events = win32evtlog.EvtNext(h, 256)  # newest first
            if not events:
                time.sleep(1); continue

            # We want chronological order for new items. First filter to record_id > baseline, then sort
            new_items = []
            for e in events:
                try:
                    xml = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                    event_id, host, rid, tcreated, data = parse_event_xml(xml)
                    if rid is None or rid <= baseline_rid:
                        continue
                    # Also enforce time gate (some logs can be ingested late)
                    if tcreated and tcreated < start_time_utc:
                        continue
                    new_items.append((event_id, host, rid, tcreated, data))
                except Exception as ex:
                    # Ignore parse errors in live mode
                    continue

            if not new_items:
                time.sleep(1); continue

            # Process oldest->newest among the *new* ones
            new_items.sort(key=lambda x: x[2])  # sort by RecordID
            for event_id, host, rid, tcreated, data in new_items:
                # Update baseline as we go
                if rid > baseline_rid:
                    baseline_rid = rid

                # Extract fields
                newproc  = (data.get("NewProcessName","") or "").lower()
                parent   = (data.get("ParentProcessName","") or "").lower()
                cmdline  = (data.get("CommandLine","") or data.get("ProcessCommandLine","") or "")
                subj_user= (data.get("SubjectUserName","") or "")
                tgt_user = (data.get("TargetUserName","") or "")
                tgt_dom  = (data.get("TargetDomainName","") or "")
                logon_tp = (data.get("LogonType","") or "")
                procname = (data.get("ProcessName","") or "")

                # Optional user filter to cut down noise
                def user_ok(u):
                    return (not WATCH_USER) or (u.lower() == WATCH_USER.lower())

                now = dt.datetime.now()

                if event_id == 4688:
                    # cmdkey.exe
                    if newproc.endswith("\\cmdkey.exe") and user_ok(subj_user):
                        alert("CMDKEY_Usage", f"By={subj_user}; CommandLine='{cmdline}'")

                    # runas.exe /savecred
                    if newproc.endswith("\\runas.exe") and re.search(r"(?i)\s/savecred\b", cmdline):
                        # subject user filter applies to the one launching runas
                        if user_ok(subj_user):
                            alert("RUNAS_SaveCred", f"By={subj_user}; CommandLine='{cmdline}'")
                            recent_runas_times.append(now)

                    # shell spawned by runas
                    if parent.endswith("\\runas.exe") and (
                        newproc.endswith("\\cmd.exe") or newproc.endswith("\\powershell.exe") or newproc.endswith("\\pwsh.exe")
                    ):
                        alert("RUNAS_ChildShell", f"Shell='{newproc}' spawned; By={subj_user}; CmdLine='{cmdline}'")

                elif event_id == 4648:
                    # explicit creds — likely during runas
                    if user_ok(subj_user) or user_ok(tgt_user):
                        alert("ExplicitCredLogon_4648", f"Subject={subj_user} -> Target={tgt_dom}\\{tgt_user}; Proc={procname}")

                elif event_id == 4624:
                    # only care about interactive-ish types and likely tied to runas
                    if logon_tp in ("2","10","11"):
                        # correlate with recent runas
                        recent_runas_times = [t for t in recent_runas_times if (now - t).total_seconds() <= CORR_WINDOW_SEC]
                        if recent_runas_times and (user_ok(tgt_user) or WATCH_USER == ""):
                            alert("Post-Runas_Logon_4624", f"User={tgt_user}; LogonType={logon_tp} (soon after runas /savecred)")

                elif event_id == 4672:
                    # ignore noisy SYSTEM tokens; focus on human accounts or your WATCH_USER
                    if subj_user.upper() != "SYSTEM" and (user_ok(subj_user) or WATCH_USER == ""):
                        alert("SpecialPrivs_4672", f"User {subj_user} received special privileges.")

            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[+] Stopped.")

if __name__ == "__main__":
    # Optional: turn on command-line auditing (non-fatal if it fails)
    try:
        import winreg
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
        winreg.SetValueEx(key, "ProcessCreationIncludeCmdLine_Enabled", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        print("[*] Enabled ProcessCreationIncludeCmdLine_Enabled=1 (may need reboot).")
    except Exception as e:
        print(f"[i] Could not set command-line auditing: {e}")
    main()
