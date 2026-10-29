# -*- coding: utf-8 -*-
# Live detector for Unquoted Service Path exploitation on Windows.
# Enumerates services with UNQUOTED ImagePath (with spaces), builds candidate
# binaries Windows might execute earlier (e.g., C:\\Program.exe), and monitors
# Security(4688/4720/4732) + System(7036) from "now" onward.
# Run as Administrator.  Requires:  pip install pywin32
# CSV output: C:\ProgramData\UnquotedServiceEscalation-Detections.csv

import os, re, sys, time, csv, datetime as dt, xml.etree.ElementTree as ET
import win32evtlog
import win32com.client
import win32security   # for SID -> name
import winreg          # for registry tweak (4688 cmdline)

# Shared, unit-tested decision logic (see detection_logic.py and ../tests/).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detection_logic import collect_until_baseline, AUDIT_POLICY_KEY, AUDIT_POLICY_VALUE

# ---------------- Config ----------------
OUT_CSV = r"C:\ProgramData\UnquotedServiceEscalation-Detections.csv"
WRITE_CSV = True
CORR_WINDOW_SEC = 15  # seconds
SECURITY_IDS = (4688, 4720, 4732)
SYSTEM_IDS   = (7036,)

# --------------- Utilities ---------------
def ensure_outfile():
    if not WRITE_CSV:
        return
    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    if not os.path.exists(OUT_CSV):
        with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(["Timestamp","Host","Detector","Details"])

def alert(detector, details):
    ts = dt.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    host = os.environ.get("COMPUTERNAME","")
    line = f"[ALERT] {detector} :: {details}"
    print(line)
    if WRITE_CSV:
        with open(OUT_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([ts, host, detector, details.replace("\n"," ")])

def nsmap(root):
    if root.tag.startswith("{"):
        return {"e": root.tag.split("}")[0].strip("{")}
    return {}

def xfind(elem, path, ns):
    try:
        return elem.find(path if not ns else (path if path.startswith("e:") else f"e:{path}"), ns)
    except Exception:
        return None

def parse_event_xml(xml_str):
    # Return (event_id, computer, record_id, time_created_utc, data_map)
    root = ET.fromstring(xml_str)
    ns = nsmap(root)
    system = xfind(root, "System", ns)
    if system is None:
        for c in root.iter():
            if c.tag.endswith("System"):
                system = c; break
    if system is None:
        raise ValueError("No <System>")

    event_id = -1; computer = ""; record_id = None; tcreated = None
    for c in system:
        t = (c.text or "").strip()
        if c.tag.endswith("EventID") and t: event_id = int(t)
        elif c.tag.endswith("Computer"): computer = t
        elif c.tag.endswith("EventRecordID") and t: record_id = int(t)
        elif c.tag.endswith("TimeCreated"):
            iso = c.attrib.get("SystemTime")
            if iso:
                try: tcreated = dt.datetime.fromisoformat(iso.replace("Z","+00:00"))
                except: tcreated = None

    data = {}
    for d in root.iter():
        if d.tag.endswith("Data"):
            name = d.attrib.get("Name","")
            if name:
                data.setdefault(name, d.text or "")
    return event_id, computer, record_id, tcreated, data

def newest_record_id(log_name, ids):
    q = "*[System[(" + " or ".join(f"EventID={i}" for i in ids) + ")]]"
    try:
        h = win32evtlog.EvtQuery(log_name, win32evtlog.EvtQueryReverseDirection, q)
        ev = win32evtlog.EvtNext(h, 1)
        if not ev: return 0
        xml = win32evtlog.EvtRender(ev[0], win32evtlog.EvtRenderEventXml)
        _,_,rid,_,_ = parse_event_xml(xml)
        return rid or 0
    except Exception:
        return 0

def drain_log(log_name, query, baseline):
    """Read ALL events on `log_name` newer than `baseline`, paging back to it.

    Replaces the old single fixed-size batch (64/128), which advanced the
    baseline past whatever it read and so lost any burst larger than one batch.
    """
    h = win32evtlog.EvtQuery(log_name, win32evtlog.EvtQueryReverseDirection, query)
    pages = []
    while True:
        batch = win32evtlog.EvtNext(h, 256)  # newest first
        if not batch:
            break
        page = []
        reached = False
        for e in batch:
            try:
                xml = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                eid, host, rid, tcreated, data = parse_event_xml(xml)
            except Exception:
                continue
            if rid is None:
                continue
            page.append({"rid": rid, "eid": eid, "tcreated": tcreated, "data": data})
            if rid <= baseline:
                reached = True
        pages.append(page)
        if reached:
            break
    return collect_until_baseline(pages, baseline)

# ----------- Service enumeration ----------
def extract_exe_path(pathname: str):
    # From a service PathName, return the exe path up to .exe (no args).
    if not pathname:
        return None
    s = pathname.strip()
    if s.startswith('"'):
        m = re.match(r'^"([^"]+?\.exe)"', s, flags=re.IGNORECASE)
        return m.group(1) if m else None
    m = re.match(r'^([A-Za-z]:\\.*?\.exe)\b', s, flags=re.IGNORECASE)
    return m.group(1) if m else None

def candidate_execs(unquoted_exe_path: str):
    # Build the Windows search-order candidates for an UNQUOTED path with spaces.
    # Example: 'C:\\Program Files\\Vuln Service\\service.exe' ->
    #          ['C:\\Program.exe', 'C:\\Program Files\\Vuln.exe']
    path = unquoted_exe_path
    prefix = path[:-4] if path.lower().endswith(".exe") else path
    candidates = []
    for m in re.finditer(r'\s', prefix):
        candidates.append(prefix[:m.start()] + ".exe")
    out, seen = [], set()
    for c in candidates:
        lc = c.lower()
        if lc not in seen:
            seen.add(lc); out.append(c)
    return out

def enumerate_unquoted_services():
    # Returns:
    #   candidate_to_services: dict(lower-candidate-path -> set([service names]))
    #   service_candidates:   dict(service name -> list(candidate paths))
    # Includes only services with UNQUOTED ImagePath that contains spaces.
    locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    svc = locator.ConnectServer(".", "root\\cimv2")
    results = svc.ExecQuery("SELECT Name, DisplayName, PathName FROM Win32_Service")
    candidate_to_services = {}
    service_candidates = {}
    for r in results:
        raw = r.PathName
        exe = extract_exe_path(raw)
        if not exe:
            continue
        unquoted = (raw is not None) and (not str(raw).strip().startswith('"'))
        if unquoted and (" " in exe):
            cands = candidate_execs(exe)
            if not cands:
                continue
            service_candidates[r.Name] = cands
            for c in cands:
                candidate_to_services.setdefault(c.lower(), set()).add(r.Name)
    return candidate_to_services, service_candidates

# ------------ 4732 Member resolver -------------
def resolve_member_name(data: dict) -> str:
    # Prefer MemberName; if missing, try MemberSid -> DOMAIN\\Name.
    name = data.get("MemberName", "")
    if name:
        return name
    sid_str = data.get("MemberSid", "")
    if not sid_str:
        return "-"
    try:
        sid = win32security.ConvertStringSidToSid(sid_str)
        acct, domain, _ = win32security.LookupAccountSid(None, sid)
        return f"{domain}\\{acct}" if domain else acct
    except Exception:
        return sid_str

# ----------------- Main monitor -----------------
def main():
    ensure_outfile()

    print("[*] Enumerating services with unquoted ImagePath ...")
    cand2svc, svc2cands = enumerate_unquoted_services()
    if not cand2svc:
        print("[i] No unquoted service paths with spaces were found. Monitoring anyway.")
    else:
        print(f"[i] Monitoring {len(cand2svc)} candidate hijack path(s) across {len(svc2cands)} vulnerable service(s).")
        for s, cands in svc2cands.items():
            print(f"    - {s}: {', '.join(cands)}")

    # Live-only baselines
    base_sec = newest_record_id("Security", SECURITY_IDS)
    base_sys = newest_record_id("System",   SYSTEM_IDS)
    start_utc = dt.datetime.now(dt.timezone.utc)
    print(f"[*] Live-only mode. Baselines -> Security RID={base_sec}, System RID={base_sys}")

    recent_service_starts = []   # list[(t_utc, service_name)]

    q_sec = "*[System[(" + " or ".join(f"EventID={i}" for i in SECURITY_IDS) + ")]]"
    q_sys = "*[System[(" + " or ".join(f"EventID={i}" for i in SYSTEM_IDS)   + ")]]"

    try:
        while True:
            # --- System log: 7036 (service running/stopped) ---
            try:
                new_sys = drain_log("System", q_sys, base_sys)
                new_sys = [r for r in new_sys if not (r["tcreated"] and r["tcreated"] < start_utc)]
                new_sys.sort(key=lambda x: x["rid"])
                for r in new_sys:
                    base_sys = max(base_sys, r["rid"])
                    if r["eid"] == 7036:
                        data = r["data"]
                        svc_name = data.get("param1","")
                        state    = data.get("param2","")
                        if state.lower().startswith("running"):
                            recent_service_starts.append((r["tcreated"] or dt.datetime.now(dt.timezone.utc), svc_name))
                            cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=CORR_WINDOW_SEC)
                            recent_service_starts = [(t,s) for (t,s) in recent_service_starts if t >= cutoff]
            except Exception:
                pass

            # --- Security log: 4688/4720/4732 ---
            try:
                new_sec = drain_log("Security", q_sec, base_sec)
                new_sec = [r for r in new_sec if not (r["tcreated"] and r["tcreated"] < start_utc)]
                new_sec.sort(key=lambda x: x["rid"])
                for r in new_sec:
                    base_sec = max(base_sec, r["rid"])
                    eid = r["eid"]; data = r["data"]; tcreated = r["tcreated"]

                    if eid == 4688:
                        newproc = (data.get("NewProcessName","") or "").lower()
                        if newproc in cand2svc:
                            svcs = ", ".join(sorted(cand2svc[newproc]))
                            # correlate with recent 7036 "Running"
                            correlated = False
                            t_evt = tcreated or dt.datetime.now(dt.timezone.utc)
                            for t,s in recent_service_starts:
                                if s in cand2svc[newproc] and abs((t_evt - t).total_seconds()) <= CORR_WINDOW_SEC:
                                    correlated = True; break
                            msg = f"Suspicious binary executed: '{newproc}'. Possible hijack for service(s): {svcs}."
                            if correlated:
                                msg += " (Correlated with recent service start)"
                            alert("UnquotedServicePath_Exploit", msg)

                    elif eid == 4720:
                        new_user = data.get("TargetUserName","") or "?"
                        subj     = data.get("SubjectUserName","") or "?"
                        alert("UserCreated_4720", f"New user '{new_user}' created by '{subj}'")

                    elif eid == 4732:
                        group = data.get("TargetUserName","") or data.get("GroupName","") or "?"
                        member = resolve_member_name(data)
                        alert("AddedToLocalGroup_4732", f"Member added to local group. Group='{group}', Member='{member}'")

            except Exception:
                pass

            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[+] Stopped.")

# ---------------- bootstrap ----------------
if __name__ == "__main__":
    # Best-effort: enable auditing (non-fatal if it fails). The command-line
    # inclusion value lives under …\Policies\System\Audit — see
    # detection_logic.AUDIT_POLICY_KEY.
    try:
        os.system('auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable >nul 2>&1')
        os.system('auditpol /set /subcategory:"Logon" /success:enable /failure:enable >nul 2>&1')
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, AUDIT_POLICY_KEY)
            winreg.SetValueEx(key, AUDIT_POLICY_VALUE, 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except Exception:
            pass
    except Exception:
        pass

    ensure_outfile()
    print("[*] Starting Unquoted Service Path live detector...")
    main()
