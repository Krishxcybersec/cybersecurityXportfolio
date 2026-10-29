# -*- coding: utf-8 -*-
r"""
Shared, dependency-free detection logic for the privilege-escalation detectors.

This module holds the *decision* logic only — no Windows I/O (no win32evtlog,
winreg, WMI or psutil). Keeping it separate means the logic can be unit-tested
on any machine without a Windows host or a live event log. The detector scripts
import these helpers; the tests in ../tests/ exercise them directly.

Each helper below corresponds to a bug that was found and fixed; see
../tests/test_detection_logic.py, which reproduces each original failure.
"""
import re

# ---------------------------------------------------------------------------
# Command-line process-creation auditing (Event 4688 with CommandLine)
# ---------------------------------------------------------------------------
# The "Include command line in process creation events" policy value lives under
# the \Audit subkey. Writing it one level up (…\Policies\System) silently fails
# to turn the telemetry on, so the script reports success while the detections
# that need the command line never get it. This constant is the single source
# of truth for both detectors that enable it.
# Ref: https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-auditsettings
AUDIT_POLICY_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
AUDIT_POLICY_VALUE = "ProcessCreationIncludeCmdLine_Enabled"


# ---------------------------------------------------------------------------
# Technique 3 — SeBackupPrivilege / credential-hive access
# ---------------------------------------------------------------------------
CREDENTIAL_HINTS = (
    r"hklm\sam", r"hklm\system", r"hklm\security",
    r"hkey_local_machine\sam", r"hkey_local_machine\system", r"hkey_local_machine\security",
    r"\config\sam", r"\config\system", r"\config\security",
)

_HELP_FLAGS = ("/?", "-?", "/help", "--help")


_CREDENTIAL_HIVES = {h for h in CREDENTIAL_HINTS if h.startswith("hk")}


def _has_credential_hint(cmdline_lower: str) -> bool:
    return any(h in cmdline_lower for h in CREDENTIAL_HINTS)


def reg_save_hive(cmdline: str):
    """If the command is `reg save <hive> ...`, return the hive argument
    (lowercased, without quotes or a trailing backslash); otherwise None.

    `save` must be the reg SUBCOMMAND (the word straight after reg / reg.exe),
    not just a word somewhere in the line — so `reg query HKLM\\SAM /v save`
    is a query, not a save.
    """
    tokens = [t.strip('"') for t in (cmdline or "").lower().split()]
    for i, tok in enumerate(tokens):
        if tok.rsplit("\\", 1)[-1] in ("reg", "reg.exe"):
            if i + 2 < len(tokens) and tokens[i + 1] == "save":
                return tokens[i + 2].rstrip("\\")
            return None
    return None


def is_suspicious_backup(name: str, cmdline: str) -> bool:
    """True when a backup-capable tool is actually touching credential material.

    Deliberately narrow:
      * for reg.exe, `save` must be the subcommand and the hive argument must be
        a credential hive, so a query that merely mentions "save"/"saved" does
        not alert;
      * both the short (`hklm\\sam`) and long (`hkey_local_machine\\sam`) hive
        spellings are recognised.
    diskshadow is rare enough on a workstation to flag on sight, but never on a
    help invocation (`/?`).
    """
    n = (name or "").lower()
    c = (cmdline or "").lower()
    if n == "reg.exe":
        return reg_save_hive(c) in _CREDENTIAL_HIVES
    if n == "esentutl.exe":
        return _has_credential_hint(c)
    if n == "diskshadow.exe":
        if any(f in c for f in _HELP_FLAGS):
            return False
        return True
    if n == "robocopy.exe":
        return (" /b" in c) and ("\\config" in c)
    return False


# ---------------------------------------------------------------------------
# Technique 1 — AlwaysInstallElevated
# ---------------------------------------------------------------------------
# Sentinel for "the value could not be read" (permission error, etc.), which is
# NOT the same as the value being absent. A collection failure must never be
# reported as "not exploitable".
READ_ERROR = "ERROR"


def classify_always_install(hklm, hku_values, hku_enumerated=True):
    """Classify the AlwaysInstallElevated posture.

    hklm           : 1, 0, None (absent) or READ_ERROR (could not read)
    hku_values     : iterable of the same, one per loaded user hive
    hku_enumerated : False if the list of user hives itself could not be read

    Returns (severity, message, details). Two rules:
      * Severity reflects what was CONFIRMED from the values that could be read,
        so an unreadable extra hive never downgrades a confirmed CRITICAL.
      * Incomplete visibility is reported separately (details["visibility"]),
        and when nothing dangerous was confirmed it yields UNKNOWN rather than
        INFO, so a collection problem can never read as "not exploitable".
    """
    hku_values = list(hku_values)
    known_hku = [v for v in hku_values if v != READ_ERROR]
    incomplete = (not hku_enumerated) or hklm == READ_ERROR or len(known_hku) != len(hku_values)
    any_hku_1 = any(v == 1 for v in known_hku)
    details = {"hklm": hklm, "hku_any_1": any_hku_1,
               "visibility": "incomplete" if incomplete else "complete"}
    note = " (visibility incomplete: some values could not be read)" if incomplete else ""

    if hklm == 1 and any_hku_1:
        return ("CRITICAL", "AlwaysInstallElevated exploitable (HKLM=1 & HKCU=1)" + note, details)
    if hklm == 1:
        extra = " (some user hives unreadable: could be CRITICAL)" if incomplete else ""
        return ("HIGH", "HKLM AlwaysInstallElevated enabled (HKCU not set/0)" + extra, details)
    if any_hku_1:
        extra = " (HKLM unreadable: could be CRITICAL)" if hklm == READ_ERROR else note
        return ("MEDIUM", "HKCU AlwaysInstallElevated enabled for at least one user (HKLM!=1)" + extra, details)
    if incomplete:
        return ("UNKNOWN",
                "AlwaysInstallElevated could not be fully read (collection failure) — treat as unverified",
                details)
    return ("INFO", "AlwaysInstallElevated not exploitable (both unset or 0)", details)


# ---------------------------------------------------------------------------
# Technique 4 — runas /savecred correlation
# ---------------------------------------------------------------------------
def parse_runas_target(cmdline: str):
    """Return (domain, account) named by `runas /user:...`, both lowercased, or
    None if absent. The domain is kept so that DOMAIN_A\\admin and DOMAIN_B\\admin
    are not treated as the same account; it is None when the command gave no
    domain (a local account) or used a UPN (user@suffix), whose suffix is not
    comparable to the NetBIOS domain in a 4624 event."""
    if not cmdline:
        return None
    m = re.search(r"/user:(\S+)", cmdline, flags=re.IGNORECASE)
    if not m:
        return None
    acct = m.group(1).strip().strip('"')
    domain = None
    if "\\" in acct:
        domain, acct = acct.split("\\", 1)
    elif "@" in acct:
        acct = acct.split("@", 1)[0]
    acct = acct.lower()
    if not acct:
        return None
    return ((domain or "").lower() or None, acct)


def _same_account(target, logon_user, logon_domain):
    domain, account = target
    if account != (logon_user or "").lower():
        return False
    # Compare domains whenever both sides name one.
    if domain and logon_domain and domain != logon_domain.lower():
        return False
    return True


def runas_logon_correlates(logon_user, logon_domain, recent_runas, event_time, window_sec):
    """Decide whether a 4624 logon really follows a runas /savecred.

    The logon must be for the SAME account the runas targeted (account name,
    and domain when both sides give one), within `window_sec` of the runas,
    measured on the events' own timestamps rather than on processing time.

    logon_user / logon_domain : TargetUserName / TargetDomainName from the 4624
    recent_runas              : list of (event_time, (domain, account))
    event_time                : TimeCreated of the 4624 event
    """
    if not logon_user:
        return False
    for t, target in recent_runas:
        if (target and _same_account(target, logon_user, logon_domain)
                and 0 <= (event_time - t).total_seconds() <= window_sec):
            return True
    return False


# ---------------------------------------------------------------------------
# Event-log reading — drain every new record (fixes burst event loss)
# ---------------------------------------------------------------------------
def collect_until_baseline(pages, baseline):
    """Return every record newer than `baseline`, draining pages to the baseline.

    `pages` is an iterable of pages in newest-first order (and each page holds
    records newest-first); every record is a dict with an integer `rid`
    (EventRecordID). Because record IDs are monotonic, the first record at or
    below the baseline means everything after it is older, so we stop there.

    The old readers took a single fixed-size batch (e.g. 256) and advanced the
    baseline past it, so a burst larger than one batch lost the overflow
    permanently. Draining to the baseline fixes that.
    """
    out = []
    for page in pages:
        for rec in page:
            if rec["rid"] <= baseline:
                return out
            out.append(rec)
    return out
