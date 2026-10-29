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


def _has_credential_hint(cmdline_lower: str) -> bool:
    return any(h in cmdline_lower for h in CREDENTIAL_HINTS)


def is_suspicious_backup(name: str, cmdline: str) -> bool:
    """True when a backup-capable tool is actually touching credential material.

    Deliberately narrow, to fix two earlier problems:
      * `save` is matched as a whole word, so `reg query ... /v saved` no longer
        trips the rule (the old `"save" in cmdline` matched the substring in
        "saved").
      * both the short (`hklm\\sam`) and long (`hkey_local_machine\\sam`) hive
        spellings are recognised.
    diskshadow is rare enough on a workstation to flag on sight, but never on a
    help invocation (`/?`), which the old code alerted on.
    """
    n = (name or "").lower()
    c = (cmdline or "").lower()
    if n == "reg.exe":
        return bool(re.search(r"\bsave\b", c)) and _has_credential_hint(c)
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


def classify_always_install(hklm, hku_values):
    """Classify the AlwaysInstallElevated posture.

    hklm        : 1, 0, None (absent) or READ_ERROR (could not read)
    hku_values  : iterable of the same, one per loaded user hive

    Returns (severity, message, details). A read failure returns UNKNOWN rather
    than INFO/"not exploitable", so a collection problem cannot look reassuring.
    """
    hku_values = list(hku_values)
    if hklm == READ_ERROR or any(v == READ_ERROR for v in hku_values):
        return (
            "UNKNOWN",
            "AlwaysInstallElevated could not be read (collection failure) — treat as unverified",
            {"hklm": hklm, "hku_any_1": None},
        )
    any_hku_1 = any(v == 1 for v in hku_values)
    if hklm == 1 and any_hku_1:
        return ("CRITICAL", "AlwaysInstallElevated exploitable (HKLM=1 & HKCU=1)",
                {"hklm": hklm, "hku_any_1": True})
    if hklm == 1 and not any_hku_1:
        return ("HIGH", "HKLM AlwaysInstallElevated enabled (HKCU not set/0)",
                {"hklm": hklm, "hku_any_1": False})
    if hklm != 1 and any_hku_1:
        return ("MEDIUM", "HKCU AlwaysInstallElevated enabled for at least one user (HKLM!=1)",
                {"hklm": hklm, "hku_any_1": True})
    return ("INFO", "AlwaysInstallElevated not exploitable (both unset or 0)",
            {"hklm": hklm, "hku_any_1": any_hku_1})


# ---------------------------------------------------------------------------
# Technique 4 — runas /savecred correlation
# ---------------------------------------------------------------------------
def parse_runas_target(cmdline: str):
    """Return the account named by `runas /user:[domain\\]account`, lowercased
    and without the domain, or None if absent."""
    if not cmdline:
        return None
    m = re.search(r"/user:(\S+)", cmdline, flags=re.IGNORECASE)
    if not m:
        return None
    acct = m.group(1).strip().strip('"')
    if "\\" in acct:
        acct = acct.split("\\", 1)[1]
    if "@" in acct:
        acct = acct.split("@", 1)[0]
    return acct.lower() or None


def runas_logon_correlates(logon_user, recent_runas, now, window_sec):
    """Decide whether a 4624 logon really follows a runas /savecred.

    The old code correlated on time proximity alone, so an unrelated user's
    logon soon after someone else's runas produced a false "Post-Runas" alert.
    Here the logon must be for the SAME account the runas targeted, within the
    window.

    logon_user   : TargetUserName from the 4624 event
    recent_runas : list of (timestamp, target_account_lower) seen recently
    """
    if not logon_user:
        return False
    lu = logon_user.lower()
    for t, target in recent_runas:
        if target and target == lu and 0 <= (now - t).total_seconds() <= window_sec:
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
