# -*- coding: utf-8 -*-
"""
Unit tests for the privilege-escalation detectors' decision logic.

Each test reproduces a specific bug that was found in an external code review and
then fixed, so a regression would turn the test red. They run anywhere with just
pytest (no Windows, no pywin32, no live event log), because the logic under test
lives in the dependency-free detection_logic module.

    pip install pytest
    pytest
"""
import os
import sys
import datetime as dt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detectors"))
import detection_logic as dl  # noqa: E402


# ---------------------------------------------------------------------------
# Bug 1 — command-line auditing was written to the wrong registry key
# (…\Policies\System instead of …\Policies\System\Audit), so the script
# reported success while the telemetry never turned on.
# ---------------------------------------------------------------------------
def test_audit_key_targets_the_audit_subkey():
    assert dl.AUDIT_POLICY_KEY.endswith(r"\Policies\System\Audit")
    assert dl.AUDIT_POLICY_VALUE == "ProcessCreationIncludeCmdLine_Enabled"


# ---------------------------------------------------------------------------
# Bug 2 — the event reader took only the newest fixed-size batch and advanced
# its baseline past it, so a burst bigger than one batch lost the overflow.
# collect_until_baseline must return every record above the baseline.
# ---------------------------------------------------------------------------
def test_burst_larger_than_one_batch_loses_nothing():
    # 300 new records (rids 101..400) arrive newest-first across two pages
    # (256 + 44) — exactly the shape that used to drop the oldest 44.
    rids = list(range(400, 100, -1))                 # 400 down to 101
    page1 = [{"rid": r} for r in rids[:256]]
    page2 = [{"rid": r} for r in rids[256:]]
    got = dl.collect_until_baseline([page1, page2], baseline=100)
    assert len(got) == 300
    assert {r["rid"] for r in got} == set(range(101, 401))


def test_drain_stops_at_the_baseline():
    page = [{"rid": r} for r in (5, 4, 3, 2, 1)]     # newest-first
    got = dl.collect_until_baseline([page], baseline=3)
    assert [r["rid"] for r in got] == [5, 4]         # 3 and older are excluded


# ---------------------------------------------------------------------------
# Bug 3 — a 4624 logon was linked to a runas by timing alone, so an unrelated
# user's logon soon after someone else's runas produced a false alert.
# ---------------------------------------------------------------------------
def test_parse_runas_target_strips_domain():
    assert dl.parse_runas_target(r'runas /savecred /user:WIN-LAB\labadmin "cmd.exe /c whoami"') == "labadmin"
    assert dl.parse_runas_target(r'runas /savecred /user:labadmin@corp whoami') == "labadmin"
    assert dl.parse_runas_target("runas /savecred whoami") is None


def test_same_account_logon_correlates():
    now = dt.datetime(2026, 1, 1, 12, 0, 30)
    recent = [(dt.datetime(2026, 1, 1, 12, 0, 0), "labadmin")]
    assert dl.runas_logon_correlates("labadmin", recent, now, 180) is True


def test_unrelated_user_logon_does_not_correlate():
    # Alice ran runas; Bob's unrelated interactive logon must NOT alert.
    now = dt.datetime(2026, 1, 1, 12, 0, 30)
    recent = [(dt.datetime(2026, 1, 1, 12, 0, 0), "alice")]
    assert dl.runas_logon_correlates("bob", recent, now, 180) is False


def test_same_account_outside_window_does_not_correlate():
    now = dt.datetime(2026, 1, 1, 12, 10, 0)         # 10 min later
    recent = [(dt.datetime(2026, 1, 1, 12, 0, 0), "labadmin")]
    assert dl.runas_logon_correlates("labadmin", recent, now, 180) is False


# ---------------------------------------------------------------------------
# Bug 4 — a registry read failure became None and classified as INFO
# ("not exploitable"), making a collection failure look reassuring.
# ---------------------------------------------------------------------------
def test_both_hives_set_is_critical():
    sev, _, _ = dl.classify_always_install(1, [1])
    assert sev == "CRITICAL"


def test_only_hklm_set_is_high():
    sev, _, _ = dl.classify_always_install(1, [0, None])
    assert sev == "HIGH"


def test_absent_is_info():
    sev, _, _ = dl.classify_always_install(None, [None])
    assert sev == "INFO"


def test_read_error_is_not_reported_as_safe():
    sev, msg, _ = dl.classify_always_install(dl.READ_ERROR, [None])
    assert sev == "UNKNOWN"
    assert "not exploitable" not in msg.lower()


# ---------------------------------------------------------------------------
# Bug 5 — the backup matcher used `"save" in cmdline` (matched "saved"), missed
# the HKEY_LOCAL_MACHINE spelling, and flagged diskshadow unconditionally
# (even `/?`). These are the exact cases from the review.
# ---------------------------------------------------------------------------
def test_reg_save_sam_alerts():
    assert dl.is_suspicious_backup("reg.exe", r"reg save HKLM\SAM C:\temp\sam.hiv") is True


def test_reg_save_long_hive_spelling_alerts():
    assert dl.is_suspicious_backup("reg.exe", r"reg save HKEY_LOCAL_MACHINE\SAM C:\temp\s") is True


def test_reg_query_saved_does_not_alert():
    # "saved" contains "save" but is a read, not a hive save.
    assert dl.is_suspicious_backup("reg.exe", r"reg query HKLM\SAM /v saved") is False


def test_diskshadow_help_does_not_alert():
    assert dl.is_suspicious_backup("diskshadow.exe", "diskshadow.exe /?") is False


def test_diskshadow_script_alerts():
    assert dl.is_suspicious_backup("diskshadow.exe", "diskshadow.exe /s dump.dsh") is True


def test_benign_reg_query_does_not_alert():
    assert dl.is_suspicious_backup("reg.exe", r"reg query HKLM\SOFTWARE\Microsoft") is False
