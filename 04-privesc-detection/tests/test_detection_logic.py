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
T0 = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.timezone.utc)


def test_parse_runas_target_keeps_domain():
    assert dl.parse_runas_target(r'runas /savecred /user:WIN-LAB\labadmin "cmd.exe /c whoami"') == ("win-lab", "labadmin")
    assert dl.parse_runas_target("runas /savecred /user:labadmin whoami") == (None, "labadmin")
    # A UPN suffix is not comparable to a 4624 NetBIOS domain, so it is not kept.
    assert dl.parse_runas_target("runas /savecred /user:labadmin@corp whoami") == (None, "labadmin")
    assert dl.parse_runas_target("runas /savecred whoami") is None


def test_same_account_logon_correlates():
    recent = [(T0, ("win-lab", "labadmin"))]
    assert dl.runas_logon_correlates("labadmin", "WIN-LAB", recent, T0 + dt.timedelta(seconds=30), 180) is True


def test_unrelated_user_logon_does_not_correlate():
    # Alice ran runas; Bob's unrelated interactive logon must NOT alert.
    recent = [(T0, ("corp", "alice"))]
    assert dl.runas_logon_correlates("bob", "CORP", recent, T0 + dt.timedelta(seconds=30), 180) is False


def test_same_name_in_another_domain_does_not_correlate():
    # Re-audit finding: DOMAIN_A\admin must not match DOMAIN_B\admin.
    recent = [(T0, ("domain_a", "admin"))]
    assert dl.runas_logon_correlates("admin", "DOMAIN_B", recent, T0 + dt.timedelta(seconds=30), 180) is False


def test_same_account_outside_window_does_not_correlate():
    recent = [(T0, ("win-lab", "labadmin"))]
    assert dl.runas_logon_correlates("labadmin", "WIN-LAB", recent, T0 + dt.timedelta(minutes=10), 180) is False


def test_correlation_uses_event_time_not_processing_time():
    # Re-audit finding: the window is measured between the two events' own
    # timestamps. A logon whose TimeCreated is before the runas never correlates,
    # however the events happen to be processed.
    recent = [(T0, ("win-lab", "labadmin"))]
    assert dl.runas_logon_correlates("labadmin", "WIN-LAB", recent, T0 - dt.timedelta(seconds=5), 180) is False


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


def test_enumeration_failure_is_not_reported_as_safe():
    # Re-audit finding: if the user hives could not even be listed, an absent
    # machine value must not produce INFO / "not exploitable".
    sev, msg, det = dl.classify_always_install(None, [], hku_enumerated=False)
    assert sev == "UNKNOWN"
    assert det["visibility"] == "incomplete"
    assert "not exploitable" not in msg.lower()


def test_confirmed_critical_is_not_downgraded_by_an_unreadable_hive():
    # Re-audit finding: HKLM=1 + one user =1 + another user unreadable is still
    # a confirmed CRITICAL; the unreadable hive is reported separately.
    sev, _, det = dl.classify_always_install(1, [1, dl.READ_ERROR])
    assert sev == "CRITICAL"
    assert det["visibility"] == "incomplete"


def test_high_with_unreadable_user_hive_flags_possible_critical():
    sev, msg, det = dl.classify_always_install(1, [0, dl.READ_ERROR])
    assert sev == "HIGH"
    assert det["visibility"] == "incomplete"
    assert "could be critical" in msg.lower()


def test_complete_visibility_is_reported():
    _, _, det = dl.classify_always_install(1, [1])
    assert det["visibility"] == "complete"


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


def test_reg_query_value_named_save_does_not_alert():
    # Re-audit finding: "save" as a whole word is still not a save unless it is
    # the reg subcommand.
    assert dl.is_suspicious_backup("reg.exe", r"reg query HKLM\SAM /v save") is False


def test_reg_save_with_full_path_and_quotes_alerts():
    assert dl.is_suspicious_backup(
        "reg.exe", r'"C:\Windows\System32\reg.exe" save "HKLM\SAM" C:\temp\s') is True


def test_reg_save_of_a_non_credential_hive_does_not_alert():
    assert dl.is_suspicious_backup("reg.exe", r"reg save HKLM\SOFTWARE C:\temp\sw.hiv") is False


def test_diskshadow_help_does_not_alert():
    assert dl.is_suspicious_backup("diskshadow.exe", "diskshadow.exe /?") is False


def test_diskshadow_script_alerts():
    assert dl.is_suspicious_backup("diskshadow.exe", "diskshadow.exe /s dump.dsh") is True


def test_benign_reg_query_does_not_alert():
    assert dl.is_suspicious_backup("reg.exe", r"reg query HKLM\SOFTWARE\Microsoft") is False
