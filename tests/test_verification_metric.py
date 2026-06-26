"""Tests for the verified-secret precision metric and history exposure window."""

from credscan.history.result_manager import HistoryResultManager
from credscan.output.reporter import verification_stats


class TestVerificationStats:
    def test_live_rate_from_real_verdicts(self):
        findings = [
            {"aws_validation": "ACTIVE: Account 1, ARN arn:... [long_term]"},
            {"verification": "ACTIVE: github user: x"},
            {"verification": "INVALID: revoked"},
            {"verification": "SKIPPED: no secret"},  # not counted as verifiable
            {"rule_name": "no verdict here"},
        ]
        s = verification_stats(findings)
        # 3 verifiable (2 ACTIVE + 1 INVALID); SKIPPED and no-verdict excluded.
        assert s["verifiable"] == 3
        assert s["live"] == 2
        assert round(s["live_rate"], 3) == round(2 / 3, 3)

    def test_no_verdicts_is_zero(self):
        s = verification_stats([{"rule_name": "x"}, {"value": "y"}])
        assert s["verifiable"] == 0 and s["live"] == 0 and s["live_rate"] == 0.0

    def test_breached_counted(self):
        s = verification_stats(
            [
                {"breach_exposure": "EXPOSED: seen in 9 known breaches"},
                {"breach_exposure": "not in known breaches"},
            ]
        )
        assert s["breached"] == 1


class TestExposureWindow:
    def _finding(self, ts, value="AKIAEXAMPLE0000000XX"):
        return {
            "rule_id": "r",
            "original_file": "a.py",
            "variable": "k",
            "value": value,
            "commit_timestamp": ts,
        }

    def test_window_widens_across_commits(self):
        m = HistoryResultManager()
        # Newest-first (as the scanner feeds them): newest, then older dup.
        m.process_commit_findings("newsha", [self._finding(1_700_000_000)])
        m.process_commit_findings("oldsha", [self._finding(1_600_000_000)])
        out = m.get_findings()
        assert len(out) == 1  # deduped to one credential
        f = out[0]
        assert f["exposure_commit_count"] == 2
        assert f["first_seen_timestamp"] == 1_600_000_000
        assert f["last_seen_timestamp"] == 1_700_000_000
        assert f["first_seen_commit"] == "oldsha"
        assert f["last_seen_commit"] == "newsha"
        # ~1.1 billion seconds apart is well over 60 days -> "months".
        assert "months" in f["exposure_window"]
        assert "2 commits" in f["exposure_window"]

    def test_single_commit_window(self):
        m = HistoryResultManager()
        m.process_commit_findings("sha", [self._finding(1_700_000_000)])
        f = m.get_findings()[0]
        assert f["exposure_commit_count"] == 1
        assert "1 commit" in f["exposure_window"]
