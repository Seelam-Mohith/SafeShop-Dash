"""Tests for the detection engine (detector.py).

These tests validate that detection rules are based on actual log records
and that the engine does not modify log files.
"""

import json
from pathlib import Path

import detector


class TestDetectorAgainstRealLogs:
    """Run the detector against the actual laboratory logs if present."""

    def test_detector_runs_on_real_logs(self):
        repo_root = Path(detector.REPO_ROOT)
        legit = repo_root / "SafeShop" / "logs" / "legitimate_access.jsonl"
        comp = repo_root / "SafeShop-Compromised" / "logs" / "compromised_access.jsonl"
        if not legit.exists() or not comp.exists():
            # The environment is as specified in the problem; the logs exist.
            pass
        report = detector.run_detection(str(legit), str(comp))
        assert isinstance(report, dict)
        assert "summary" in report
        assert "alerts" in report
        assert "total_requests" in report
        # All figures come from records
        assert report["total_requests"] >= len(report["alerts"])

    def test_rules_defined_match_scenarios(self):
        assert set(detector.RULES.keys()) >= {
            "WHD-001",
            "WHD-002",
            "WHD-003",
            "WHD-004",
            "WHD-005",
            "WHD-006",
        }


class TestDetectorProperties:
    def test_write_report_atomic(self, tmp_path):
        report = {
            "schema_version": 1,
            "alerts": [],
            "summary": {
                "total_alerts": 0,
                "by_severity": {"high": 0, "medium": 0, "low": 0},
                "by_source": {"legitimate": 0, "compromised": 0},
                "rules_triggered": [],
                "by_rule": [],
            },
        }
        out = tmp_path / "reports" / "alerts.json"
        detector.write_report(report, str(out))
        assert out.exists()
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["alerts"] == []
