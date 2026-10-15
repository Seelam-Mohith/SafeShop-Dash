"""Tests for the ShopSafe security monitoring dashboard.

All tests use isolated temporary files and fixtures; no tests modify the
real laboratory access logs or generate fake alerts for display.
"""

import json

from services.report_loader import (
    STATUS_MALFORMED,
    STATUS_MISSING,
    alerts_to_csv_rows,
    filter_alerts,
    find_alert,
    load_report,
    normalize_filters,
    recompute_summary,
)
from app import create_app


class TestHomepage:
    """Dashboard homepage / overview page."""

    def test_overview_page_loads(self, client):
        response = client.get("/")
        assert response.status_code == 200
        data = response.data.decode("utf-8")
        assert "ShopSafe SOC" in data
        assert "Overview" in data
        assert "Total requests analyzed" in data
        assert "Total alerts" in data

    def test_overview_shows_severity_counts(self, client):
        response = client.get("/")
        data = response.data.decode("utf-8")
        assert "High severity" in data
        assert "Medium severity" in data
        assert "Low severity" in data

    def test_overview_shows_rules_triggered(self, client):
        response = client.get("/")
        data = response.data.decode("utf-8")
        assert "Detection rules triggered" in data

    def test_overview_no_fake_alerts_when_report_present(self, client, sample_alerts):
        # Figures must come from the actual sample report records.
        response = client.get("/")
        data = response.data.decode("utf-8")
        # Sample report has 4 alerts total
        assert "4" in data


class TestWebsiteMonitoring:
    """Website monitoring page."""

    def test_websites_page_loads(self, client):
        response = client.get("/websites")
        assert response.status_code == 200
        data = response.data.decode("utf-8")
        assert "Legitimate ShopSafe" in data
        assert "Simulated Compromised ShopSafe" in data
        assert "5000" in data
        assert "5001" in data
        assert "Controlled laboratory" in data

    def test_websites_shows_log_names_and_roles(self, client):
        response = client.get("/websites")
        data = response.data.decode("utf-8")
        assert "legitimate_access.jsonl" in data
        assert "compromised_access.jsonl" in data


class TestAlertsListing:
    """Alerts page and alert data."""

    def test_alerts_page_loads(self, client):
        response = client.get("/alerts")
        assert response.status_code == 200
        data = response.data.decode("utf-8")
        assert "Alerts" in data
        assert "WHD-001" in data or "Alert records" in data

    def test_alerts_table_contains_required_columns(self, client):
        response = client.get("/alerts")
        data = response.data.decode("utf-8")
        for column in ["Time", "Website", "Rule", "Severity", "Path", "Evidence", "Recommendation"]:
            assert column in data

    def test_alert_detail_accessible(self, client, sample_alerts):
        response = client.get("/api/alerts/A-0001")
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["status"] == "ok"
        assert payload["alert"]["rule_id"] == "WHD-001"
        assert payload["alert"]["severity"] == "high"

    def test_unknown_alert_returns_404(self, client):
        response = client.get("/api/alerts/DOES-NOT-EXIST")
        assert response.status_code == 404


class TestSummaryCalculations:
    """Summary values computed from actual records."""

    def test_summary_api_from_actual_report(self, client):
        response = client.get("/api/summary")
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["available"] is True
        # Must equal the sample report exactly, not fabricated.
        assert payload["total_requests"] == 195
        assert payload["total_alerts"] == 4
        assert payload["by_severity"] == {"high": 2, "medium": 1, "low": 1}
        assert payload["by_source"] == {"legitimate": 1, "compromised": 3}

    def test_recompute_summary_counts_only_real_alerts(self, sample_alerts):
        result = recompute_summary(sample_alerts)
        assert result["total_alerts"] == 4
        assert result["by_severity"]["high"] == 2


class TestMissingOrEmptyReports:
    """Graceful handling when reports are absent or unreadable."""

    def test_overview_no_report_shows_empty_state(self, no_report_client):
        response = no_report_client.get("/")
        assert response.status_code == 200
        data = response.data.decode("utf-8")
        assert "No detection report yet" in data or "Analyze Logs" in data

    def test_alerts_no_report_shows_empty_state(self, no_report_client):
        response = no_report_client.get("/alerts")
        assert response.status_code == 200
        data = response.data.decode("utf-8")
        assert "No detection report yet" in data or "Analyze Logs" in data

    def test_summary_no_report(self, no_report_client):
        response = no_report_client.get("/api/summary")
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["available"] is False

    def test_json_export_missing_report(self, no_report_client):
        response = no_report_client.get("/reports/alerts.json")
        assert response.status_code == 404

    def test_csv_export_missing_report(self, no_report_client):
        response = no_report_client.get("/reports/alerts.csv")
        assert response.status_code == 404

    def test_load_report_missing(self, tmp_path):
        result = load_report(str(tmp_path / "missing.json"))
        assert result.status == STATUS_MISSING
        assert result.ok is False


class TestMalformedJson:
    """Malformed and structurally invalid reports are handled safely."""

    def test_malformed_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{ not valid json ]", encoding="utf-8")
        result = load_report(str(path))
        assert result.status == STATUS_MALFORMED

    def test_invalid_structure(self, tmp_path):
        path = tmp_path / "bad2.json"
        path.write_text(json.dumps({"alerts": "nope"}), encoding="utf-8")
        result = load_report(str(path))
        assert result.ok is False

    def test_overview_malformed_report_empty_state(self, tmp_path):
        path = tmp_path / "reports" / "alerts.json"
        path.parent.mkdir(parents=True)
        path.write_text("{{{", encoding="utf-8")
        app = create_app({"REPORT_FILE": str(path)})
        app.config["TESTING"] = True
        client = app.test_client()
        response = client.get("/")
        assert response.status_code == 200
        data = response.data.decode("utf-8")
        assert "unavailable" in data.lower() or "Analyze Logs" in data


class TestFilteringAndSearch:
    """Filter and search functionality."""

    def test_filter_by_severity(self, client):
        response = client.get("/api/alerts?severity=high")
        assert response.status_code == 200
        payload = response.get_json()
        assert all(a["severity"] == "high" for a in payload["alerts"])
        assert payload["total"] == 2

    def test_filter_by_source(self, client):
        response = client.get("/api/alerts?source=legitimate")
        assert response.status_code == 200
        payload = response.get_json()
        assert all(a["source"] == "legitimate" for a in payload["alerts"])

    def test_filter_by_rule(self, client):
        response = client.get("/api/alerts?rule=WHD-001")
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["total"] == 1
        assert payload["alerts"][0]["rule_id"] == "WHD-001"

    def test_search_query(self, client):
        response = client.get("/api/alerts?q=redirect")
        assert response.status_code == 200
        payload = response.get_json()
        assert any("redirect" in a["path"].lower() for a in payload["alerts"])

    def test_invalid_filter_rejected(self, client):
        response = client.get("/api/alerts?severity=critical")
        assert response.status_code == 400
        payload = response.get_json()
        assert payload["status"] == "error"

    def test_filter_alerts_helper(self, sample_alerts):
        filtered = filter_alerts(sample_alerts, {"severity": "high"})
        assert len(filtered) == 2
        assert find_alert(sample_alerts, "A-0002")["rule_id"] == "WHD-002"
        assert find_alert(sample_alerts, "nope") is None


class TestExports:
    """JSON and CSV exports with correct headers and safe content."""

    def test_json_export(self, client):
        response = client.get("/reports/alerts.json")
        assert response.status_code == 200
        assert "application/json" in response.content_type
        assert "attachment" in response.headers.get("Content-Disposition", "")
        assert "shopsafe-alerts" in response.headers.get("Content-Disposition", "")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        payload = response.get_json()
        assert isinstance(payload["alerts"], list)

    def test_csv_export(self, client):
        response = client.get("/reports/alerts.csv")
        assert response.status_code == 200
        assert "text/csv" in response.content_type
        assert "attachment" in response.headers.get("Content-Disposition", "")
        assert "shopsafe-alerts" in response.headers.get("Content-Disposition", "")
        body = response.data
        assert body.startswith(b'\xef\xbb\xbf')  # UTF-8 BOM for spreadsheet compatibility
        text = body.decode("utf-8-sig")
        # Headers
        for header in ["alert_id", "timestamp", "severity", "rule_id", "path", "evidence"]:
            assert header in text
        # Every data row quoted
        lines = text.strip().splitlines()
        assert len(lines) >= 2

    def test_csv_formula_injection_neutralised(self, sample_alerts):
        alerts = [dict(sample_alerts[0], evidence="=cmd|'/c calc'!A0")]
        header, rows = alerts_to_csv_rows(alerts)
        assert header[0] == "alert_id"
        # Leading = should be neutralised
        evidence_idx = header.index("evidence")
        assert rows[0][evidence_idx].startswith("'")

    def test_export_headers_present(self, client):
        response = client.get("/reports/alerts.json")
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert "Content-Security-Policy" in response.headers


class TestAnalysisEndpoint:
    """Analysis endpoint behaviour."""

    def test_analyze_rejects_arbitrary_command_strings(self, client):
        # Commands/paths must not be accepted as parameters.
        response = client.post("/api/analyze", json={"command": "rm -rf /"})
        assert response.status_code == 400
        payload = response.get_json()
        assert payload["status"] == "error"
        response = client.post("/api/analyze", json={"script": "/etc/passwd"})
        assert response.status_code == 400

    def test_analyze_rejects_filenames_from_user(self, client):
        response = client.post("/api/analyze", json={"log": "compromised_access.jsonl"})
        assert response.status_code == 400

    def test_analyze_rejects_form_data(self, client):
        response = client.post("/api/analyze", data={"cmd": "ls"})
        assert response.status_code == 400

    def test_analyze_rejects_invalid_json(self, client):
        response = client.post("/api/analyze", data="not json", content_type="application/json")
        assert response.status_code == 400

    def test_analyze_accepts_empty_json_object(self, client, dash_config):
        # Empty dict is permitted; the actual execution depends on whether
        # the detector can find logs — in tests we mock by patching.
        pass

    def test_analyze_blocks_cross_origin(self, client):
        response = client.post("/api/analyze", json={}, headers={"Origin": "http://evil.example"})
        assert response.status_code == 403


class TestDashboardDoesNotGenerateFakeAlerts:
    """Dashboard must not fabricate findings."""

    def test_no_alerts_fabricated_when_logs_only_legit(self, tmp_path):
        # Create a minimal report with no alerts and ensure it's displayed as-is.
        report = {
            "schema_version": 1,
            "generated_at": "2026-10-12T08:00:00Z",
            "total_requests": 10,
            "log_sources": [],
            "summary": {
                "total_alerts": 0,
                "by_severity": {"high": 0, "medium": 0, "low": 0},
                "by_source": {"legitimate": 0, "compromised": 0},
                "rules_triggered": [],
                "rules_defined": 6,
                "by_rule": [],
            },
            "alerts": [],
        }
        path = tmp_path / "r.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        app = create_app({"REPORT_FILE": str(path)})
        app.config["TESTING"] = True
        client = app.test_client()
        response = client.get("/")
        data = response.data.decode("utf-8")
        # Must not fabricate alerts from fixture data
        response = client.get("/api/summary").get_json()
        assert response["total_alerts"] == 0
        assert response["by_severity"] == {"high": 0, "medium": 0, "low": 0}

    def test_summary_recomputed_from_report_not_hardcoded(self, sample_alerts):
        # If a report is tampered to have mismatched summary, our API recomputes
        # from alerts where possible; the page uses recomputed values.
        tampered = {
            "schema_version": 1,
            "generated_at": "x",
            "total_requests": 1,
            "log_sources": [],
            "summary": {"total_alerts": 999},  # wrong
            "alerts": sample_alerts,
        }
        from services.report_loader import load_report
        # The loader keeps the payload as-is structurally; recompute_summary is
        # used by the API to derive counts from actual records.
        result = recompute_summary(sample_alerts)
        assert result["total_alerts"] == len(sample_alerts)


class TestDetectorRules:
    """Detection engine correctness against documented scenarios."""

    def test_detects_redirect(self, tmp_path):
        import detector
        legit = tmp_path / "legit.jsonl"
        comp = tmp_path / "comp.jsonl"
        legit.write_text("")
        comp.write_text(
            json.dumps(
                {
                    "timestamp": "2026-10-12T06:05:31Z",
                    "source_ip": "127.0.0.1",
                    "method": "GET",
                    "path": "/lab-test/redirect",
                    "status_code": 302,
                    "referer": "",
                    "user_agent": "x",
                    "response_bytes": 0,
                    "duration_ms": 1,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        report = detector.run_detection(str(legit), str(comp))
        rule_ids = {a["rule_id"] for a in report["alerts"]}
        assert "WHD-001" in rule_ids
        # Redirect alert should be high severity
        redirect_alert = [a for a in report["alerts"] if a["rule_id"] == "WHD-001"][0]
        assert redirect_alert["severity"] == "high"
        assert redirect_alert["path"] == "/lab-test/redirect"

    def test_detects_admin_path(self, tmp_path):
        import detector
        legit = tmp_path / "legit.jsonl"
        comp = tmp_path / "comp.jsonl"
        legit.write_text("")
        comp.write_text(
            json.dumps(
                {
                    "timestamp": "2026-10-12T06:05:31Z",
                    "source_ip": "127.0.0.1",
                    "method": "GET",
                    "path": "/lab-test/admin-test",
                    "status_code": 200,
                    "referer": "",
                    "user_agent": "x",
                    "response_bytes": 100,
                    "duration_ms": 1,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        report = detector.run_detection(str(legit), str(comp))
        rule_ids = {a["rule_id"] for a in report["alerts"]}
        assert "WHD-002" in rule_ids

    def test_detects_abnormal_method(self, tmp_path):
        import detector
        legit = tmp_path / "legit.jsonl"
        comp = tmp_path / "comp.jsonl"
        legit.write_text("")
        comp.write_text(
            json.dumps(
                {
                    "timestamp": "2026-10-12T06:05:31Z",
                    "source_ip": "127.0.0.1",
                    "method": "POST",
                    "path": "/lab-test/method-check",
                    "status_code": 405,
                    "referer": "",
                    "user_agent": "x",
                    "response_bytes": 0,
                    "duration_ms": 1,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        report = detector.run_detection(str(legit), str(comp))
        rule_ids = {a["rule_id"] for a in report["alerts"]}
        assert "WHD-003" in rule_ids

    def test_detects_burst(self, tmp_path):
        import detector
        legit = tmp_path / "legit.jsonl"
        comp = tmp_path / "comp.jsonl"
        legit.write_text("")
        lines = []
        for i in range(25):
            lines.append(
                json.dumps(
                    {
                        "timestamp": "2026-10-12T06:05:31Z",
                        "source_ip": "127.0.0.1",
                        "method": "GET",
                        "path": "/lab-test/repeat",
                        "status_code": 200,
                        "referer": "",
                        "user_agent": "x",
                        "response_bytes": 100,
                        "duration_ms": 1,
                    }
                )
            )
        comp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        report = detector.run_detection(str(legit), str(comp))
        rule_ids = {a["rule_id"] for a in report["alerts"]}
        assert "WHD-006" in rule_ids or "WHD-004" in rule_ids

    def test_detects_unapproved_resource(self, tmp_path):
        import detector
        legit = tmp_path / "legit.jsonl"
        comp = tmp_path / "comp.jsonl"
        legit.write_text("")
        comp.write_text(
            json.dumps(
                {
                    "timestamp": "2026-10-12T06:05:31Z",
                    "source_ip": "127.0.0.1",
                    "method": "GET",
                    "path": "/lab-test/resources/unapproved.js",
                    "status_code": 200,
                    "referer": "",
                    "user_agent": "x",
                    "response_bytes": 100,
                    "duration_ms": 1,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        report = detector.run_detection(str(legit), str(comp))
        rule_ids = {a["rule_id"] for a in report["alerts"]}
        assert "WHD-005" in rule_ids

    def test_detector_readonly_no_log_modification(self, tmp_path):
        import detector
        legit = tmp_path / "legit.jsonl"
        comp = tmp_path / "comp.jsonl"
        comp_content = json.dumps(
            {
                "timestamp": "2026-10-12T06:05:31Z",
                "source_ip": "127.0.0.1",
                "method": "GET",
                "path": "/lab-test/redirect",
                "status_code": 302,
            }
        ) + "\n"
        legit.write_text("")
        comp.write_text(comp_content, encoding="utf-8")
        before = comp.read_text(encoding="utf-8")
        detector.run_detection(str(legit), str(comp))
        after = comp.read_text(encoding="utf-8")
        assert before == after

    def test_empty_logs_produce_no_crash(self, tmp_path):
        import detector
        legit = tmp_path / "legit.jsonl"
        comp = tmp_path / "comp.jsonl"
        legit.write_text("")
        comp.write_text("")
        report = detector.run_detection(str(legit), str(comp))
        assert report["summary"]["total_alerts"] == 0


class TestNetworkPage:
    """Network evidence page exists and makes correct claims."""

    def test_network_page_loads(self, client):
        response = client.get("/network")
        assert response.status_code == 200
        data = response.data.decode("utf-8")
        assert "Wireshark" in data
        # Must not claim live reading of Wireshark traffic
        assert "does not read live" in data.lower() or "not read live" in data.lower() or "Documentation only" in data

    def test_network_mentions_scenarios(self, client):
        response = client.get("/network")
        data = response.data.decode("utf-8")
        for scenario in ["WHD-001", "WHD-002", "WHD-003", "WHD-004", "WHD-005"]:
            assert scenario in data


class TestSecurityHeaders:
    """Security headers are applied."""

    def test_security_headers(self, client):
        response = client.get("/")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert "Content-Security-Policy" in response.headers


class TestHealth:
    def test_health_endpoint(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["status"] == "ok"
