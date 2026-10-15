import json
import os
import sys

import pytest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import create_app  # noqa: E402

DETECTOR_SCRIPT = os.path.join(BASE_DIR, "detector.py")


@pytest.fixture
def sample_alerts():
    return [
        {
            "id": "A-0001",
            "timestamp": "2026-10-12T06:05:31Z",
            "source": "compromised",
            "source_label": "Simulated Compromised ShopSafe (port 5001)",
            "rule_id": "WHD-001",
            "rule_name": "Unexpected Redirect",
            "severity": "high",
            "path": "/lab-test/redirect",
            "method": "GET",
            "status_code": 302,
            "source_ip": "127.0.0.1",
            "evidence": "HTTP 302 redirect observed on laboratory redirect path /lab-test/redirect.",
            "recommendation": "Verify the redirect is intentional.",
        },
        {
            "id": "A-0002",
            "timestamp": "2026-10-12T06:05:31Z",
            "source": "compromised",
            "source_label": "Simulated Compromised ShopSafe (port 5001)",
            "rule_id": "WHD-002",
            "rule_name": "Suspicious Administration Path",
            "severity": "high",
            "path": "/lab-test/admin-test",
            "method": "GET",
            "status_code": 200,
            "source_ip": "127.0.0.1",
            "evidence": "Request path matched suspicious administration pattern '/lab-test/admin-test'.",
            "recommendation": "Confirm whether administrative access is expected.",
        },
        {
            "id": "A-0003",
            "timestamp": "2026-10-12T06:06:00Z",
            "source": "compromised",
            "source_label": "Simulated Compromised ShopSafe (port 5001)",
            "rule_id": "WHD-003",
            "rule_name": "Abnormal HTTP Method",
            "severity": "medium",
            "path": "/lab-test/method-check",
            "method": "POST",
            "status_code": 405,
            "source_ip": "127.0.0.1",
            "evidence": "Abnormal request: unsupported HTTP method POST and HTTP 405 Method Not Allowed.",
            "recommendation": "Restrict allowed HTTP methods.",
        },
        {
            "id": "A-0004",
            "timestamp": "2026-10-11T18:00:00Z",
            "source": "legitimate",
            "source_label": "Legitimate ShopSafe (port 5000)",
            "rule_id": "WHD-006",
            "rule_name": "Lab Test Endpoint Traffic",
            "severity": "low",
            "path": "/lab-test/repeat",
            "method": "GET",
            "status_code": 200,
            "source_ip": "127.0.0.1",
            "evidence": "Request to laboratory test endpoint /lab-test/repeat without a higher-severity indicator.",
            "recommendation": "Informational.",
        },
    ]


@pytest.fixture
def sample_report(sample_alerts):
    return {
        "schema_version": 1,
        "engine": "shopsafe-watering-hole-detection",
        "engine_version": "1.0.0",
        "generated_at": "2026-10-12T07:00:00Z",
        "lab_notice": "Authorized local laboratory report.",
        "log_sources": [
            {"id": "legitimate", "label": "Legitimate ShopSafe (port 5000)", "records": 131, "parse_errors": 0, "present": True},
            {"id": "compromised", "label": "Simulated Compromised ShopSafe (port 5001)", "records": 64, "parse_errors": 0, "present": True},
        ],
        "total_requests": 195,
        "summary": {
            "total_alerts": 4,
            "by_severity": {"high": 2, "medium": 1, "low": 1},
            "by_source": {"legitimate": 1, "compromised": 3},
            "rules_triggered": ["WHD-001", "WHD-002", "WHD-003", "WHD-006"],
            "rules_defined": 6,
            "by_rule": [],
        },
        "alerts": sample_alerts,
    }


@pytest.fixture
def report_path(tmp_path, sample_report):
    path = tmp_path / "reports" / "alerts.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sample_report), encoding="utf-8")
    return str(path)


@pytest.fixture
def dash_config(tmp_path, report_path):
    return {
        "REPORT_FILE": report_path,
        "LEGITIMATE_LOG": str(tmp_path / "legitimate_access.jsonl"),
        "COMPROMISED_LOG": str(tmp_path / "compromised_access.jsonl"),
        "DETECTOR_SCRIPT": DETECTOR_SCRIPT,
        "ANALYZE_TIMEOUT_SECONDS": 60,
    }


@pytest.fixture
def app(dash_config):
    application = create_app(dash_config)
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def no_report_config(tmp_path):
    return {
        "REPORT_FILE": str(tmp_path / "does-not-exist" / "alerts.json"),
        "LEGITIMATE_LOG": str(tmp_path / "legitimate_access.jsonl"),
        "COMPROMISED_LOG": str(tmp_path / "compromised_access.jsonl"),
        "DETECTOR_SCRIPT": DETECTOR_SCRIPT,
        "ANALYZE_TIMEOUT_SECONDS": 60,
    }


@pytest.fixture
def no_report_app(no_report_config):
    application = create_app(no_report_config)
    application.config["TESTING"] = True
    return application


@pytest.fixture
def no_report_client(no_report_app):
    return no_report_app.test_client()
