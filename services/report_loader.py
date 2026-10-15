"""Loading and validation of the detection report produced by detector.py."""

import json
import os
import re

SEVERITIES = ("high", "medium", "low")
SOURCES = ("legitimate", "compromised")
RULE_ID_RE = re.compile(r"^WHD-\d{3}$")

STATUS_OK = "ok"
STATUS_MISSING = "missing"
STATUS_MALFORMED = "malformed"
STATUS_INVALID = "invalid"


def _empty_summary():
    return {
        "total_alerts": 0,
        "by_severity": {"high": 0, "medium": 0, "low": 0},
        "by_source": {"legitimate": 0, "compromised": 0},
        "rules_triggered": [],
        "by_rule": [],
    }


class ReportResult:
    """Outcome of a report load: status, data, and safe error flag."""

    def __init__(self, status, data=None, error=None):
        self.status = status
        self.data = data
        self.error = error

    @property
    def ok(self):
        return self.status == STATUS_OK and isinstance(self.data, dict)


def _validate_structure(payload):
    """Return an error string when the payload is not a usable report."""
    if not isinstance(payload, dict):
        return "Report root must be a JSON object."
    alerts = payload.get("alerts")
    if not isinstance(alerts, list):
        return "Report field 'alerts' must be a list."
    for alert in alerts:
        if not isinstance(alert, dict):
            return "Every alert must be a JSON object."
        if not isinstance(alert.get("rule_id"), str):
            return "Every alert must include a string 'rule_id'."
        if alert.get("severity") not in SEVERITIES:
            return "Every alert must include a valid severity."
    if payload.get("summary") is not None and not isinstance(payload.get("summary"), dict):
        return "Report field 'summary' must be an object."
    return None


def load_report(path):
    """Load and validate the report at ``path``.

    Never raises for ordinary problems; returns a ReportResult whose status is
    one of ok / missing / malformed / invalid. Filesystem paths and exception
    details are intentionally not included in the result.
    """
    if not path or not os.path.isfile(path):
        return ReportResult(STATUS_MISSING, error="missing")

    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return ReportResult(STATUS_MALFORMED, error="malformed")

    structure_error = _validate_structure(payload)
    if structure_error:
        return ReportResult(STATUS_INVALID, error="invalid")

    payload.setdefault("summary", _empty_summary())
    payload.setdefault("alerts", [])
    payload.setdefault("log_sources", [])
    payload.setdefault("generated_at", None)
    payload.setdefault("total_requests", 0)
    payload["summary"].setdefault("by_severity", {"high": 0, "medium": 0, "low": 0})
    payload["summary"].setdefault("by_source", {"legitimate": 0, "compromised": 0})
    payload["summary"].setdefault("rules_triggered", [])
    payload["summary"].setdefault("by_rule", [])
    return ReportResult(STATUS_OK, data=payload)


def recompute_summary(alerts):
    """Derive summary counters strictly from the alert records."""
    by_severity = {"high": 0, "medium": 0, "low": 0}
    by_source = {"legitimate": 0, "compromised": 0}
    by_rule = {}
    for alert in alerts:
        severity = alert.get("severity")
        if severity in by_severity:
            by_severity[severity] += 1
        source = alert.get("source")
        if source in by_source:
            by_source[source] += 1
        rule_id = alert.get("rule_id")
        bucket = by_rule.setdefault(
            rule_id,
            {
                "rule_id": rule_id,
                "rule_name": alert.get("rule_name", ""),
                "severity": severity,
                "count": 0,
            },
        )
        bucket["count"] += 1
    by_rule_list = sorted(
        by_rule.values(), key=lambda r: (-r["count"], r.get("severity") or "", r.get("rule_id") or "")
    )
    return {
        "total_alerts": len(alerts),
        "by_severity": by_severity,
        "by_source": by_source,
        "rules_triggered": sorted({a.get("rule_id") for a in alerts if a.get("rule_id")}),
        "by_rule": by_rule_list,
    }


def normalize_filters(severity, source, rule, valid_rules=None, strict=False):
    """Normalize user-supplied filters.

    Returns (filters_dict, error_message). In strict mode (API), invalid
    values produce an error; in lenient mode (HTML pages) invalid values are
    dropped. ``valid_rules`` is the set of rule ids present in the loaded
    report; when provided, the rule filter must match one of them.
    """
    filters = {}
    error = None

    def _apply(key, value, valid, label):
        nonlocal error
        if value in (None, ""):
            return
        if value in valid:
            filters[key] = value
        elif strict:
            error = "Invalid %s filter." % label

    _apply("severity", severity, SEVERITIES, "severity")
    _apply("source", source, SOURCES, "website")

    if rule not in (None, ""):
        if not RULE_ID_RE.match(rule):
            if strict:
                error = error or "Invalid rule filter."
        elif valid_rules is not None and rule not in valid_rules and strict:
            error = error or "Invalid rule filter."
        elif valid_rules is None or rule in valid_rules:
            filters["rule"] = rule

    return filters, error


def filter_alerts(alerts, filters, query=None):
    """Filter alert records; returns a new list."""
    result = list(alerts)
    severity = filters.get("severity")
    source = filters.get("source")
    rule = filters.get("rule")
    if severity:
        result = [a for a in result if a.get("severity") == severity]
    if source:
        result = [a for a in result if a.get("source") == source]
    if rule:
        result = [a for a in result if a.get("rule_id") == rule]
    if query:
        needle = query.lower()
        result = [
            a
            for a in result
            if needle in str(a.get("path", "")).lower()
            or needle in str(a.get("evidence", "")).lower()
            or needle in str(a.get("rule_name", "")).lower()
            or needle in str(a.get("rule_id", "")).lower()
            or needle in str(a.get("source_ip", "")).lower()
            or needle in str(a.get("source_label", "")).lower()
            or needle in str(a.get("id", "")).lower()
        ]
    return result


def find_alert(alerts, alert_id):
    """Return the alert with the given id, or None."""
    if not alert_id:
        return None
    for alert in alerts:
        if alert.get("id") == alert_id:
            return alert
    return None


CSV_COLUMNS = [
    ("id", "alert_id"),
    ("timestamp", "timestamp"),
    ("source", "source"),
    ("source_label", "source_label"),
    ("rule_id", "rule_id"),
    ("rule_name", "rule_name"),
    ("severity", "severity"),
    ("method", "method"),
    ("status_code", "status_code"),
    ("source_ip", "source_ip"),
    ("path", "path"),
    ("evidence", "evidence"),
    ("recommendation", "recommendation"),
]


def csv_safe(value):
    """Neutralise spreadsheet formula injection in exported cells."""
    if value is None:
        return ""
    text = str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def alerts_to_csv_rows(alerts):
    """Return (header_row, data_rows) for the CSV export."""
    header = [header_name for _, header_name in CSV_COLUMNS]
    rows = []
    for alert in alerts:
        rows.append([csv_safe(alert.get(key, "")) for key, _ in CSV_COLUMNS])
    return header, rows
