#!/usr/bin/env python3
"""Watering-Hole Detection Engine for the ShopSafe laboratory.

Reads the two JSONL access logs produced by the laboratory websites
(legitimate ShopSafe on port 5000 and the simulated compromised ShopSafe on
port 5001), applies deterministic detection rules derived from the documented
laboratory scenarios, and writes a JSON findings report.

This engine is read-only with respect to the access logs. It never modifies
them and never fabricates records.

Detection rules (grounded in SafeShop-Compromised/README.md scenarios A-E):

  WHD-001  Unexpected Redirect              high     Scenario A
  WHD-002  Suspicious Administration Path   high     Scenario B
  WHD-003  Abnormal HTTP Method             medium   Scenario C
  WHD-004  Request Burst                    medium   Scenario D
  WHD-005  Unapproved Script Resource       medium   Scenario E
  WHD-006  Lab Test Endpoint Traffic        low      residual lab endpoint access

Usage (manual / laboratory use):

    python detector.py
    python detector.py --legit-log PATH --compromised-log PATH --output PATH

The dashboard invokes this script with no arguments; path overrides are only
taken from server-side environment configuration, never from HTTP input.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE_DIR, os.pardir))

ENV_LEGIT_LOG = "SAFESHOP_LEGITIMATE_LOG"
ENV_COMPROMISED_LOG = "SAFESHOP_COMPROMISED_LOG"
ENV_REPORT_FILE = "SAFESHOP_REPORT_FILE"

DEFAULT_LEGIT_LOG = os.path.join(REPO_ROOT, "SafeShop", "logs", "legitimate_access.jsonl")
DEFAULT_COMPROMISED_LOG = os.path.join(
    REPO_ROOT, "SafeShop-Compromised", "logs", "compromised_access.jsonl"
)
DEFAULT_REPORT_FILE = os.path.join(BASE_DIR, "reports", "alerts.json")

SCHEMA_VERSION = 1
ENGINE_NAME = "shopsafe-watering-hole-detection"
ENGINE_VERSION = "1.0.0"

SOURCE_LABELS = {
    "legitimate": "Legitimate ShopSafe (port 5000)",
    "compromised": "Simulated Compromised ShopSafe (port 5001)",
}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# Paths on the compromised site that perform a redirect to a fixed target.
REDIRECT_PATHS = {"/lab-test/redirect"}

SUSPICIOUS_PATH_PATTERNS = (
    "/lab-test/admin-test",
    "/admin",
    "/administrator",
    "/wp-admin",
    "/wp-login",
    "/phpmyadmin",
    "/.env",
    "/.git",
    "/console",
    "/manager/html",
)

UNAPPROVED_RESOURCE_MARKERS = (
    "/lab-test/resources/",
    "unapproved.js",
)

LAB_ENDPOINT_PREFIX = "/lab-test"

NORMAL_METHODS = {"GET", "HEAD", "OPTIONS"}

BURST_WINDOW_SECONDS = 10
BURST_THRESHOLD = 21  # alert when more than 20 requests hit the same path in the window

RULES = {
    "WHD-001": {
        "name": "Unexpected Redirect",
        "severity": "high",
        "recommendation": (
            "Verify the redirect is an intentional laboratory scenario. On a "
            "production site, investigate the redirect source and remove any "
            "injected redirect logic."
        ),
    },
    "WHD-002": {
        "name": "Suspicious Administration Path",
        "severity": "high",
        "recommendation": (
            "Confirm whether administrative access is expected from this "
            "source. Block or rate-limit probing of administration paths and "
            "review web-server logs for follow-on activity."
        ),
    },
    "WHD-003": {
        "name": "Abnormal HTTP Method",
        "severity": "medium",
        "recommendation": (
            "Restrict allowed HTTP methods to those required by the "
            "application and investigate the client issuing unsupported "
            "methods."
        ),
    },
    "WHD-004": {
        "name": "Request Burst",
        "severity": "medium",
        "recommendation": (
            "Review the traffic source for scripted enumeration or denial-of "
            "service behaviour and apply rate limiting if the burst is "
            "unauthorised."
        ),
    },
    "WHD-005": {
        "name": "Unapproved Script Resource",
        "severity": "medium",
        "recommendation": (
            "Remove any unapproved script resources from the site, rotate "
            "affected pages from a known-good copy, and inspect client-side "
            "code for unexpected inclusions."
        ),
    },
    "WHD-006": {
        "name": "Lab Test Endpoint Traffic",
        "severity": "low",
        "recommendation": (
            "Informational: requests to laboratory test endpoints that did "
            "not trigger a higher-severity rule. Confirm the traffic belongs "
            "to an authorised test run."
        ),
    },
}


def parse_timestamp(value):
    """Parse a UTC ISO 8601 timestamp; return None when unparseable."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_log_records(path, source):
    """Load JSONL access-log records.

    Returns (records, parse_errors, present). Malformed lines are counted,
    never raised. Missing files are reported as present=False.
    """
    records = []
    parse_errors = 0
    if not os.path.isfile(path):
        return records, parse_errors, False

    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            if not isinstance(obj, dict):
                parse_errors += 1
                continue
            ts = parse_timestamp(obj.get("timestamp"))
            if ts is None:
                parse_errors += 1
                continue
            obj["_timestamp"] = ts
            obj["_source"] = source
            records.append(obj)
    return records, parse_errors, True


def _path_of(record):
    path = record.get("path")
    return path if isinstance(path, str) else ""


def _method_of(record):
    method = record.get("method")
    return method.upper() if isinstance(method, str) else ""


def _status_of(record):
    status = record.get("status_code")
    if isinstance(status, int):
        return status
    if isinstance(status, str) and status.isdigit():
        return int(status)
    return None


def _source_ip_of(record):
    ip = record.get("source_ip")
    return ip if isinstance(ip, str) else ""


def _matches_any(path, patterns):
    lowered = path.lower()
    return any(pattern.lower() in lowered for pattern in patterns)


def _alert(record, rule_id, evidence):
    rule = RULES[rule_id]
    record["_alerted"] = True
    return {
        "timestamp": record["timestamp"] if isinstance(record.get("timestamp"), str) else "",
        "_ts": record["_timestamp"],
        "source": record["_source"],
        "source_label": SOURCE_LABELS.get(record["_source"], record["_source"]),
        "rule_id": rule_id,
        "rule_name": rule["name"],
        "severity": rule["severity"],
        "path": _path_of(record),
        "method": _method_of(record),
        "status_code": _status_of(record),
        "source_ip": _source_ip_of(record),
        "evidence": evidence,
        "recommendation": rule["recommendation"],
    }


def detect_redirects(records):
    alerts = []
    for record in records:
        path = _path_of(record)
        status = _status_of(record)
        if path in REDIRECT_PATHS and status is not None and 300 <= status < 400:
            alerts.append(
                _alert(
                    record,
                    "WHD-001",
                    "HTTP %d redirect observed on laboratory redirect path %s."
                    % (status, path),
                )
            )
    return alerts


def detect_suspicious_paths(records):
    alerts = []
    for record in records:
        path = _path_of(record)
        if not path:
            continue
        for pattern in SUSPICIOUS_PATH_PATTERNS:
            if pattern.lower() in path.lower():
                alerts.append(
                    _alert(
                        record,
                        "WHD-002",
                        "Request path matched suspicious administration pattern '%s'."
                        % pattern,
                    )
                )
                break
    return alerts


def detect_abnormal_methods(records):
    alerts = []
    for record in records:
        method = _method_of(record)
        status = _status_of(record)
        if not method:
            continue
        reasons = []
        if method not in NORMAL_METHODS:
            reasons.append("unsupported HTTP method %s" % method)
        if status == 405:
            reasons.append("HTTP 405 Method Not Allowed")
        if reasons:
            alerts.append(
                _alert(record, "WHD-003", "Abnormal request: %s." % " and ".join(reasons))
            )
    return alerts


def detect_bursts(records, window_seconds=BURST_WINDOW_SECONDS, threshold=BURST_THRESHOLD):
    """One alert per (source_ip, path) cluster exceeding the threshold."""
    grouped = {}
    for record in records:
        key = (_source_ip_of(record), _path_of(record))
        grouped.setdefault(key, []).append(record)

    alerts = []
    seen_clusters = set()
    for (ip, path), items in grouped.items():
        if not path:
            continue
        items = sorted(items, key=lambda r: r["_timestamp"])
        for i in range(len(items)):
            cluster = []
            for j in range(i, len(items)):
                if (items[j]["_timestamp"] - items[i]["_timestamp"]).total_seconds() <= window_seconds:
                    cluster.append(items[j])
                else:
                    break
            if len(cluster) >= threshold:
                cluster_key = (ip, path, id(cluster[0]), len(cluster))
                if cluster_key in seen_clusters:
                    break
                seen_clusters.add(cluster_key)
                alerts.append(_burst_alert(cluster, ip, path, window_seconds, threshold))
                break
    return alerts


def _burst_alert(cluster, ip, path, window_seconds, threshold):
    first = cluster[0]
    for record in cluster:
        record["_alerted"] = True
    evidence = (
        "%d requests to '%s' from %s within a %d-second window "
        "(threshold: %d requests)."
        % (len(cluster), path, ip or "unknown source", window_seconds, threshold)
    )
    alert = _alert(first, "WHD-004", evidence)
    alert["request_count"] = len(cluster)
    return alert


def detect_unapproved_resources(records):
    alerts = []
    for record in records:
        path = _path_of(record)
        if not path:
            continue
        matched = None
        for marker in UNAPPROVED_RESOURCE_MARKERS:
            if marker.lower() in path.lower():
                matched = marker
                break
        if matched:
            alerts.append(
                _alert(
                    record,
                    "WHD-005",
                    "Resource path matched unapproved-resource marker '%s'." % matched,
                )
            )
    return alerts


def detect_lab_endpoint_traffic(records):
    """Low-severity informational rule for residual /lab-test/* access.

    Records already flagged by a higher-severity rule are skipped via the
    ``_alerted`` marker set by :func:`_alert`.
    """
    alerts = []
    for record in records:
        path = _path_of(record)
        if not path.startswith(LAB_ENDPOINT_PREFIX):
            continue
        if record.get("_alerted"):
            continue
        alerts.append(
            _alert(
                record,
                "WHD-006",
                "Request to laboratory test endpoint %s without a "
                "higher-severity indicator." % path,
            )
        )
    return alerts


def analyze_records(records):
    """Apply all detection rules; returns a list of alert dicts."""
    alerts = []
    alerts.extend(detect_redirects(records))
    alerts.extend(detect_suspicious_paths(records))
    alerts.extend(detect_abnormal_methods(records))
    alerts.extend(detect_bursts(records))
    alerts.extend(detect_unapproved_resources(records))

    # Informational rule covers residual /lab-test/* access that did not
    # already trigger a higher-severity rule on the same record.
    alerts.extend(detect_lab_endpoint_traffic(records))

    alerts.sort(key=lambda a: (a["_ts"], SEVERITY_ORDER.get(a["severity"], 9), a["rule_id"]))
    for index, alert in enumerate(alerts, start=1):
        alert["id"] = "A-%04d" % index
        alert.pop("_ts", None)
    return alerts


def build_report(sources):
    """Assemble the full report structure.

    sources: list of dicts with keys id, label, records, parse_errors, present.
    """
    all_records = []
    log_sources = []
    for entry in sources:
        all_records.extend(entry["records"])
        log_sources.append(
            {
                "id": entry["id"],
                "label": SOURCE_LABELS.get(entry["id"], entry["label"]),
                "records": len(entry["records"]),
                "parse_errors": entry["parse_errors"],
                "present": entry["present"],
            }
        )

    alerts = analyze_records(all_records)

    by_severity = {"high": 0, "medium": 0, "low": 0}
    by_source = {"legitimate": 0, "compromised": 0}
    by_rule = {}
    for alert in alerts:
        by_severity[alert["severity"]] = by_severity.get(alert["severity"], 0) + 1
        by_source[alert["source"]] = by_source.get(alert["source"], 0) + 1
        bucket = by_rule.setdefault(
            alert["rule_id"],
            {
                "rule_id": alert["rule_id"],
                "rule_name": alert["rule_name"],
                "severity": alert["severity"],
                "count": 0,
            },
        )
        bucket["count"] += 1

    by_rule_list = sorted(
        by_rule.values(),
        key=lambda r: (-r["count"], SEVERITY_ORDER.get(r["severity"], 9), r["rule_id"]),
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "engine": ENGINE_NAME,
        "engine_version": ENGINE_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lab_notice": (
            "Authorized local laboratory report. All figures are derived from "
            "the JSONL access logs of the two local ShopSafe applications."
        ),
        "log_sources": log_sources,
        "total_requests": sum(len(entry["records"]) for entry in sources),
        "summary": {
            "total_alerts": len(alerts),
            "by_severity": by_severity,
            "by_source": by_source,
            "rules_triggered": sorted({a["rule_id"] for a in alerts}),
            "rules_defined": len(RULES),
            "by_rule": by_rule_list,
        },
        "alerts": alerts,
    }


def run_detection(legit_log_path, compromised_log_path):
    """Run detection over both logs and return the report dict."""
    sources = []
    for source_id, path in (
        ("legitimate", legit_log_path),
        ("compromised", compromised_log_path),
    ):
        records, parse_errors, present = load_log_records(path, source_id)
        sources.append(
            {
                "id": source_id,
                "label": SOURCE_LABELS[source_id],
                "records": records,
                "parse_errors": parse_errors,
                "present": present,
            }
        )
    return build_report(sources)


def write_report(report, output_path):
    """Atomically write the report JSON to output_path."""
    directory = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(directory, exist_ok=True)
    tmp_path = output_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    os.replace(tmp_path, output_path)


def main(argv=None):
    parser = argparse.ArgumentParser(description="ShopSafe watering-hole detection engine")
    parser.add_argument(
        "--legit-log",
        default=os.environ.get(ENV_LEGIT_LOG, DEFAULT_LEGIT_LOG),
        help="Path to the legitimate access log (JSONL).",
    )
    parser.add_argument(
        "--compromised-log",
        default=os.environ.get(ENV_COMPROMISED_LOG, DEFAULT_COMPROMISED_LOG),
        help="Path to the compromised access log (JSONL).",
    )
    parser.add_argument(
        "--output",
        default=os.environ.get(ENV_REPORT_FILE, DEFAULT_REPORT_FILE),
        help="Path to the JSON report to write.",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress stdout summary.")
    args = parser.parse_args(argv)

    try:
        report = run_detection(args.legit_log, args.compromised_log)
        write_report(report, args.output)
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        sys.stderr.write("detection failed: %s\n" % type(exc).__name__)
        return 2

    if not args.quiet:
        summary = report["summary"]
        sys.stdout.write(
            json.dumps(
                {
                    "status": "ok",
                    "total_requests": report["total_requests"],
                    "total_alerts": summary["total_alerts"],
                    "by_severity": summary["by_severity"],
                    "generated_at": report["generated_at"],
                }
            )
            + "\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
