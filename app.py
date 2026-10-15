"""ShopSafe security monitoring dashboard.

A read-only monitoring interface for the Watering-Hole Detection Laboratory.
It reads the JSON report produced by ``detector.py`` and the metadata of the
two laboratory websites; it never writes to the access logs and never
fabricates findings. Bound to 127.0.0.1 by default.

Run:

    python app.py
    # -> http://127.0.0.1:8000
"""

import csv
import io
import os
from datetime import datetime, timezone

from flask import (
    Flask,
    abort,
    jsonify,
    render_template,
    request,
    send_file,
)

from config import load_config
from services import analysis
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

SEVERITIES = ("high", "medium", "low")
MAX_QUERY_LENGTH = 200

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'"
    ),
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


def create_app(config_overrides=None):
    app = Flask(__name__)
    config = load_config()
    if config_overrides:
        config.update(config_overrides)
    app.config["DASH"] = config
    app.config["JSON_SORT_KEYS"] = False

    def cfg(key):
        return app.config["DASH"][key]

    def site_meta(source_id):
        return config["SITES"].get(source_id, {"label": source_id, "url": "", "port": ""})

    def build_summary_payload(report_result):
        """Summary computed strictly from the loaded report records."""
        if not report_result.ok:
            return {
                "available": False,
                "status": report_result.status,
                "generated_at": None,
                "total_requests": 0,
                "total_alerts": 0,
                "by_severity": {s: 0 for s in SEVERITIES},
                "by_source": {"legitimate": 0, "compromised": 0},
                "rules_triggered": [],
                "rules_defined": 0,
                "by_rule": [],
                "log_sources": [],
            }
        data = report_result.data
        alerts = data.get("alerts", [])
        recomputed = recompute_summary(alerts)
        log_sources = data.get("log_sources", [])
        return {
            "available": True,
            "status": "ok",
            "generated_at": data.get("generated_at"),
            "total_requests": data.get("total_requests", 0),
            "total_alerts": recomputed["total_alerts"],
            "by_severity": recomputed["by_severity"],
            "by_source": recomputed["by_source"],
            "rules_triggered": recomputed["rules_triggered"],
            "rules_defined": data.get("summary", {}).get("rules_defined", 0),
            "by_rule": recomputed["by_rule"],
            "log_sources": log_sources,
        }

    @app.after_request
    def apply_security_headers(response):
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if request.path.startswith("/api/") or request.path.startswith("/reports/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.before_request
    def protect_state_changing_requests():
        """Same-origin protection for state-changing endpoints.

        Browsers always attach Origin (or Sec-Fetch-Site) to cross-origin
        POSTs; either mismatching value is rejected.
        """
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return None
        origin = request.headers.get("Origin")
        if origin:
            origin_base = origin.rstrip("/")
            host_base = request.host_url.rstrip("/")
            if origin_base != host_base:
                app.logger.warning("Rejected cross-origin state change (origin mismatch).")
                return jsonify({"status": "error", "message": "Cross-origin request rejected."}), 403
        site = request.headers.get("Sec-Fetch-Site")
        if site and site not in ("same-origin", "none"):
            return jsonify({"status": "error", "message": "Cross-origin request rejected."}), 403
        return None

    @app.context_processor
    def inject_globals():
        report_result = load_report(cfg("REPORT_FILE"))
        return {
            "sites": config["SITES"],
            "report_available": report_result.ok,
            "report_generated_at": (
                report_result.data.get("generated_at") if report_result.ok else None
            ),
            "report_status": report_result.status,
            "now_year": datetime.now(timezone.utc).year,
        }

    # ------------------------------------------------------------------ pages

    @app.route("/")
    def overview():
        report_result = load_report(cfg("REPORT_FILE"))
        summary = build_summary_payload(report_result)
        recent_alerts = []
        by_rule = []
        if report_result.ok:
            alerts = sorted(
                report_result.data.get("alerts", []),
                key=lambda a: str(a.get("timestamp", "")),
                reverse=True,
            )
            recent_alerts = alerts[:8]
            by_rule = summary["by_rule"]
        return render_template(
            "overview.html",
            page_title="Overview",
            summary=summary,
            recent_alerts=recent_alerts,
            by_rule=by_rule,
        )

    @app.route("/websites")
    def websites():
        report_result = load_report(cfg("REPORT_FILE"))
        summary = build_summary_payload(report_result)
        source_stats = {}
        for source_id in ("legitimate", "compromised"):
            log_entry = next(
                (s for s in summary["log_sources"] if s.get("id") == source_id), None
            )
            source_stats[source_id] = {
                "requests": log_entry["records"] if log_entry else 0,
                "parse_errors": log_entry["parse_errors"] if log_entry else 0,
                "log_present": log_entry["present"] if log_entry else False,
                "alerts": summary["by_source"].get(source_id, 0),
            }
        return render_template(
            "websites.html",
            page_title="Website Monitoring",
            summary=summary,
            source_stats=source_stats,
        )

    @app.route("/alerts")
    def alerts_page():
        report_result = load_report(cfg("REPORT_FILE"))
        filters, _ = normalize_filters(
            request.args.get("severity"),
            request.args.get("source"),
            request.args.get("rule"),
            strict=False,
        )
        query = (request.args.get("q") or "").strip()[:MAX_QUERY_LENGTH]
        alerts = []
        rule_options = []
        if report_result.ok:
            alerts_all = report_result.data.get("alerts", [])
            rule_options = sorted({a.get("rule_id") for a in alerts_all if a.get("rule_id")})
            alerts = filter_alerts(alerts_all, filters, query or None)
            alerts = sorted(
                alerts, key=lambda a: str(a.get("timestamp", "")), reverse=True
            )
        return render_template(
            "alerts.html",
            page_title="Alerts",
            report_result=report_result,
            alerts=alerts,
            filters=filters,
            query=query,
            rule_options=rule_options,
            severities=SEVERITIES,
            filtered=bool(filters or query),
        )

    @app.route("/network")
    def network():
        return render_template("network.html", page_title="Network Evidence")

    # -------------------------------------------------------------------- api

    @app.route("/api/summary")
    def api_summary():
        report_result = load_report(cfg("REPORT_FILE"))
        payload = build_summary_payload(report_result)
        status_code = 200
        if report_result.status == STATUS_MALFORMED:
            status_code = 503
            payload["error"] = "The detection report could not be parsed."
        elif report_result.status == "invalid":
            status_code = 503
            payload["error"] = "The detection report has an unexpected structure."
        return jsonify(payload), status_code

    @app.route("/api/alerts")
    def api_alerts():
        report_result = load_report(cfg("REPORT_FILE"))
        if not report_result.ok:
            payload = {"available": False, "status": report_result.status, "alerts": []}
            status_code = 200
            if report_result.status == STATUS_MALFORMED:
                status_code = 503
                payload["error"] = "The detection report could not be parsed."
            return jsonify(payload), status_code

        alerts_all = report_result.data.get("alerts", [])
        valid_rules = {a.get("rule_id") for a in alerts_all if a.get("rule_id")}
        filters, error = normalize_filters(
            request.args.get("severity"),
            request.args.get("source"),
            request.args.get("rule"),
            valid_rules=valid_rules,
            strict=True,
        )
        if error:
            return jsonify({"status": "error", "message": error}), 400

        query = (request.args.get("q") or "").strip()
        if len(query) > MAX_QUERY_LENGTH:
            return jsonify({"status": "error", "message": "Search query is too long."}), 400

        matched = filter_alerts(alerts_all, filters, query or None)
        matched = sorted(matched, key=lambda a: str(a.get("timestamp", "")), reverse=True)
        return jsonify(
            {
                "available": True,
                "status": "ok",
                "generated_at": report_result.data.get("generated_at"),
                "total": len(matched),
                "filters": filters,
                "query": query,
                "alerts": matched,
            }
        )

    @app.route("/api/alerts/<alert_id>")
    def api_alert_detail(alert_id):
        if not alert_id or len(alert_id) > 40:
            abort(404)
        report_result = load_report(cfg("REPORT_FILE"))
        if not report_result.ok:
            return jsonify({"status": "error", "message": "No report is available."}), 404
        alert = find_alert(report_result.data.get("alerts", []), alert_id)
        if alert is None:
            abort(404)
        return jsonify({"status": "ok", "alert": alert})

    @app.route("/api/analyze", methods=["POST"])
    def api_analyze():
        # The endpoint intentionally accepts no parameters. Any JSON body
        # keys are rejected so that no client input can influence the run.
        if request.files or request.form:
            return jsonify(
                {"status": "error", "message": "Unsupported input: this endpoint takes no parameters."}
            ), 400
        if request.data:
            if not request.is_json:
                return jsonify(
                    {"status": "error", "message": "Content-Type must be application/json."}
                ), 400
            try:
                body = request.get_json(silent=False)
            except Exception:
                return jsonify({"status": "error", "message": "Request body must be valid JSON."}), 400
            if body is None:
                return jsonify({"status": "error", "message": "Request body must be valid JSON."}), 400
            if not isinstance(body, dict) or body:
                return jsonify(
                    {
                        "status": "error",
                        "message": "Unsupported input: this endpoint takes no parameters.",
                    }
                ), 400

        try:
            result = analysis.run_analysis(config)
        except analysis.AnalysisBusyError:
            return jsonify(
                {"status": "busy", "message": "An analysis run is already in progress."}
            ), 409
        except analysis.AnalysisFailedError as exc:
            return jsonify({"status": "error", "message": str(exc)}), 500

        report_result = load_report(cfg("REPORT_FILE"))
        result["report"] = build_summary_payload(report_result)
        return jsonify(result), 200

    # --------------------------------------------------------------- reports

    @app.route("/reports/alerts.json")
    def report_json():
        path = cfg("REPORT_FILE")
        report_result = load_report(path)
        if not report_result.ok:
            if report_result.status == STATUS_MISSING:
                return jsonify(
                    {"status": "error", "message": "No detection report has been generated yet."}
                ), 404
            return jsonify(
                {"status": "error", "message": "The detection report is currently unreadable."}
            ), 503
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return send_file(
            path,
            mimetype="application/json",
            as_attachment=True,
            download_name="shopsafe-alerts-%s.json" % stamp,
        )

    @app.route("/reports/alerts.csv")
    def report_csv():
        report_result = load_report(cfg("REPORT_FILE"))
        if not report_result.ok:
            if report_result.status == STATUS_MISSING:
                return jsonify(
                    {"status": "error", "message": "No detection report has been generated yet."}
                ), 404
            return jsonify(
                {"status": "error", "message": "The detection report is currently unreadable."}
            ), 503

        header, rows = alerts_to_csv_rows(report_result.data.get("alerts", []))
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer, quoting=csv.QUOTE_ALL)
        writer.writerow(header)
        writer.writerows(rows)
        data = buffer.getvalue().encode("utf-8-sig")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return send_file(
            io.BytesIO(data),
            mimetype="text/csv",
            as_attachment=True,
            download_name="shopsafe-alerts-%s.csv" % stamp,
        )

    @app.route("/health")
    def health():
        report_result = load_report(cfg("REPORT_FILE"))
        return jsonify(
            {
                "status": "ok",
                "report": report_result.status,
                "analysis_running": analysis.is_running(),
            }
        )

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/") or request.path.startswith("/reports/"):
            return jsonify({"status": "error", "message": "Not found."}), 404
        return render_template("error.html", page_title="Not Found", error_code=404), 404

    @app.errorhandler(500)
    def internal_error(e):
        if request.path.startswith("/api/") or request.path.startswith("/reports/"):
            return jsonify({"status": "error", "message": "Internal server error."}), 500
        return render_template("error.html", page_title="Server Error", error_code=500), 500

    return app


app = create_app()


if __name__ == "__main__":
    dash_config = app.config["DASH"]
    app.run(
        host=dash_config["DASHBOARD_HOST"],
        port=dash_config["DASHBOARD_PORT"],
        debug=False,
    )
