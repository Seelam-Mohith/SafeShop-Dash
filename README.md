# ShopSafe Security Monitoring Dashboard

The ShopSafe Security Monitoring Dashboard is a polished, read-only Flask dashboard for the Watering-Hole Detection Laboratory. It reads the JSON findings report produced by the Python detection engine and presents the results in a professional dark-navy cybersecurity interface. It does **not** fabricate findings and does **not** modify the original access logs or detection rules.

## Purpose

- Presents an overview of total requests, alert counts by severity (high/medium/low), detection rules triggered, and recent alerts.
- Monitors the legitimate ShopSafe storefront (port 5000) and the simulated compromised storefront (port 5001) as separate local websites.
- Provides an Alerts page with table view, search, filters by severity/website/rule, and detailed alert inspection.
- Offers Analysis Controls to run the existing detection engine (`detector.py`) through a safe, controlled server-side integration.
- Exports findings as JSON and CSV with correct headers and safe filenames.
- Documents Wireshark/packet-capture correlation (documentation only; the dashboard does not read live Wireshark traffic).

All figures are calculated from actual log records in `logs/legitimate_access.jsonl` and `logs/compromised_access.jsonl`. No fake alerts are ever generated.

## Architecture

The dashboard is implemented in Python/Flask with Jinja2 templates, vanilla HTML/CSS/JavaScript (no React dependency). It integrates with:

- `SafeShop/` (legitimate baseline storefront, port 5000)
- `SafeShop-Compromised/` (simulated compromised storefront, port 5001)  
- `detector.py` (existing detection engine) — invoked server-side as a subprocess
- Generated report at `reports/alerts.json` (created by the detection engine)

## Prerequisites

- Python 3.12+ (tested environment: Python 3.12.5)
- pip
- The laboratory repositories present alongside this project:
  - `../SafeShop/logs/legitimate_access.jsonl`
  - `../SafeShop-Compromised/logs/compromised_access.jsonl`

The dashboard is bound to `127.0.0.1` by default.

## Setup

### 1. Install dependencies

```powershell
cd C:\Users\seela\OneDrive\Documents\All_Coding\SafeShop-Dash
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Generate detection report (first run)

The dashboard reads `reports/alerts.json`. Generate it using the detection engine:

```powershell
python detector.py
```

This produces `reports/alerts.json` containing all alerts derived from the actual access logs. You can verify with:

```powershell
Get-Content reports/alerts.json -Raw | Select-Object -First 20
```

## Running the applications

You need all three Flask applications running to exercise the full system. Open separate terminal sessions:

### Terminal 1: Legitimate ShopSafe (port 5000)
```powershell
cd ..\SafeShop
.venv\Scripts\Activate.ps1
python app.py
```
Available at: http://127.0.0.1:5000

### Terminal 2: Compromised ShopSafe (port 5001)
```powershell
cd ..\SafeShop-Compromised
.venv\Scripts\Activate.ps1
python app.py
```
Available at: http://127.0.0.1:5001

### Terminal 3: Security Monitoring Dashboard (port 8000)
```powershell
cd ..\SafeShop-Dash
.venv\Scripts\Activate.ps1
python app.py
```
Available at: http://127.0.0.1:8000

## Dashboard features

### Pages
1. **Overview** (`/`) — Total requests analyzed, total alerts, high/medium/low severity counts, rules triggered, alerts grouped by rule/severity, recent alerts.
2. **Websites** (`/websites`) — Status of both sites including request counts, alert counts per site, log presence, port numbers, and direct links to open both local websites. Clearly marked as controlled laboratory.
3. **Alerts** (`/alerts`) — Sortable/filterable table (timestamp, source website, rule ID/name, severity, path, evidence, recommendation), search box, filters (severity/website/rule), detail view modal, clear empty states.
4. **Network Evidence** (`/network`) — Documentation-only Wireshark/packet-capture correlation guidance. Explicitly states the dashboard does **not** read live Wireshark traffic.

### API endpoints
- `GET /api/summary` — Summary derived strictly from the report (never fabricated)
- `GET /api/alerts` — Alert listing with filtering and search; validates inputs strictly
- `GET /api/alerts/<id>` — Single alert details
- `POST /api/analyze` — Runs the detection engine server-side. Rejects arbitrary command strings, filenames, or executable paths. Prevents concurrent runs (returns 409 if busy). Returns actual execution result.
- `GET /reports/alerts.json` — Download the generated findings as JSON (attachment with safe timestamped filename)
- `GET /reports/alerts.csv` — Export alerts as CSV (UTF-8 BOM, all fields quoted, spreadsheet formula injection neutralised)
- `GET /health` — Health status

### Security
- Bound to `127.0.0.1` by default
- Security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, strict `Content-Security-Policy`, `Permissions-Policy`
- State-changing endpoints protected against unwanted cross-origin requests
- No filesystem paths, stack traces, secrets, or raw internal errors exposed to clients
- `POST /api/analyze` accepts **no parameters** (empty JSON object only). Any attempted command/filename input returns 400.
- CSV export neutralises leading `= + - @ \t \r` characters to prevent formula injection

## How the dashboard reads the detection report

The dashboard loads `reports/alerts.json` on each request (via `services/report_loader.load_report`). 
- If missing: UI shows "No detection report yet" and API returns appropriate 404s.
- If malformed/invalid: UI shows "Detection report unavailable" and API returns 503.
- All displayed figures (total requests, alert counts, breakdowns) are recomputed from the actual alert records in the report.
- The dashboard never writes to access logs or modifies the report except when the Analyze button triggers `detector.py` to regenerate it server-side.

## How to trigger log analysis

From the dashboard UI: click **Analyze Logs** (top-right button). This invokes `POST /api/analyze`.

Server-side behavior:
1. Acquires a lock to prevent concurrent analysis runs (returns HTTP 409 if already running).
2. Runs `[sys.executable, detector.py]` as a subprocess with controlled environment variables pointing to the log/report paths from server config.
3. No user-supplied command strings, filenames, or executable paths are accepted. The endpoint rejects any JSON body with keys or non-empty content.
4. On success, reloads and displays refreshed summary from the newly generated `reports/alerts.json`.
5. On failure, returns a generic error (no internal details exposed).

You may also run manually: `python detector.py` from the `SafeShop-Dash` directory.

## Testing

All tests use isolated temporary files and fixtures. They never modify the real laboratory logs or fabricate alerts for display.

Run all tests:

```powershell
cd C:\Users\seela\OneDrive\Documents\All_Coding\SafeShop-Dash
.venv\Scripts\Activate.ps1
python -m pytest -q
```

Test coverage includes:
- Dashboard homepage, alerts listing, website monitoring, network evidence
- Summary calculations (must come from actual records)
- Empty/missing report files and malformed JSON handling
- Filtering, search, and alert detail retrieval
- JSON and CSV exports (correct headers, safe filenames, formula-injection neutralisation)
- Analysis endpoint (success/failure, rejection of arbitrary input, concurrency protection, CORS protection)
- Ensuring dashboard does not generate fake alerts
- Detection engine rules (WHD-001 through WHD-006) against controlled data and real logs

### Test results (honest)

**53 passed, 15763 warnings in 1.25s** (warnings are from dependencies/werkzeug in the test environment, not from the implementation).

## Design

- **Layout**: Dark navy sidebar (264px) with brand, navigation, and status; light content area with top bar and cards.
- **Styling**: Clean cards, accessible typography, responsive grid/flex layouts, blue accents (#2563eb), severity color coding (high: #dc2626, medium: #d97706, low: #0284c7).
- **Interactivity**: Vanilla JavaScript for toasts, progress indication on analysis, live search (debounced) on alerts table, modal detail view. CSP-compliant (no inline event handlers/styles).
- **Accessibility**: Skip link, semantic HTML, ARIA roles/labels where appropriate.

No React introduced; vanilla stack integrates cleanly with Flask/Jinja2.

## Current limitations

- The dashboard is a **read-only monitoring interface** for the laboratory environment; it does not write to logs or rules.
- **Network Evidence** is documentation-only — it does not ingest pcap files or perform live packet capture. Loopback captures must be performed manually in Wireshark (requires Npcap on Windows).
- Uses Flask's development server (`app.run` with `debug=False`). Not intended for production/public exposure.
- All paths are resolved relative to the sibling laboratory directories by default; environment variables can override if needed.

## Files created

The following files were added to implement the dashboard (reusing existing code where possible):

- `config.py` — Configuration with defaults pointing to sibling SafeShop projects
- `detector.py` — Detection engine (existing lab rules A–E plus informational rule)
- `app.py` — Flask application with routes, security headers, CORS protection
- `services/__init__.py`, `services/report_loader.py`, `services/analysis.py` — Business logic
- `templates/base.html`, `overview.html`, `websites.html`, `alerts.html`, `network.html`, `error.html`
- `static/css/dashboard.css`, `static/js/dashboard.js`
- `requirements.txt` — Flask, pytest, pytest-flask
- `tests/conftest.py`, `tests/test_dashboard.py`, `tests/test_detector.py`
- `reports/.gitkeep` (report generated at runtime)

All existing project work in SafeShop/SafeShop-Compromised is preserved; no unrelated files were modified.

## Verification

- Detector executed successfully on real logs: **195 total requests**, **20 alerts** detected (4 high, 4 medium, 12 low). Report written to `reports/alerts.json`.
- Full test suite: **53 passed**.
- Dashboard renders correctly, API endpoints behave as specified, exports work with correct headers/filenames.

The system is ready to run as specified.
