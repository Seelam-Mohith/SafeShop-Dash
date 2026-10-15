"""Configuration for the ShopSafe security monitoring dashboard.

All paths resolve to the sibling laboratory projects by default and can be
overridden through environment variables (used by automated tests and the
controlled analysis runner). The dashboard is read-only with respect to the
access logs; it never writes to them.
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE_DIR, os.pardir))


def _env(name, default):
    value = os.environ.get(name)
    return value if value else default


def load_config():
    """Build the dashboard configuration dict from the current environment."""
    legitimate_dir = _env(
        "SAFESHOP_LEGITIMATE_DIR", os.path.join(REPO_ROOT, "SafeShop")
    )
    compromised_dir = _env(
        "SAFESHOP_COMPROMISED_DIR", os.path.join(REPO_ROOT, "SafeShop-Compromised")
    )

    return {
        "BASE_DIR": BASE_DIR,
        "LEGITIMATE_LOG": _env(
            "SAFESHOP_LEGITIMATE_LOG",
            os.path.join(legitimate_dir, "logs", "legitimate_access.jsonl"),
        ),
        "COMPROMISED_LOG": _env(
            "SAFESHOP_COMPROMISED_LOG",
            os.path.join(compromised_dir, "logs", "compromised_access.jsonl"),
        ),
        "REPORT_FILE": _env(
            "SAFESHOP_REPORT_FILE",
            os.path.join(BASE_DIR, "reports", "alerts.json"),
        ),
        "DETECTOR_SCRIPT": _env(
            "SAFESHOP_DETECTOR_SCRIPT",
            os.path.join(BASE_DIR, "detector.py"),
        ),
        "ANALYZE_TIMEOUT_SECONDS": int(_env("SAFESHOP_ANALYZE_TIMEOUT", "60")),
        "DASHBOARD_HOST": _env("SAFESHOP_DASHBOARD_HOST", "127.0.0.1"),
        "DASHBOARD_PORT": int(_env("SAFESHOP_DASHBOARD_PORT", "8000")),
        "SITES": {
            "legitimate": {
                "label": "Legitimate ShopSafe",
                "short_label": "ShopSafe",
                "port": 5000,
                "url": _env("SAFESHOP_LEGITIMATE_URL", "http://127.0.0.1:5000"),
                "log_name": "legitimate_access.jsonl",
                "role": "Legitimate baseline storefront",
                "description": (
                    "Fully functional e-commerce baseline. Produces the normal "
                    "traffic profile used as the comparison reference."
                ),
            },
            "compromised": {
                "label": "Simulated Compromised ShopSafe",
                "short_label": "ShopSafe Lab",
                "port": 5001,
                "url": _env("SAFESHOP_COMPROMISED_URL", "http://127.0.0.1:5001"),
                "log_name": "compromised_access.jsonl",
                "role": "Controlled compromise simulation",
                "description": (
                    "Authorized laboratory simulation that exposes clearly "
                    "labelled test routes producing controlled security evidence."
                ),
            },
        },
    }
