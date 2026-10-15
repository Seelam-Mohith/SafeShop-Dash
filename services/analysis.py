"""Controlled, server-side runner for the detection engine.

The engine is invoked as a subprocess with a fixed executable (the current
Python interpreter) and a fixed script path taken from server configuration.
No command strings, filenames, arguments, or executable paths are accepted
from HTTP clients.
"""

import json
import os
import subprocess
import sys
import threading

_lock = threading.Lock()


class AnalysisBusyError(Exception):
    """An analysis run is already in progress."""


class AnalysisFailedError(Exception):
    """The detection engine could not complete successfully."""


def is_running():
    return _lock.locked()


def run_analysis(config):
    """Run the detection engine once; returns a result dict.

    Raises AnalysisBusyError when another run is in progress and
    AnalysisFailedError on any execution problem. Error messages are generic
    and never include filesystem paths or subprocess output.
    """
    if not _lock.acquire(blocking=False):
        raise AnalysisBusyError("An analysis run is already in progress.")

    try:
        script = config["DETECTOR_SCRIPT"]
        if not script or not os.path.isfile(script):
            raise AnalysisFailedError("The detection engine is not available on this server.")

        env = os.environ.copy()
        env["SAFESHOP_LEGITIMATE_LOG"] = config["LEGITIMATE_LOG"]
        env["SAFESHOP_COMPROMISED_LOG"] = config["COMPROMISED_LOG"]
        env["SAFESHOP_REPORT_FILE"] = config["REPORT_FILE"]

        timeout = config.get("ANALYZE_TIMEOUT_SECONDS", 60)
        try:
            proc = subprocess.run(
                [sys.executable, script],
                cwd=config["BASE_DIR"],
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise AnalysisFailedError("The analysis run timed out.")
        except OSError:
            raise AnalysisFailedError("The detection engine could not be started.")

        if proc.returncode != 0:
            raise AnalysisFailedError("The detection engine exited with an error.")

        payload = None
        for line in reversed((proc.stdout or "").splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                candidate = json.loads(line)
            except json.JSONDecodeError:
                break
            if isinstance(candidate, dict) and candidate.get("status") == "ok":
                payload = candidate
            break

        result = {
            "status": "ok",
            "message": "Analysis completed successfully.",
        }
        if payload:
            for key in ("total_requests", "total_alerts", "by_severity", "generated_at"):
                if key in payload:
                    result[key] = payload[key]
        return result
    finally:
        _lock.release()
