import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib import error as url_error
from urllib import request as url_request


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class ManagedProcess:
    name: str
    process: subprocess.Popen
    stdout_path: Path
    stderr_path: Path


def _request_json(url: str, *, method: str = "GET", payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    body = None
    headers: dict[str, str] = {}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = url_request.Request(url=url, data=body, headers=headers, method=method)
    with url_request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _health(base_url: str) -> dict[str, Any]:
    return _request_json(f"{base_url}/api/v3/ops/health")


def _wait_for_health(base_url: str, timeout_seconds: int) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            return _health(base_url)
        except Exception:
            time.sleep(1)
    raise TimeoutError(f"API did not become healthy within {timeout_seconds}s")


def _start_process(name: str, command: list[str], logs_dir: Path) -> ManagedProcess:
    stdout_path = logs_dir / f"{name}.out.log"
    stderr_path = logs_dir / f"{name}.err.log"
    stdout_file = stdout_path.open("w", encoding="utf-8")
    stderr_file = stderr_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        command,
        cwd=str(PROJECT_ROOT),
        stdout=stdout_file,
        stderr=stderr_file,
    )
    return ManagedProcess(
        name=name,
        process=proc,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )


def _stop_process(proc: ManagedProcess) -> None:
    if proc.process.poll() is None:
        proc.process.terminate()
        try:
            proc.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.process.kill()
            proc.process.wait(timeout=5)


def run_smoke_test(base_url: str, *, auto_start: bool, timeout_seconds: int) -> dict[str, Any]:
    managed: list[ManagedProcess] = []
    logs_dir = PROJECT_ROOT / "tmp_e2e_logs"
    logs_dir.mkdir(exist_ok=True)

    try:
        health: Optional[dict[str, Any]] = None
        try:
            health = _health(base_url)
        except Exception:
            if not auto_start:
                raise

        if health is None:
            python_exe = sys.executable
            managed.append(
                _start_process(
                    "api",
                    [python_exe, "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1", "--port", "8000"],
                    logs_dir,
                )
            )
            managed.append(
                _start_process(
                    "worker",
                    [python_exe, "workers/alert_worker.py"],
                    logs_dir,
                )
            )
            health = _wait_for_health(base_url, timeout_seconds)

        metrics_before = _request_json(f"{base_url}/api/v3/ops/metrics")
        enqueued = _request_json(
            f"{base_url}/api/v3/alerts",
            method="POST",
            payload={
                "severity": "HIGH",
                "type": "THREAT",
                "confidence": 0.95,
                "zone": "zone:e2e",
                "payload": {
                    "source": "scripts/e2e_smoke_test.py",
                    "note": "automated smoke test",
                },
            },
        )

        time.sleep(4)

        metrics_after = _request_json(f"{base_url}/api/v3/ops/metrics")
        recent = _request_json(f"{base_url}/api/v3/alerts/recent?limit=10")

        before = int((metrics_before.get("counters") or {}).get("alerts_processed_total", 0))
        after = int((metrics_after.get("counters") or {}).get("alerts_processed_total", 0))
        alerts = recent.get("alerts", [])
        found_zone = any(str(item.get("zone", "")) == "zone:e2e" for item in alerts)

        return {
            "status": "ok",
            "health_status": health.get("status"),
            "broker_backend": metrics_after.get("broker_backend"),
            "enqueued": enqueued,
            "processed_before": before,
            "processed_after": after,
            "processed_delta": after - before,
            "queue_depth_after": metrics_after.get("queue_depth"),
            "dlq_depth_after": metrics_after.get("dlq_depth"),
            "recent_alert_count": len(alerts),
            "recent_contains_zone_e2e": found_zone,
            "started_processes": [p.name for p in managed],
            "logs_dir": str(logs_dir),
        }
    finally:
        for proc in reversed(managed):
            _stop_process(proc)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run end-to-end alert pipeline smoke test.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="API base URL")
    parser.add_argument(
        "--no-auto-start",
        action="store_true",
        help="Do not auto-start API/worker when API is not reachable",
    )
    parser.add_argument("--timeout-seconds", type=int, default=75, help="Startup timeout for auto-start mode")
    args = parser.parse_args()

    try:
        result = run_smoke_test(
            base_url=args.base_url.rstrip("/"),
            auto_start=not args.no_auto_start,
            timeout_seconds=max(5, int(args.timeout_seconds)),
        )
        print(json.dumps(result, indent=2))
        # Treat missing pipeline progress as failure even if request path succeeded.
        if int(result.get("processed_delta", 0)) <= 0:
            return 2
        return 0
    except (TimeoutError, url_error.URLError, url_error.HTTPError, OSError, ValueError) as exc:
        payload: dict[str, Any] = {"status": "error", "error": str(exc)}
        if args.no_auto_start:
            payload["hint"] = "--no-auto-start requires API and worker to already be running."
            payload["start_commands"] = [
                "uvicorn api.main:app --host 127.0.0.1 --port 8000",
                "python workers/alert_worker.py",
            ]
        print(json.dumps(payload, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
