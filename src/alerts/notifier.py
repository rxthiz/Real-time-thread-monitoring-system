import json
import os
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Optional

from rich import print

from src.utils.types import SeverityEvent


class AlertNotifier:
    def __init__(self, cfg: Dict):
        alert_cfg = cfg["alerts"]
        self.console = bool(alert_cfg.get("console", True))
        self.output_path = Path(alert_cfg["output_jsonl"])
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    @staticmethod
    def _event_payload(event: SeverityEvent) -> Dict[str, Any]:
        return {
            "timestamp_sec": event.timestamp_sec,
            "weapon": event.weapon,
            "action": event.action,
            "score": round(event.score, 4),
            "level": event.level,
            "reason": event.reason,
            "explanation": dict(event.explanation) if isinstance(event.explanation, dict) else {},
        }

    def _append_record(self, payload: Dict[str, Any]) -> None:
        with self.output_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")

    def _rewrite_matching_alert(self, alert_id: str, updates: Dict[str, Any]) -> bool:
        safe_alert_id = str(alert_id).strip()
        if not safe_alert_id or not self.output_path.exists():
            return False

        temp_path = self.output_path.with_suffix(f"{self.output_path.suffix}.tmp")
        changed = False
        with self.output_path.open("r", encoding="utf-8") as src, temp_path.open("w", encoding="utf-8") as dst:
            for raw_line in src:
                line = raw_line.rstrip("\n")
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    dst.write(raw_line if raw_line.endswith("\n") else f"{raw_line}\n")
                    continue

                if str(payload.get("alert_id", "")).strip() == safe_alert_id:
                    payload.update(updates)
                    line = json.dumps(payload)
                    changed = True
                dst.write(f"{line}\n")

        if changed:
            os.replace(temp_path, self.output_path)
        else:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
        return changed

    def emit(self, event: SeverityEvent, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        merged_payload = self._event_payload(event)
        if payload:
            merged_payload.update(dict(payload))

        if self.console:
            color = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green",
            }.get(event.level, "white")
            alert_label = str(merged_payload.get("alert_id") or "").strip()
            prefix = f"{alert_label} " if alert_label else ""
            print(f"[{color}]ALERT {event.level}[/{color}] {prefix}{merged_payload}")

        with self._lock:
            self._append_record(merged_payload)
        return merged_payload

    def update_alert_record(self, alert_id: str, updates: Dict[str, Any]) -> bool:
        safe_alert_id = str(alert_id).strip()
        if not safe_alert_id:
            return False
        with self._lock:
            return self._rewrite_matching_alert(safe_alert_id, dict(updates))

    def update_alert_evidence(self, alert_id: str, evidence_payload: Dict[str, Any]) -> bool:
        return self.update_alert_record(alert_id, evidence_payload)

    def get_alert_record(self, alert_id: str) -> Optional[Dict[str, Any]]:
        safe_alert_id = str(alert_id).strip()
        if not safe_alert_id or not self.output_path.exists():
            return None

        return self.get_alert_records([safe_alert_id]).get(safe_alert_id)

    def get_alert_records(self, alert_ids: list[str]) -> Dict[str, Dict[str, Any]]:
        clean_ids = {str(value).strip() for value in alert_ids if str(value).strip()}
        if not clean_ids or not self.output_path.exists():
            return {}

        out: Dict[str, Dict[str, Any]] = {}
        with self._lock:
            with self.output_path.open("r", encoding="utf-8") as f:
                lines = f.readlines()
        for raw_line in reversed(lines):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            alert_id = str(payload.get("alert_id", "")).strip()
            if alert_id in clean_ids and alert_id not in out:
                out[alert_id] = payload
                if len(out) == len(clean_ids):
                    break
        return out
