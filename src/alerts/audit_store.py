import hashlib
import hmac
import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional


class AlertAuditStore:
    """Append-only audit store with chained hashes and HMAC signatures."""

    def __init__(self, db_path: str | Path, signing_key: Optional[str] = None):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        key_text = signing_key or os.getenv("THREAT_AUDIT_SIGNING_KEY", "change-me-in-production")
        self._signing_key = key_text.encode("utf-8")
        self._lock = Lock()
        self._init_schema()

    @staticmethod
    def _iso_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alert_audit (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  alert_id TEXT NOT NULL,
                  action TEXT NOT NULL,
                  operator_id TEXT NOT NULL,
                  details_json TEXT NOT NULL,
                  event_timestamp TEXT NOT NULL,
                  recorded_at TEXT NOT NULL,
                  prev_hash TEXT,
                  entry_hash TEXT NOT NULL UNIQUE,
                  signature TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS services (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  type TEXT NOT NULL,
                  lat REAL NOT NULL,
                  lng REAL NOT NULL,
                  phone TEXT,
                  email TEXT,
                  is_active INTEGER NOT NULL DEFAULT 1,
                  priority INTEGER NOT NULL DEFAULT 1,
                  last_response TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_services_type_active ON services(type, is_active, priority)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_audit_alert_id ON alert_audit(alert_id, id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_audit_recorded_at ON alert_audit(recorded_at)")
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_alert_audit_no_update
                BEFORE UPDATE ON alert_audit
                BEGIN
                  SELECT RAISE(ABORT, 'alert_audit is append-only');
                END
                """
            )
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_alert_audit_no_delete
                BEFORE DELETE ON alert_audit
                BEGIN
                  SELECT RAISE(ABORT, 'alert_audit is append-only');
                END
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS zone_policy_state (
                  zone_key TEXT NOT NULL,
                  hour_of_day INTEGER NOT NULL CHECK(hour_of_day >= 0 AND hour_of_day <= 23),
                  adaptive_threshold REAL NOT NULL,
                  dismiss_count INTEGER NOT NULL DEFAULT 0,
                  acknowledged_count INTEGER NOT NULL DEFAULT 0,
                  escalated_count INTEGER NOT NULL DEFAULT 0,
                  snooze_until TEXT,
                  updated_at TEXT NOT NULL,
                  PRIMARY KEY(zone_key, hour_of_day)
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_zone_policy_state_updated_at ON zone_policy_state(updated_at)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS shift_window_config (
                  name TEXT PRIMARY KEY,
                  start_minute INTEGER NOT NULL CHECK(start_minute >= 0 AND start_minute <= 1439),
                  end_minute INTEGER NOT NULL CHECK(end_minute >= 0 AND end_minute <= 1439),
                  display_order INTEGER NOT NULL,
                  updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_shift_window_config_order ON shift_window_config(display_order)"
            )
            row = conn.execute("SELECT COUNT(*) AS total FROM shift_window_config").fetchone()
            total = int(row["total"]) if row else 0
            if total <= 0:
                now_iso = self._iso_now()
                defaults = [
                    ("Night", 22 * 60, 6 * 60, 1, now_iso),
                    ("Morning", 6 * 60, 14 * 60, 2, now_iso),
                    ("Evening", 14 * 60, 22 * 60, 3, now_iso),
                ]
                conn.executemany(
                    """
                    INSERT INTO shift_window_config (name, start_minute, end_minute, display_order, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    defaults,
                )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS escalation_chain_config (
                  name TEXT PRIMARY KEY,
                  delay_seconds INTEGER NOT NULL CHECK(delay_seconds >= 0),
                  channels_json TEXT NOT NULL,
                  recipients_json TEXT NOT NULL,
                  display_order INTEGER NOT NULL,
                  updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_escalation_chain_config_order ON escalation_chain_config(display_order)"
            )
            row = conn.execute("SELECT COUNT(*) AS total FROM escalation_chain_config").fetchone()
            total = int(row["total"]) if row else 0
            if total <= 0:
                now_iso = self._iso_now()
                defaults = [
                    ("Operator", 0, json.dumps(["webhook", "push"]), json.dumps(["operator-on-shift"]), 1, now_iso),
                    (
                        "Supervisor",
                        10,
                        json.dumps(["webhook", "sms", "push"]),
                        json.dumps(["supervisor-on-duty"]),
                        2,
                        now_iso,
                    ),
                    (
                        "Emergency",
                        20,
                        json.dumps(["webhook", "sms", "push"]),
                        json.dumps(["all-units"]),
                        3,
                        now_iso,
                    ),
                ]
                conn.executemany(
                    """
                    INSERT INTO escalation_chain_config (
                      name, delay_seconds, channels_json, recipients_json, display_order, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    defaults,
                )
            conn.commit()

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS services (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  type TEXT NOT NULL,
                  lat REAL NOT NULL,
                  lng REAL NOT NULL,
                  phone TEXT NOT NULL,
                  email TEXT NOT NULL DEFAULT '',
                  is_active INTEGER NOT NULL DEFAULT 1,
                  priority INTEGER NOT NULL DEFAULT 1,
                  last_response TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                )
                """
            )
            service_columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(services)").fetchall()}
            if "last_response" not in service_columns:
                conn.execute("ALTER TABLE services ADD COLUMN last_response TEXT")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_services_type_active ON services(type, is_active, priority DESC)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_state (
                  incident_id TEXT PRIMARY KEY,
                  alert_id TEXT UNIQUE,
                  zone_key TEXT NOT NULL,
                  status TEXT NOT NULL,
                  severity TEXT,
                  confidence REAL,
                  lat REAL,
                  lng REAL,
                  acknowledged INTEGER NOT NULL DEFAULT 0,
                  acknowledged_at TEXT,
                  acknowledged_by TEXT,
                  last_sos_at TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_incident_state_zone_status ON incident_state(zone_key, status, updated_at)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sos_event (
                  sos_id TEXT PRIMARY KEY,
                  incident_id TEXT NOT NULL,
                  trigger_type TEXT NOT NULL,
                  reason TEXT NOT NULL,
                  services_json TEXT NOT NULL,
                  status TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  dispatch_started_at TEXT,
                  dispatch_completed_at TEXT,
                  escalation_status TEXT,
                  acknowledged_at TEXT,
                  FOREIGN KEY(incident_id) REFERENCES incident_state(incident_id)
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sos_event_incident_created ON sos_event(incident_id, created_at DESC)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sos_dispatch (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  sos_id TEXT NOT NULL,
                  incident_id TEXT NOT NULL,
                  service_id INTEGER,
                  service_type TEXT NOT NULL,
                  service_name TEXT NOT NULL,
                  phone TEXT NOT NULL,
                  distance_km REAL,
                  status TEXT NOT NULL,
                  mode TEXT NOT NULL,
                  attempts INTEGER NOT NULL DEFAULT 0,
                  message TEXT NOT NULL,
                  error TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  FOREIGN KEY(sos_id) REFERENCES sos_event(sos_id),
                  FOREIGN KEY(incident_id) REFERENCES incident_state(incident_id)
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sos_dispatch_incident_created ON sos_dispatch(incident_id, created_at DESC)"
            )
            row = conn.execute("SELECT COUNT(*) AS total FROM services").fetchone()
            total = int(row["total"]) if row else 0
            if total <= 0:
                now_iso = self._iso_now()
                seed_rows = [
                    ("Central Police Response", "police", 12.9716, 77.5946, "+911000000001", "police@example.local", 1, 3, now_iso, now_iso, now_iso),
                    ("Metro Police Rapid Unit", "police", 12.9784, 77.6002, "+911000000002", "rapidpolice@example.local", 1, 2, now_iso, now_iso, now_iso),
                    ("City General Hospital", "hospital", 12.9695, 77.5901, "+911000000003", "er@example.local", 1, 3, now_iso, now_iso, now_iso),
                    ("Eastside Trauma Center", "hospital", 12.9822, 77.6111, "+911000000004", "trauma@example.local", 1, 2, now_iso, now_iso, now_iso),
                    ("Fire Rescue Station 1", "fire", 12.9754, 77.5898, "+911000000005", "fire@example.local", 1, 3, now_iso, now_iso, now_iso),
                ]
                conn.executemany(
                    """
                    INSERT INTO services (
                      name, type, lat, lng, phone, email, is_active, priority, created_at, updated_at, last_response
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    seed_rows,
                )
            conn.commit()

    @staticmethod
    def _canonical_details(details: Dict[str, Any]) -> str:
        # Canonical JSON form so signatures are deterministic.
        return json.dumps(details, sort_keys=True, separators=(",", ":"))

    def _entry_hash(
        self,
        alert_id: str,
        action: str,
        operator_id: str,
        details_json: str,
        event_timestamp: str,
        prev_hash: Optional[str],
    ) -> str:
        payload = json.dumps(
            {
                "alert_id": alert_id,
                "action": action,
                "operator_id": operator_id,
                "details_json": details_json,
                "event_timestamp": event_timestamp,
                "prev_hash": prev_hash or "",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _sign(self, entry_hash: str) -> str:
        return hmac.new(self._signing_key, entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _safe_hour(value: int) -> int:
        hour = int(value)
        if hour < 0 or hour > 23:
            raise ValueError("hour_of_day must be between 0 and 23")
        return hour

    @staticmethod
    def _clamp_threshold(value: float, minimum: float, maximum: float) -> float:
        return max(minimum, min(maximum, float(value)))

    @staticmethod
    def _parse_iso(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            text = str(value).strip().replace("Z", "+00:00")
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def _ensure_zone_policy_row(
        self,
        conn: sqlite3.Connection,
        *,
        zone_key: str,
        hour_of_day: int,
        initial_threshold: float,
    ) -> None:
        now_iso = self._iso_now()
        conn.execute(
            """
            INSERT OR IGNORE INTO zone_policy_state (
              zone_key, hour_of_day, adaptive_threshold, dismiss_count, acknowledged_count, escalated_count, snooze_until, updated_at
            ) VALUES (?, ?, ?, 0, 0, 0, NULL, ?)
            """,
            (zone_key, hour_of_day, float(initial_threshold), now_iso),
        )

    def get_alert_context(self, alert_id: str) -> Optional[Dict[str, Any]]:
        safe_alert_id = str(alert_id).strip()
        if not safe_alert_id:
            return None
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT details_json, event_timestamp
                FROM alert_audit
                WHERE alert_id = ? AND action = 'ALERT_RAISED'
                ORDER BY id ASC
                LIMIT 1
                """,
                (safe_alert_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            details = json.loads(row["details_json"])
        except Exception:
            details = {}
        zone_key = str(details.get("zone_key") or details.get("source") or "zone:default")
        hour_raw = details.get("hour_of_day")
        hour_of_day: Optional[int]
        try:
            hour_of_day = int(hour_raw) if hour_raw is not None else None
        except (TypeError, ValueError):
            hour_of_day = None
        if hour_of_day is None:
            parsed = self._parse_iso(row["event_timestamp"])
            hour_of_day = parsed.hour if parsed is not None else datetime.now().hour
        hour_of_day = self._safe_hour(hour_of_day)
        return {
            "alert_id": safe_alert_id,
            "zone_key": zone_key,
            "hour_of_day": hour_of_day,
            "details": details,
            "event_timestamp": row["event_timestamp"],
        }

    def append_entry(
        self,
        *,
        alert_id: str,
        action: str,
        operator_id: str,
        details: Dict[str, Any],
        event_timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        safe_alert_id = str(alert_id).strip()
        safe_action = str(action).strip().upper()
        safe_operator = str(operator_id).strip() or "unknown"
        details_json = self._canonical_details(details)
        event_ts = event_timestamp or self._iso_now()
        recorded_at = self._iso_now()

        with self._lock:
            with self._connect() as conn:
                row = conn.execute("SELECT entry_hash FROM alert_audit ORDER BY id DESC LIMIT 1").fetchone()
                prev_hash = row["entry_hash"] if row else None
                entry_hash = self._entry_hash(
                    safe_alert_id,
                    safe_action,
                    safe_operator,
                    details_json,
                    event_ts,
                    prev_hash,
                )
                signature = self._sign(entry_hash)
                cur = conn.execute(
                    """
                    INSERT INTO alert_audit (
                      alert_id, action, operator_id, details_json, event_timestamp, recorded_at, prev_hash, entry_hash, signature
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        safe_alert_id,
                        safe_action,
                        safe_operator,
                        details_json,
                        event_ts,
                        recorded_at,
                        prev_hash,
                        entry_hash,
                        signature,
                    ),
                )
                conn.commit()
                audit_id = int(cur.lastrowid)

        return {
            "id": audit_id,
            "alert_id": safe_alert_id,
            "action": safe_action,
            "operator_id": safe_operator,
            "details": json.loads(details_json),
            "event_timestamp": event_ts,
            "recorded_at": recorded_at,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
            "signature": signature,
        }

    def alert_exists(self, alert_id: str) -> bool:
        safe_alert_id = str(alert_id).strip()
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM alert_audit WHERE alert_id = ? LIMIT 1", (safe_alert_id,)).fetchone()
        return row is not None

    def fetch_entries(self, *, alert_id: Optional[str] = None, limit: int = 200) -> Dict[str, Any]:
        count = max(1, min(int(limit), 2000))
        params: list[Any]
        query = """
            SELECT id, alert_id, action, operator_id, details_json, event_timestamp, recorded_at, prev_hash, entry_hash, signature
            FROM alert_audit
        """
        total_query = "SELECT COUNT(*) AS total FROM alert_audit"
        total_params: list[Any] = []
        if alert_id:
            query += " WHERE alert_id = ?"
            params = [str(alert_id).strip()]
            total_query += " WHERE alert_id = ?"
            total_params = [str(alert_id).strip()]
        else:
            params = []
        query += " ORDER BY id DESC LIMIT ?"
        params.append(count)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            total_row = conn.execute(total_query, total_params).fetchone()
            total = int(total_row["total"]) if total_row else 0

        items = []
        for row in rows:
            items.append(
                {
                    "id": int(row["id"]),
                    "alert_id": row["alert_id"],
                    "action": row["action"],
                    "operator_id": row["operator_id"],
                    "details": json.loads(row["details_json"]),
                    "event_timestamp": row["event_timestamp"],
                    "recorded_at": row["recorded_at"],
                    "prev_hash": row["prev_hash"],
                    "entry_hash": row["entry_hash"],
                    "signature": row["signature"],
                }
            )
        items.reverse()
        return {"entries": items, "total": total}

    def fetch_entries_for_alert_ids(
        self,
        *,
        alert_ids: List[str],
        limit: int = 2000,
        actions: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        clean_ids = [str(value).strip() for value in alert_ids if str(value).strip()]
        if not clean_ids:
            return {"entries": [], "total": 0}

        count = max(1, min(int(limit), 20000))
        placeholders = ",".join("?" for _ in clean_ids)
        params: list[Any] = list(clean_ids)
        action_filter = ""
        if actions:
            action_tokens = [str(token).strip().upper() for token in actions if str(token).strip()]
            if action_tokens:
                action_placeholders = ",".join("?" for _ in action_tokens)
                action_filter = f" AND action IN ({action_placeholders})"
                params.extend(action_tokens)

        query = f"""
            SELECT id, alert_id, action, operator_id, details_json, event_timestamp, recorded_at, prev_hash, entry_hash, signature
            FROM alert_audit
            WHERE alert_id IN ({placeholders}){action_filter}
            ORDER BY id DESC
            LIMIT ?
        """
        params.append(count)

        total_query = f"SELECT COUNT(*) AS total FROM alert_audit WHERE alert_id IN ({placeholders}){action_filter}"
        total_params: list[Any] = list(params[:-1])

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            total_row = conn.execute(total_query, total_params).fetchone()
            total = int(total_row["total"]) if total_row else 0

        items = []
        for row in rows:
            items.append(
                {
                    "id": int(row["id"]),
                    "alert_id": row["alert_id"],
                    "action": row["action"],
                    "operator_id": row["operator_id"],
                    "details": json.loads(row["details_json"]),
                    "event_timestamp": row["event_timestamp"],
                    "recorded_at": row["recorded_at"],
                    "prev_hash": row["prev_hash"],
                    "entry_hash": row["entry_hash"],
                    "signature": row["signature"],
                }
            )
        items.reverse()
        return {"entries": items, "total": total}

    def alert_ids_by_threat(self, threat_id: str, limit: int = 4000) -> List[str]:
        safe_threat_id = str(threat_id).strip()
        if not safe_threat_id:
            return []
        count = max(1, min(int(limit), 50000))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT alert_id, details_json
                FROM alert_audit
                WHERE action = 'ALERT_RAISED'
                ORDER BY id DESC
                LIMIT ?
                """,
                (count,),
            ).fetchall()
        alert_ids: list[str] = []
        seen: set[str] = set()
        for row in rows:
            alert_id = str(row["alert_id"]).strip()
            if not alert_id or alert_id in seen:
                continue
            try:
                details = json.loads(row["details_json"])
            except Exception:
                details = {}
            if str(details.get("threat_id", "")).strip() == safe_threat_id:
                seen.add(alert_id)
                alert_ids.append(alert_id)
        alert_ids.reverse()
        return alert_ids

    @staticmethod
    def incident_key(incident_id: str) -> str:
        safe_incident_id = str(incident_id).strip()
        return f"INCIDENT:{safe_incident_id}"

    def append_incident_event(
        self,
        *,
        incident_id: str,
        action: str,
        operator_id: str,
        details: Dict[str, Any],
        event_timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self.append_entry(
            alert_id=self.incident_key(incident_id),
            action=action,
            operator_id=operator_id,
            details=details,
            event_timestamp=event_timestamp,
        )

    def incident_events(self, incident_id: str, limit: int = 500) -> Dict[str, Any]:
        key = self.incident_key(incident_id)
        return self.fetch_entries(alert_id=key, limit=limit)

    def list_shift_windows(self) -> Dict[str, Any]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT name, start_minute, end_minute, display_order, updated_at
                FROM shift_window_config
                ORDER BY display_order ASC, name ASC
                """
            ).fetchall()
        items = []
        for row in rows:
            items.append(
                {
                    "name": row["name"],
                    "start_minute": int(row["start_minute"]),
                    "end_minute": int(row["end_minute"]),
                    "display_order": int(row["display_order"]),
                    "updated_at": row["updated_at"],
                }
            )
        return {"windows": items, "total": len(items)}

    def replace_shift_windows(self, windows: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not windows:
            raise ValueError("At least one shift window is required")
        normalized: list[tuple[str, int, int, int, str]] = []
        seen_names: set[str] = set()
        now_iso = self._iso_now()
        for index, item in enumerate(windows, start=1):
            name = str(item.get("name", "")).strip()
            if not name:
                raise ValueError("Each shift window must include a name")
            name_key = name.lower()
            if name_key in seen_names:
                raise ValueError(f"Duplicate shift window name '{name}'")
            seen_names.add(name_key)
            start_minute = int(item.get("start_minute"))
            end_minute = int(item.get("end_minute"))
            if start_minute < 0 or start_minute > 1439:
                raise ValueError(f"Invalid start_minute for shift '{name}'")
            if end_minute < 0 or end_minute > 1439:
                raise ValueError(f"Invalid end_minute for shift '{name}'")
            if start_minute == end_minute:
                raise ValueError(f"Shift '{name}' cannot have identical start and end times")
            normalized.append((name, start_minute, end_minute, index, now_iso))

        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM shift_window_config")
                conn.executemany(
                    """
                    INSERT INTO shift_window_config (name, start_minute, end_minute, display_order, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    normalized,
                )
                conn.commit()
        return self.list_shift_windows()

    def list_escalation_chain(self) -> Dict[str, Any]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT name, delay_seconds, channels_json, recipients_json, display_order, updated_at
                FROM escalation_chain_config
                ORDER BY display_order ASC, name ASC
                """
            ).fetchall()
        items = []
        for row in rows:
            try:
                channels = json.loads(row["channels_json"])
            except Exception:
                channels = []
            try:
                recipients = json.loads(row["recipients_json"])
            except Exception:
                recipients = []
            safe_channels = [str(ch).strip().lower() for ch in channels if str(ch).strip()]
            safe_recipients = [str(value).strip() for value in recipients if str(value).strip()]
            items.append(
                {
                    "name": row["name"],
                    "delay_seconds": int(row["delay_seconds"]),
                    "channels": safe_channels,
                    "recipients": safe_recipients,
                    "display_order": int(row["display_order"]),
                    "updated_at": row["updated_at"],
                }
            )
        return {"steps": items, "total": len(items)}

    def replace_escalation_chain(self, steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not steps:
            raise ValueError("At least one escalation step is required")
        allowed_channels = {"webhook", "sms", "push"}
        normalized: list[tuple[str, int, str, str, int, str]] = []
        seen_names: set[str] = set()
        now_iso = self._iso_now()
        for index, item in enumerate(steps, start=1):
            name = str(item.get("name", "")).strip()
            if not name:
                raise ValueError("Each escalation step must include a name")
            name_key = name.lower()
            if name_key in seen_names:
                raise ValueError(f"Duplicate escalation step name '{name}'")
            seen_names.add(name_key)

            delay_seconds = int(item.get("delay_seconds"))
            if delay_seconds < 0 or delay_seconds > 86400:
                raise ValueError(f"Invalid delay_seconds for step '{name}'")

            raw_channels = item.get("channels", [])
            if not isinstance(raw_channels, list):
                raise ValueError(f"channels must be a list for step '{name}'")
            channels = [str(ch).strip().lower() for ch in raw_channels if str(ch).strip()]
            if not channels:
                raise ValueError(f"Step '{name}' must include at least one channel")
            invalid = [ch for ch in channels if ch not in allowed_channels]
            if invalid:
                raise ValueError(f"Unsupported channels for step '{name}': {', '.join(invalid)}")

            raw_recipients = item.get("recipients", [])
            if raw_recipients is None:
                raw_recipients = []
            if not isinstance(raw_recipients, list):
                raise ValueError(f"recipients must be a list for step '{name}'")
            recipients = [str(value).strip() for value in raw_recipients if str(value).strip()]

            normalized.append(
                (
                    name,
                    delay_seconds,
                    json.dumps(channels, separators=(",", ":")),
                    json.dumps(recipients, separators=(",", ":")),
                    index,
                    now_iso,
                )
            )

        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM escalation_chain_config")
                conn.executemany(
                    """
                    INSERT INTO escalation_chain_config (
                      name, delay_seconds, channels_json, recipients_json, display_order, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    normalized,
                )
                conn.commit()
        return self.list_escalation_chain()

    # --- Services (geo routing) ---
    @staticmethod
    def _validate_service_type(value: str) -> str:
        token = str(value or "").strip().lower()
        if token not in {"police", "hospital", "fire"}:
            raise ValueError("service type must be one of: police, hospital, fire")
        return token

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def list_services(self, active_only: bool = True) -> list[Dict[str, Any]]:
        query = "SELECT id, name, type, lat, lng, phone, email, is_active, priority, created_at, updated_at FROM services"
        if active_only:
            query += " WHERE is_active = 1"
        query += " ORDER BY type ASC, priority DESC, id ASC"
        with self._connect() as conn:
            rows = conn.execute(query).fetchall()
        return [
            {
                "id": int(row["id"]),
                "name": row["name"],
                "type": row["type"],
                "lat": float(row["lat"]),
                "lng": float(row["lng"]),
                "phone": row["phone"],
                "email": row["email"],
                "is_active": bool(row["is_active"]),
                "priority": int(row["priority"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def upsert_service(
        self,
        *,
        name: str,
        type: str,
        lat: float,
        lng: float,
        phone: str = "",
        email: str = "",
        is_active: bool = True,
        priority: int = 1,
        service_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        safe_type = self._validate_service_type(type)
        now_iso = self._now_iso()
        payload = {
            "name": str(name or "").strip() or safe_type.title(),
            "type": safe_type,
            "lat": float(lat),
            "lng": float(lng),
            "phone": str(phone or "").strip(),
            "email": str(email or "").strip(),
            "is_active": 1 if is_active else 0,
            "priority": max(1, int(priority)),
            "updated_at": now_iso,
        }
        with self._lock:
            with self._connect() as conn:
                if service_id is None:
                    payload["created_at"] = now_iso
                    cur = conn.execute(
                        """
                        INSERT INTO services (name, type, lat, lng, phone, email, is_active, priority, created_at, updated_at)
                        VALUES (:name, :type, :lat, :lng, :phone, :email, :is_active, :priority, :created_at, :updated_at)
                        """,
                        payload,
                    )
                    payload["id"] = int(cur.lastrowid)
                else:
                    payload["id"] = int(service_id)
                    cur = conn.execute(
                        """
                        UPDATE services
                        SET name=:name, type=:type, lat=:lat, lng=:lng, phone=:phone, email=:email,
                            is_active=:is_active, priority=:priority, updated_at=:updated_at
                        WHERE id=:id
                        """,
                        payload,
                    )
                    if cur.rowcount <= 0:
                        raise ValueError(f"Unknown service id {service_id}")
                    row = conn.execute(
                        "SELECT created_at FROM services WHERE id = ?", (payload["id"],)
                    ).fetchone()
                    payload["created_at"] = row["created_at"] if row else now_iso
                conn.commit()
        return payload

    def deactivate_service(self, service_id: int) -> bool:
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE services SET is_active = 0, updated_at = ? WHERE id = ?",
                    (self._now_iso(), int(service_id)),
                )
                conn.commit()
                return cur.rowcount > 0

    def fetch_entries_by_actions(
        self,
        *,
        actions: List[str],
        from_ts: Optional[str] = None,
        to_ts: Optional[str] = None,
        limit: int = 20000,
    ) -> Dict[str, Any]:
        clean_actions = [str(value).strip().upper() for value in actions if str(value).strip()]
        if not clean_actions:
            return {"entries": [], "total": 0}
        count = max(1, min(int(limit), 200000))
        action_placeholders = ",".join("?" for _ in clean_actions)
        query = f"""
            SELECT id, alert_id, action, operator_id, details_json, event_timestamp, recorded_at, prev_hash, entry_hash, signature
            FROM alert_audit
            WHERE action IN ({action_placeholders})
        """
        params: list[Any] = list(clean_actions)
        if from_ts:
            query += " AND event_timestamp >= ?"
            params.append(str(from_ts))
        if to_ts:
            query += " AND event_timestamp <= ?"
            params.append(str(to_ts))
        query += " ORDER BY id DESC LIMIT ?"
        params.append(count)

        total_query = f"SELECT COUNT(*) AS total FROM alert_audit WHERE action IN ({action_placeholders})"
        total_params: list[Any] = list(clean_actions)
        if from_ts:
            total_query += " AND event_timestamp >= ?"
            total_params.append(str(from_ts))
        if to_ts:
            total_query += " AND event_timestamp <= ?"
            total_params.append(str(to_ts))

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            total_row = conn.execute(total_query, total_params).fetchone()
            total = int(total_row["total"]) if total_row else 0

        entries = []
        for row in rows:
            entries.append(
                {
                    "id": int(row["id"]),
                    "alert_id": row["alert_id"],
                    "action": row["action"],
                    "operator_id": row["operator_id"],
                    "details": json.loads(row["details_json"]),
                    "event_timestamp": row["event_timestamp"],
                    "recorded_at": row["recorded_at"],
                    "prev_hash": row["prev_hash"],
                    "entry_hash": row["entry_hash"],
                    "signature": row["signature"],
                }
            )
        entries.reverse()
        return {"entries": entries, "total": total}

    def get_zone_policy(
        self,
        *,
        zone_key: str,
        hour_of_day: int,
        base_threshold: float,
        min_threshold: float,
        max_threshold: float,
        now_iso: Optional[str] = None,
    ) -> Dict[str, Any]:
        safe_zone = str(zone_key).strip() or "zone:default"
        safe_hour = self._safe_hour(hour_of_day)
        clamped_base = self._clamp_threshold(base_threshold, min_threshold, max_threshold)
        now_text = now_iso or self._iso_now()
        now_dt = self._parse_iso(now_text) or datetime.now(timezone.utc)

        with self._lock:
            with self._connect() as conn:
                self._ensure_zone_policy_row(
                    conn,
                    zone_key=safe_zone,
                    hour_of_day=safe_hour,
                    initial_threshold=clamped_base,
                )
                row = conn.execute(
                    """
                    SELECT adaptive_threshold, dismiss_count, acknowledged_count, escalated_count, snooze_until, updated_at
                    FROM zone_policy_state
                    WHERE zone_key = ? AND hour_of_day = ?
                    """,
                    (safe_zone, safe_hour),
                ).fetchone()
                conn.commit()

        threshold = self._clamp_threshold(
            float(row["adaptive_threshold"]),
            min_threshold,
            max_threshold,
        )
        snooze_until = row["snooze_until"]
        snooze_dt = self._parse_iso(snooze_until)
        is_snoozed = bool(snooze_dt is not None and snooze_dt > now_dt)
        return {
            "zone_key": safe_zone,
            "hour_of_day": safe_hour,
            "base_threshold": round(clamped_base, 4),
            "adaptive_threshold": round(threshold, 4),
            "effective_threshold": round(threshold, 4),
            "dismiss_count": int(row["dismiss_count"]),
            "acknowledged_count": int(row["acknowledged_count"]),
            "escalated_count": int(row["escalated_count"]),
            "snooze_until": snooze_until,
            "is_snoozed": is_snoozed,
            "updated_at": row["updated_at"],
        }

    def list_zone_policies(self, *, limit: int = 200) -> Dict[str, Any]:
        count = max(1, min(int(limit), 2000))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT zone_key, hour_of_day, adaptive_threshold, dismiss_count, acknowledged_count, escalated_count, snooze_until, updated_at
                FROM zone_policy_state
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (count,),
            ).fetchall()
        items = []
        for row in rows:
            snooze_dt = self._parse_iso(row["snooze_until"])
            now_dt = datetime.now(timezone.utc)
            items.append(
                {
                    "zone_key": row["zone_key"],
                    "hour_of_day": int(row["hour_of_day"]),
                    "adaptive_threshold": round(float(row["adaptive_threshold"]), 4),
                    "dismiss_count": int(row["dismiss_count"]),
                    "acknowledged_count": int(row["acknowledged_count"]),
                    "escalated_count": int(row["escalated_count"]),
                    "snooze_until": row["snooze_until"],
                    "is_snoozed": bool(snooze_dt is not None and snooze_dt > now_dt),
                    "updated_at": row["updated_at"],
                }
            )
        return {"policies": items, "total": len(items)}

    def set_zone_policy(
        self,
        *,
        zone_key: str,
        hour_of_day: int,
        base_threshold: float,
        min_threshold: float,
        max_threshold: float,
        adaptive_threshold: Optional[float] = None,
        snooze_minutes: Optional[int] = None,
    ) -> Dict[str, Any]:
        safe_zone = str(zone_key).strip() or "zone:default"
        safe_hour = self._safe_hour(hour_of_day)
        clamped_base = self._clamp_threshold(base_threshold, min_threshold, max_threshold)
        now_iso = self._iso_now()
        now_dt = self._parse_iso(now_iso) or datetime.now(timezone.utc)

        with self._lock:
            with self._connect() as conn:
                self._ensure_zone_policy_row(
                    conn,
                    zone_key=safe_zone,
                    hour_of_day=safe_hour,
                    initial_threshold=clamped_base,
                )
                row = conn.execute(
                    """
                    SELECT adaptive_threshold, dismiss_count, acknowledged_count, escalated_count, snooze_until
                    FROM zone_policy_state
                    WHERE zone_key = ? AND hour_of_day = ?
                    """,
                    (safe_zone, safe_hour),
                ).fetchone()
                current_threshold = float(row["adaptive_threshold"])
                current_snooze = row["snooze_until"]
                next_threshold = (
                    self._clamp_threshold(adaptive_threshold, min_threshold, max_threshold)
                    if adaptive_threshold is not None
                    else current_threshold
                )
                next_snooze = current_snooze
                if snooze_minutes is not None:
                    minutes = int(snooze_minutes)
                    if minutes <= 0:
                        next_snooze = None
                    else:
                        next_snooze = (now_dt + timedelta(minutes=minutes)).isoformat()
                conn.execute(
                    """
                    UPDATE zone_policy_state
                    SET adaptive_threshold = ?, snooze_until = ?, updated_at = ?
                    WHERE zone_key = ? AND hour_of_day = ?
                    """,
                    (float(next_threshold), next_snooze, now_iso, safe_zone, safe_hour),
                )
                conn.commit()

        return self.get_zone_policy(
            zone_key=safe_zone,
            hour_of_day=safe_hour,
            base_threshold=clamped_base,
            min_threshold=min_threshold,
            max_threshold=max_threshold,
            now_iso=now_iso,
        )

    def apply_disposition_learning(
        self,
        *,
        alert_id: str,
        action: str,
        base_threshold: float,
        min_threshold: float,
        max_threshold: float,
        tune_step: float,
        dismiss_trigger_count: int,
        snooze_minutes: int,
    ) -> Dict[str, Any]:
        context = self.get_alert_context(alert_id)
        if context is None:
            return {"updated": False, "reason": "Missing alert context"}

        safe_action = str(action).strip().upper()
        if safe_action not in {"DISMISSED", "ACKNOWLEDGED", "ESCALATED"}:
            return {"updated": False, "reason": "Unsupported action for learning"}

        safe_zone = str(context["zone_key"]).strip() or "zone:default"
        safe_hour = self._safe_hour(int(context["hour_of_day"]))
        clamped_base = self._clamp_threshold(base_threshold, min_threshold, max_threshold)
        safe_step = max(0.001, float(tune_step))
        safe_trigger = max(1, int(dismiss_trigger_count))
        safe_snooze_minutes = max(0, int(snooze_minutes))
        now_iso = self._iso_now()
        now_dt = self._parse_iso(now_iso) or datetime.now(timezone.utc)

        with self._lock:
            with self._connect() as conn:
                self._ensure_zone_policy_row(
                    conn,
                    zone_key=safe_zone,
                    hour_of_day=safe_hour,
                    initial_threshold=clamped_base,
                )
                row = conn.execute(
                    """
                    SELECT adaptive_threshold, dismiss_count, acknowledged_count, escalated_count, snooze_until
                    FROM zone_policy_state
                    WHERE zone_key = ? AND hour_of_day = ?
                    """,
                    (safe_zone, safe_hour),
                ).fetchone()

                threshold = float(row["adaptive_threshold"])
                dismiss_count = int(row["dismiss_count"])
                acknowledged_count = int(row["acknowledged_count"])
                escalated_count = int(row["escalated_count"])
                snooze_until = row["snooze_until"]

                auto_tuned = False
                auto_snoozed = False
                if safe_action == "DISMISSED":
                    dismiss_count += 1
                    if dismiss_count >= safe_trigger:
                        threshold = self._clamp_threshold(threshold + safe_step, min_threshold, max_threshold)
                        dismiss_count = 0
                        auto_tuned = True
                        if safe_snooze_minutes > 0:
                            snooze_until = (now_dt + timedelta(minutes=safe_snooze_minutes)).isoformat()
                            auto_snoozed = True
                elif safe_action == "ACKNOWLEDGED":
                    acknowledged_count += 1
                elif safe_action == "ESCALATED":
                    escalated_count += 1

                conn.execute(
                    """
                    UPDATE zone_policy_state
                    SET adaptive_threshold = ?, dismiss_count = ?, acknowledged_count = ?, escalated_count = ?, snooze_until = ?, updated_at = ?
                    WHERE zone_key = ? AND hour_of_day = ?
                    """,
                    (
                        threshold,
                        dismiss_count,
                        acknowledged_count,
                        escalated_count,
                        snooze_until,
                        now_iso,
                        safe_zone,
                        safe_hour,
                    ),
                )
                conn.commit()

        policy = self.get_zone_policy(
            zone_key=safe_zone,
            hour_of_day=safe_hour,
            base_threshold=clamped_base,
            min_threshold=min_threshold,
            max_threshold=max_threshold,
            now_iso=now_iso,
        )
        return {
            "updated": True,
            "action": safe_action,
            "zone_key": safe_zone,
            "hour_of_day": safe_hour,
            "auto_tuned": auto_tuned,
            "auto_snoozed": auto_snoozed,
            "policy": policy,
        }

    def latest_dispositions(self, alert_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        clean_ids = [str(value).strip() for value in alert_ids if str(value).strip()]
        if not clean_ids:
            return {}
        placeholders = ",".join("?" for _ in clean_ids)
        query = f"""
            SELECT a.id, a.alert_id, a.action, a.operator_id, a.details_json, a.event_timestamp, a.recorded_at
            FROM alert_audit a
            JOIN (
              SELECT alert_id, MAX(id) AS latest_id
              FROM alert_audit
              WHERE alert_id IN ({placeholders})
                AND action IN ('ACKNOWLEDGED', 'ESCALATED', 'DISMISSED')
              GROUP BY alert_id
            ) s ON a.id = s.latest_id
        """
        with self._connect() as conn:
            rows = conn.execute(query, clean_ids).fetchall()

        out: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            out[row["alert_id"]] = {
                "id": int(row["id"]),
                "action": row["action"],
                "operator_id": row["operator_id"],
                "details": json.loads(row["details_json"]),
                "event_timestamp": row["event_timestamp"],
                "recorded_at": row["recorded_at"],
            }
        return out

    def verify_chain(self, *, alert_id: Optional[str] = None, limit: int = 5000) -> Dict[str, Any]:
        count = max(1, min(int(limit), 100000))
        params: list[Any]
        query = """
            SELECT id, alert_id, action, operator_id, details_json, event_timestamp, prev_hash, entry_hash, signature
            FROM alert_audit
        """
        if alert_id:
            query += " WHERE alert_id = ?"
            params = [str(alert_id).strip()]
        else:
            params = []
        query += " ORDER BY id ASC LIMIT ?"
        params.append(count)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        prev_hash: Optional[str] = None
        for row in rows:
            expected_hash = self._entry_hash(
                row["alert_id"],
                row["action"],
                row["operator_id"],
                row["details_json"],
                row["event_timestamp"],
                row["prev_hash"],
            )
            if expected_hash != row["entry_hash"]:
                return {
                    "valid": False,
                    "checked": len(rows),
                    "failed_id": int(row["id"]),
                    "reason": "Entry hash mismatch",
                }
            expected_sig = self._sign(row["entry_hash"])
            if expected_sig != row["signature"]:
                return {
                    "valid": False,
                    "checked": len(rows),
                    "failed_id": int(row["id"]),
                    "reason": "Signature mismatch",
                }
            if row["prev_hash"] != (prev_hash or None):
                return {
                    "valid": False,
                    "checked": len(rows),
                    "failed_id": int(row["id"]),
                    "reason": "Chain link mismatch",
                }
            prev_hash = row["entry_hash"]

        return {"valid": True, "checked": len(rows)}

    def list_services(self, *, active_only: bool = False, service_type: Optional[str] = None) -> List[Dict[str, Any]]:
        query = """
            SELECT id, name, type, lat, lng, phone, email, is_active, priority, last_response, created_at, updated_at
            FROM services
            WHERE 1 = 1
        """
        params: list[Any] = []
        if active_only:
            query += " AND is_active = 1"
        if service_type:
            query += " AND type = ?"
            params.append(str(service_type).strip().lower())
        query += " ORDER BY type ASC, is_active DESC, priority DESC, name ASC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "id": int(row["id"]),
                "name": row["name"],
                "type": row["type"],
                "lat": float(row["lat"]),
                "lng": float(row["lng"]),
                "phone": row["phone"],
                "email": row["email"],
                "is_active": bool(row["is_active"]),
                "priority": int(row["priority"]),
                "last_response": row["last_response"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def create_service(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        now_iso = self._iso_now()
        name = str(payload.get("name", "")).strip()
        service_type = str(payload.get("type", "")).strip().lower()
        if not name:
            raise ValueError("Service name is required")
        if service_type not in {"police", "hospital", "fire"}:
            raise ValueError("Service type must be one of: police, hospital, fire")
        phone = str(payload.get("phone", "")).strip()
        if not phone:
            raise ValueError("Service phone is required")
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO services (
                      name, type, lat, lng, phone, email, is_active, priority, created_at, updated_at, last_response
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        name,
                        service_type,
                        float(payload.get("lat")),
                        float(payload.get("lng")),
                        phone,
                        str(payload.get("email", "")).strip(),
                        1 if bool(payload.get("is_active", True)) else 0,
                        int(payload.get("priority", 1)),
                        now_iso,
                        now_iso,
                        str(payload.get("last_response", "")).strip() or now_iso,
                    ),
                )
                conn.commit()
                service_id = int(cur.lastrowid)
        for item in self.list_services(active_only=False):
            if int(item["id"]) == service_id:
                return item
        raise ValueError("Failed to create service")

    def touch_service_last_response(self, service_id: int, response_at: Optional[str] = None) -> None:
        now_iso = response_at or self._iso_now()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE services
                    SET last_response = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (now_iso, now_iso, int(service_id)),
                )
                conn.commit()

    def incident_by_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        safe_alert_id = str(alert_id).strip()
        if not safe_alert_id:
            return None
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT incident_id, alert_id, zone_key, status, severity, confidence, lat, lng,
                       acknowledged, acknowledged_at, acknowledged_by, last_sos_at, created_at, updated_at
                FROM incident_state
                WHERE alert_id = ?
                LIMIT 1
                """,
                (safe_alert_id,),
            ).fetchone()
        return self._incident_row_to_dict(row)

    def incident_state(self, incident_id: str) -> Optional[Dict[str, Any]]:
        safe_incident_id = str(incident_id).strip()
        if not safe_incident_id:
            return None
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT incident_id, alert_id, zone_key, status, severity, confidence, lat, lng,
                       acknowledged, acknowledged_at, acknowledged_by, last_sos_at, created_at, updated_at
                FROM incident_state
                WHERE incident_id = ?
                LIMIT 1
                """,
                (safe_incident_id,),
            ).fetchone()
        return self._incident_row_to_dict(row)

    @staticmethod
    def _incident_row_to_dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        return {
            "incident_id": row["incident_id"],
            "alert_id": row["alert_id"],
            "zone_key": row["zone_key"],
            "status": row["status"],
            "severity": row["severity"],
            "confidence": float(row["confidence"]) if row["confidence"] is not None else None,
            "lat": float(row["lat"]) if row["lat"] is not None else None,
            "lng": float(row["lng"]) if row["lng"] is not None else None,
            "acknowledged": bool(row["acknowledged"]),
            "acknowledged_at": row["acknowledged_at"],
            "acknowledged_by": row["acknowledged_by"],
            "last_sos_at": row["last_sos_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def create_incident(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        incident_id = str(payload.get("incident_id") or f"INC-{uuid.uuid4().hex[:12].upper()}").strip()
        now_iso = self._iso_now()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO incident_state (
                      incident_id, alert_id, zone_key, status, severity, confidence, lat, lng,
                      acknowledged, acknowledged_at, acknowledged_by, last_sos_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        str(payload.get("alert_id", "")).strip() or None,
                        str(payload.get("zone_key", "")).strip() or "zone:default",
                        str(payload.get("status", "active")).strip().lower() or "active",
                        str(payload.get("severity", "")).strip() or None,
                        float(payload["confidence"]) if payload.get("confidence") is not None else None,
                        float(payload["lat"]) if payload.get("lat") is not None else None,
                        float(payload["lng"]) if payload.get("lng") is not None else None,
                        0,
                        None,
                        None,
                        None,
                        now_iso,
                        now_iso,
                    ),
                )
                conn.commit()
        incident = self.incident_state(incident_id)
        if incident is None:
            raise ValueError("Failed to create incident")
        return incident

    def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        safe_incident_id = str(incident_id).strip()
        current = self.incident_state(safe_incident_id)
        if current is None:
            raise ValueError(f"Unknown incident_id '{incident_id}'")
        allowed_fields = {
            "status",
            "severity",
            "confidence",
            "lat",
            "lng",
            "acknowledged",
            "acknowledged_at",
            "acknowledged_by",
            "last_sos_at",
            "alert_id",
            "zone_key",
        }
        assignments: list[str] = []
        params: list[Any] = []
        for key, value in updates.items():
            if key not in allowed_fields:
                continue
            assignments.append(f"{key} = ?")
            if key == "acknowledged":
                params.append(1 if bool(value) else 0)
            elif key in {"confidence", "lat", "lng"} and value is not None:
                params.append(float(value))
            else:
                params.append(value)
        if not assignments:
            return current
        assignments.append("updated_at = ?")
        params.append(self._iso_now())
        params.append(safe_incident_id)
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    f"UPDATE incident_state SET {', '.join(assignments)} WHERE incident_id = ?",
                    params,
                )
                conn.commit()
        updated = self.incident_state(safe_incident_id)
        if updated is None:
            raise ValueError(f"Unknown incident_id '{incident_id}'")
        return updated

    def create_sos_event(
        self,
        *,
        incident_id: str,
        trigger_type: str,
        reason: str,
        services: List[str],
        status: str = "pending",
    ) -> Dict[str, Any]:
        safe_incident_id = str(incident_id).strip()
        if not safe_incident_id:
            raise ValueError("incident_id is required")
        now_iso = self._iso_now()
        sos_id = f"SOS-{uuid.uuid4().hex[:12].upper()}"
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO sos_event (
                      sos_id, incident_id, trigger_type, reason, services_json, status, created_at,
                      dispatch_started_at, dispatch_completed_at, escalation_status, acknowledged_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL)
                    """,
                    (
                        sos_id,
                        safe_incident_id,
                        str(trigger_type).strip().lower() or "manual",
                        str(reason or "").strip(),
                        json.dumps([str(item).strip().lower() for item in services if str(item).strip()]),
                        str(status).strip().lower() or "pending",
                        now_iso,
                    ),
                )
                conn.commit()
        return self.sos_event(sos_id)

    def sos_event(self, sos_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT sos_id, incident_id, trigger_type, reason, services_json, status, created_at,
                       dispatch_started_at, dispatch_completed_at, escalation_status, acknowledged_at
                FROM sos_event
                WHERE sos_id = ?
                LIMIT 1
                """,
                (str(sos_id).strip(),),
            ).fetchone()
        return self._sos_row_to_dict(row)

    def latest_sos_event(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT sos_id, incident_id, trigger_type, reason, services_json, status, created_at,
                       dispatch_started_at, dispatch_completed_at, escalation_status, acknowledged_at
                FROM sos_event
                WHERE incident_id = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (str(incident_id).strip(),),
            ).fetchone()
        return self._sos_row_to_dict(row)

    def find_active_sos_event(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT sos_id, incident_id, trigger_type, reason, services_json, status, created_at,
                       dispatch_started_at, dispatch_completed_at, escalation_status, acknowledged_at
                FROM sos_event
                WHERE incident_id = ?
                  AND status IN ('pending', 'dispatching', 'dispatched', 'active')
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (str(incident_id).strip(),),
            ).fetchone()
        return self._sos_row_to_dict(row)

    @staticmethod
    def _sos_row_to_dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        try:
            services = json.loads(row["services_json"])
        except Exception:
            services = []
        return {
            "sos_id": row["sos_id"],
            "incident_id": row["incident_id"],
            "trigger_type": row["trigger_type"],
            "reason": row["reason"],
            "services": services if isinstance(services, list) else [],
            "status": row["status"],
            "created_at": row["created_at"],
            "dispatch_started_at": row["dispatch_started_at"],
            "dispatch_completed_at": row["dispatch_completed_at"],
            "escalation_status": row["escalation_status"],
            "acknowledged_at": row["acknowledged_at"],
        }

    def update_sos_event(self, sos_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        allowed_fields = {
            "status",
            "dispatch_started_at",
            "dispatch_completed_at",
            "escalation_status",
            "acknowledged_at",
        }
        assignments: list[str] = []
        params: list[Any] = []
        for key, value in updates.items():
            if key not in allowed_fields:
                continue
            assignments.append(f"{key} = ?")
            params.append(value)
        if not assignments:
            event = self.sos_event(sos_id)
            if event is None:
                raise ValueError(f"Unknown sos_id '{sos_id}'")
            return event
        params.append(str(sos_id).strip())
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    f"UPDATE sos_event SET {', '.join(assignments)} WHERE sos_id = ?",
                    params,
                )
                conn.commit()
        event = self.sos_event(sos_id)
        if event is None:
            raise ValueError(f"Unknown sos_id '{sos_id}'")
        return event

    def record_sos_dispatch(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        now_iso = self._iso_now()
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO sos_dispatch (
                      sos_id, incident_id, service_id, service_type, service_name, phone, distance_km,
                      status, mode, attempts, message, error, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(payload.get("sos_id", "")).strip(),
                        str(payload.get("incident_id", "")).strip(),
                        payload.get("service_id"),
                        str(payload.get("service_type", "")).strip().lower(),
                        str(payload.get("service_name", "")).strip(),
                        str(payload.get("phone", "")).strip(),
                        float(payload["distance_km"]) if payload.get("distance_km") is not None else None,
                        str(payload.get("status", "pending")).strip().lower(),
                        str(payload.get("mode", "simulation")).strip().lower(),
                        max(0, int(payload.get("attempts", 0))),
                        str(payload.get("message", "")).strip(),
                        str(payload.get("error", "")).strip() or None,
                        now_iso,
                        now_iso,
                    ),
                )
                conn.commit()
                row_id = int(cur.lastrowid)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, sos_id, incident_id, service_id, service_type, service_name, phone, distance_km,
                       status, mode, attempts, message, error, created_at, updated_at
                FROM sos_dispatch
                WHERE id = ?
                """,
                (row_id,),
            ).fetchone()
        if row is None:
            raise ValueError("Failed to record SOS dispatch")
        return {
            "id": int(row["id"]),
            "sos_id": row["sos_id"],
            "incident_id": row["incident_id"],
            "service_id": row["service_id"],
            "service_type": row["service_type"],
            "service_name": row["service_name"],
            "phone": row["phone"],
            "distance_km": float(row["distance_km"]) if row["distance_km"] is not None else None,
            "status": row["status"],
            "mode": row["mode"],
            "attempts": int(row["attempts"]),
            "message": row["message"],
            "error": row["error"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def incident_dispatches(self, incident_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, sos_id, incident_id, service_id, service_type, service_name, phone, distance_km,
                       status, mode, attempts, message, error, created_at, updated_at
                FROM sos_dispatch
                WHERE incident_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (str(incident_id).strip(), max(1, int(limit))),
            ).fetchall()
        items: List[Dict[str, Any]] = []
        for row in rows:
            items.append(
                {
                    "id": int(row["id"]),
                    "sos_id": row["sos_id"],
                    "incident_id": row["incident_id"],
                    "service_id": row["service_id"],
                    "service_type": row["service_type"],
                    "service_name": row["service_name"],
                    "phone": row["phone"],
                    "distance_km": float(row["distance_km"]) if row["distance_km"] is not None else None,
                    "status": row["status"],
                    "mode": row["mode"],
                    "attempts": int(row["attempts"]),
                    "message": row["message"],
                    "error": row["error"],
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                }
            )
        items.reverse()
        return items
