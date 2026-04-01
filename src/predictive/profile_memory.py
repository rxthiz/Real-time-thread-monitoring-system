import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from time import monotonic
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class TrackProfileStore:
    def __init__(self, *, db_path: str | Path, cfg: Optional[Dict[str, Any]] = None) -> None:
        config = cfg or {}
        memory_cfg = config.get("behavior_memory", {}) if isinstance(config.get("behavior_memory", {}), dict) else {}
        predictive_cfg = config.get("predictive", {}) if isinstance(config.get("predictive", {}), dict) else {}

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.enabled = bool(memory_cfg.get("enabled", True))
        self.history_limit = max(10, int(memory_cfg.get("history_limit", 50)))
        self.zone_history_limit = max(10, int(memory_cfg.get("zone_history_limit", self.history_limit)))
        self.visit_history_limit = max(5, int(memory_cfg.get("visit_history_limit", 24)))
        self.visit_gap_seconds = max(5.0, float(memory_cfg.get("visit_gap_seconds", 45.0)))
        self.frequent_visit_threshold = max(2, int(memory_cfg.get("frequent_visit_threshold", 5)))
        self.loitering_seconds = max(
            30.0,
            float(memory_cfg.get("loitering_seconds", predictive_cfg.get("loitering_seconds", 90.0))),
        )
        self.risk_escalation_window = max(3, int(memory_cfg.get("risk_escalation_window", 5)))
        self.risk_escalation_delta = max(0.01, float(memory_cfg.get("risk_escalation_delta", 0.18)))
        self.zone_hopping_threshold = max(2, int(memory_cfg.get("zone_hopping_threshold", 2)))
        self.archive_after_days = max(1, int(memory_cfg.get("archive_after_days", 30)))
        self.archive_prune_interval_seconds = max(
            60.0,
            float(memory_cfg.get("archive_prune_interval_seconds", 3600.0)),
        )
        self.high_risk_threshold = self._clamp_score(memory_cfg.get("high_risk_threshold", 0.78))

        formula_cfg = memory_cfg.get("risk_formula", {}) if isinstance(memory_cfg.get("risk_formula", {}), dict) else {}
        avg_weight = max(0.0, float(formula_cfg.get("avg_weight", 0.5)))
        max_weight = max(0.0, float(formula_cfg.get("max_weight", 0.3)))
        flag_weight = max(0.0, float(formula_cfg.get("flag_weight", 0.2)))
        weight_total = avg_weight + max_weight + flag_weight
        if weight_total <= 0.0:
            avg_weight, max_weight, flag_weight = 0.5, 0.3, 0.2
            weight_total = 1.0
        self.avg_weight = avg_weight / weight_total
        self.max_weight = max_weight / weight_total
        self.flag_weight = flag_weight / weight_total

        raw_flag_weights = formula_cfg.get("flag_weights", {}) if isinstance(formula_cfg.get("flag_weights", {}), dict) else {}
        default_flag_weights = {
            "frequent_visitor": 0.45,
            "risk_escalation": 0.65,
            "loitering": 0.55,
            "zone_hopping": 0.40,
            "repeated_zone_transitions": 0.35,
            "pacing": 0.25,
            "circular_movement": 0.25,
            "sudden_speed": 0.30,
            "restricted_zone": 0.45,
        }
        flag_weights = {**default_flag_weights}
        for key, value in raw_flag_weights.items():
            token = str(key or "").strip()
            if not token:
                continue
            flag_weights[token] = self._clamp_score(value)
        self.flag_weights = flag_weights

        self._lock = Lock()
        self._last_archive_tick = 0.0
        self._init_schema()

    @staticmethod
    def _iso_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _parse_iso(value: Optional[str]) -> datetime:
        if not value:
            return datetime.now(timezone.utc)
        text = str(value).strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return datetime.now(timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    @staticmethod
    def _clamp_score(value: Any) -> float:
        try:
            score = float(value)
        except (TypeError, ValueError):
            score = 0.0
        return max(0.0, min(1.0, score))

    @staticmethod
    def _clean_token(value: Any, *, default: str = "") -> str:
        token = str(value or "").strip()
        return token or default

    @staticmethod
    def _clean_flags(flags: Any) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        if not isinstance(flags, list):
            return cleaned
        for value in flags:
            token = str(value or "").strip()
            if not token or token in seen:
                continue
            seen.add(token)
            cleaned.append(token)
        return cleaned

    @staticmethod
    def _json_loads(value: Any, *, fallback: Any) -> Any:
        if value is None:
            return fallback
        if isinstance(value, (list, dict)):
            return value
        try:
            return json.loads(str(value))
        except Exception:
            return fallback

    @staticmethod
    def _dedupe(values: list[str]) -> list[str]:
        deduped: list[str] = []
        seen: set[str] = set()
        for value in values:
            token = str(value or "").strip()
            if not token or token in seen:
                continue
            seen.add(token)
            deduped.append(token)
        return deduped

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS track_profiles (
                  track_id TEXT PRIMARY KEY,
                  first_seen TEXT NOT NULL,
                  last_seen TEXT NOT NULL,
                  visit_count INTEGER NOT NULL DEFAULT 1,
                  total_duration REAL NOT NULL DEFAULT 0,
                  avg_risk_score REAL NOT NULL DEFAULT 0,
                  max_risk_score REAL NOT NULL DEFAULT 0,
                  risk_history TEXT NOT NULL DEFAULT '[]',
                  zone_history TEXT NOT NULL DEFAULT '[]',
                  behavior_flags TEXT NOT NULL DEFAULT '[]',
                  behavior_risk_score REAL NOT NULL DEFAULT 0,
                  visit_durations TEXT NOT NULL DEFAULT '[]',
                  risk_score_sum REAL NOT NULL DEFAULT 0,
                  risk_observation_count INTEGER NOT NULL DEFAULT 0,
                  current_visit_started_at TEXT,
                  last_zone_key TEXT,
                  last_risk_score REAL NOT NULL DEFAULT 0,
                  updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS track_profiles_archive (
                  track_id TEXT PRIMARY KEY,
                  first_seen TEXT NOT NULL,
                  last_seen TEXT NOT NULL,
                  visit_count INTEGER NOT NULL DEFAULT 1,
                  total_duration REAL NOT NULL DEFAULT 0,
                  avg_risk_score REAL NOT NULL DEFAULT 0,
                  max_risk_score REAL NOT NULL DEFAULT 0,
                  risk_history TEXT NOT NULL DEFAULT '[]',
                  zone_history TEXT NOT NULL DEFAULT '[]',
                  behavior_flags TEXT NOT NULL DEFAULT '[]',
                  behavior_risk_score REAL NOT NULL DEFAULT 0,
                  visit_durations TEXT NOT NULL DEFAULT '[]',
                  risk_score_sum REAL NOT NULL DEFAULT 0,
                  risk_observation_count INTEGER NOT NULL DEFAULT 0,
                  current_visit_started_at TEXT,
                  last_zone_key TEXT,
                  last_risk_score REAL NOT NULL DEFAULT 0,
                  updated_at TEXT NOT NULL,
                  archived_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_track_profiles_last_seen ON track_profiles(last_seen DESC)"
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_track_profiles_behavior_risk
                ON track_profiles(behavior_risk_score DESC, last_seen DESC)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_track_profiles_archive_last_seen
                ON track_profiles_archive(last_seen DESC)
                """
            )
            conn.commit()

    def _log_event(self, event: str, **payload: Any) -> None:
        body = {
            "event": event,
            "timestamp": self._iso_now(),
            **payload,
        }
        logger.info(json.dumps(body, default=str))

    def _archive_stale_locked(self, *, force: bool = False) -> None:
        if not self.enabled:
            return
        now_tick = monotonic()
        if not force and (now_tick - self._last_archive_tick) < self.archive_prune_interval_seconds:
            return
        self._last_archive_tick = now_tick
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.archive_after_days)).isoformat()
        archived_at = self._iso_now()

        with self._connect() as conn:
            stale_rows = conn.execute(
                "SELECT track_id FROM track_profiles WHERE last_seen < ?",
                (cutoff,),
            ).fetchall()
            if not stale_rows:
                return
            conn.execute(
                """
                INSERT OR REPLACE INTO track_profiles_archive (
                  track_id, first_seen, last_seen, visit_count, total_duration, avg_risk_score, max_risk_score,
                  risk_history, zone_history, behavior_flags, behavior_risk_score, visit_durations,
                  risk_score_sum, risk_observation_count, current_visit_started_at, last_zone_key,
                  last_risk_score, updated_at, archived_at
                )
                SELECT
                  track_id, first_seen, last_seen, visit_count, total_duration, avg_risk_score, max_risk_score,
                  risk_history, zone_history, behavior_flags, behavior_risk_score, visit_durations,
                  risk_score_sum, risk_observation_count, current_visit_started_at, last_zone_key,
                  last_risk_score, updated_at, ?
                FROM track_profiles
                WHERE last_seen < ?
                """,
                (archived_at, cutoff),
            )
            conn.execute("DELETE FROM track_profiles WHERE last_seen < ?", (cutoff,))
            conn.commit()

        for row in stale_rows:
            track_id = self._clean_token(row["track_id"])
            if track_id:
                self._log_event(
                    "TRACK_PROFILE_ARCHIVED",
                    track_id=track_id,
                    archived_at=archived_at,
                )

    def _compute_behavior_flags(
        self,
        *,
        visit_count: int,
        risk_history: list[float],
        zone_history: list[str],
        visit_durations: list[float],
        current_visit_started_at: Optional[str],
        last_seen: str,
        extra_flags: list[str],
    ) -> list[str]:
        flags = set(self._clean_flags(extra_flags))

        if int(visit_count) >= self.frequent_visit_threshold:
            flags.add("frequent_visitor")

        if len(risk_history) >= self.risk_escalation_window:
            recent = [self._clamp_score(value) for value in risk_history[-self.risk_escalation_window :]]
            deltas = [recent[idx + 1] - recent[idx] for idx in range(len(recent) - 1)]
            positive_steps = sum(1 for delta in deltas if delta > 0.0)
            if (recent[-1] - recent[0]) >= self.risk_escalation_delta and positive_steps >= max(1, len(deltas) - 1):
                flags.add("risk_escalation")

        current_duration = 0.0
        if current_visit_started_at:
            current_duration = max(
                0.0,
                (self._parse_iso(last_seen) - self._parse_iso(current_visit_started_at)).total_seconds(),
            )
        longest_duration = max([current_duration, *[max(0.0, float(value)) for value in visit_durations]], default=0.0)
        if longest_duration >= self.loitering_seconds:
            flags.add("loitering")

        if len(self._dedupe(zone_history)) >= self.zone_hopping_threshold:
            flags.add("zone_hopping")

        return sorted(flags)

    def _compute_behavior_risk(
        self,
        *,
        avg_risk_score: float,
        max_risk_score: float,
        behavior_flags: list[str],
    ) -> float:
        flag_score = 0.0
        for flag in behavior_flags:
            flag_score = min(1.0, flag_score + self._clamp_score(self.flag_weights.get(flag, 0.15)))
        risk = (
            self.avg_weight * self._clamp_score(avg_risk_score)
            + self.max_weight * self._clamp_score(max_risk_score)
            + self.flag_weight * flag_score
        )
        return round(self._clamp_score(risk), 4)

    def _row_to_profile(self, row: Optional[sqlite3.Row], *, archived: bool = False) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        risk_history = [
            round(self._clamp_score(value), 4)
            for value in self._json_loads(row["risk_history"], fallback=[])
            if isinstance(value, (int, float))
        ]
        zone_history = [
            self._clean_token(value)
            for value in self._json_loads(row["zone_history"], fallback=[])
            if self._clean_token(value)
        ]
        behavior_flags = self._clean_flags(self._json_loads(row["behavior_flags"], fallback=[]))
        visit_durations = [
            round(max(0.0, float(value)), 3)
            for value in self._json_loads(row["visit_durations"], fallback=[])
            if isinstance(value, (int, float))
        ]
        last_seen = self._clean_token(row["last_seen"])
        current_visit_started_at = self._clean_token(row["current_visit_started_at"])
        current_visit_duration = 0.0
        if current_visit_started_at and last_seen:
            current_visit_duration = max(
                0.0,
                (self._parse_iso(last_seen) - self._parse_iso(current_visit_started_at)).total_seconds(),
            )
        behavior_risk = round(self._clamp_score(row["behavior_risk_score"]), 4)
        profile = {
            "track_id": self._clean_token(row["track_id"]),
            "first_seen": self._clean_token(row["first_seen"]),
            "last_seen": last_seen,
            "visit_count": int(row["visit_count"] or 0),
            "visits": int(row["visit_count"] or 0),
            "total_duration": round(max(0.0, float(row["total_duration"] or 0.0)), 3),
            "avg_risk_score": round(self._clamp_score(row["avg_risk_score"]), 4),
            "avg_risk": round(self._clamp_score(row["avg_risk_score"]), 4),
            "max_risk_score": round(self._clamp_score(row["max_risk_score"]), 4),
            "max_risk": round(self._clamp_score(row["max_risk_score"]), 4),
            "behavior_risk_score": behavior_risk,
            "final_behavior_risk_score": behavior_risk,
            "risk_history": risk_history,
            "zone_history": zone_history,
            "zones": self._dedupe(zone_history),
            "behavior_flags": behavior_flags,
            "visit_durations": visit_durations,
            "current_visit_started_at": current_visit_started_at or None,
            "current_visit_duration": round(current_visit_duration, 3),
            "last_zone_key": self._clean_token(row["last_zone_key"]) or (zone_history[-1] if zone_history else None),
            "last_risk_score": round(self._clamp_score(row["last_risk_score"]), 4),
            "updated_at": self._clean_token(row["updated_at"]),
            "high_risk": behavior_risk >= self.high_risk_threshold,
            "archived": archived,
        }
        if archived:
            profile["archived_at"] = self._clean_token(row["archived_at"])
        return profile

    def compact_profile(self, profile: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(profile, dict):
            return None
        return {
            "track_id": profile.get("track_id"),
            "first_seen": profile.get("first_seen"),
            "last_seen": profile.get("last_seen"),
            "visit_count": profile.get("visit_count"),
            "visits": profile.get("visits"),
            "total_duration": profile.get("total_duration"),
            "avg_risk_score": profile.get("avg_risk_score"),
            "max_risk_score": profile.get("max_risk_score"),
            "behavior_risk_score": profile.get("behavior_risk_score"),
            "behavior_flags": list(profile.get("behavior_flags", [])),
            "zones": list(profile.get("zones", [])),
            "zone_history": list(profile.get("zone_history", [])),
            "risk_history": list(profile.get("risk_history", [])),
            "high_risk": bool(profile.get("high_risk")),
            "current_visit_duration": profile.get("current_visit_duration"),
            "last_zone_key": profile.get("last_zone_key"),
            "archived": bool(profile.get("archived")),
        }

    def update_track_profile(
        self,
        *,
        track_id: str,
        zone_key: str,
        risk_score: float,
        timestamp: Optional[str] = None,
        behavior_flags: Optional[list[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        safe_track_id = self._clean_token(track_id)
        safe_zone_key = self._clean_token(zone_key, default="zone:unknown")
        if not safe_track_id:
            return None

        safe_timestamp = self._clean_token(timestamp, default=self._iso_now())
        score = self._clamp_score(risk_score)
        extra_flags = self._clean_flags(behavior_flags or [])

        with self._lock:
            self._archive_stale_locked()
            with self._connect() as conn:
                row = conn.execute("SELECT * FROM track_profiles WHERE track_id = ?", (safe_track_id,)).fetchone()
                created = row is None
                if row is None:
                    risk_history = [round(score, 4)]
                    zone_history = [safe_zone_key]
                    visit_durations: list[float] = []
                    visit_count = 1
                    total_duration = 0.0
                    avg_risk_score = round(score, 4)
                    max_risk_score = round(score, 4)
                    risk_score_sum = score
                    risk_observation_count = 1
                    current_visit_started_at = safe_timestamp
                    last_seen = safe_timestamp
                else:
                    risk_history = [
                        round(self._clamp_score(value), 4)
                        for value in self._json_loads(row["risk_history"], fallback=[])
                        if isinstance(value, (int, float))
                    ]
                    risk_history.append(round(score, 4))
                    risk_history = risk_history[-self.history_limit :]

                    zone_history = [
                        self._clean_token(value)
                        for value in self._json_loads(row["zone_history"], fallback=[])
                        if self._clean_token(value)
                    ]
                    if not zone_history or zone_history[-1] != safe_zone_key:
                        zone_history.append(safe_zone_key)
                    zone_history = zone_history[-self.zone_history_limit :]

                    visit_durations = [
                        round(max(0.0, float(value)), 3)
                        for value in self._json_loads(row["visit_durations"], fallback=[])
                        if isinstance(value, (int, float))
                    ]
                    visit_count = int(row["visit_count"] or 0)
                    total_duration = max(0.0, float(row["total_duration"] or 0.0))
                    risk_score_sum = max(0.0, float(row["risk_score_sum"] or 0.0)) + score
                    risk_observation_count = max(0, int(row["risk_observation_count"] or 0)) + 1
                    last_seen = self._clean_token(row["last_seen"], default=safe_timestamp)
                    last_seen_dt = self._parse_iso(last_seen)
                    current_visit_started_at = self._clean_token(row["current_visit_started_at"], default=row["first_seen"])
                    current_visit_started_dt = self._parse_iso(current_visit_started_at)
                    safe_timestamp_dt = self._parse_iso(safe_timestamp)
                    delta_seconds = max(0.0, (safe_timestamp_dt - last_seen_dt).total_seconds())

                    if delta_seconds <= self.visit_gap_seconds:
                        total_duration += delta_seconds
                    else:
                        prior_visit_duration = max(0.0, (last_seen_dt - current_visit_started_dt).total_seconds())
                        if prior_visit_duration > 0.0:
                            visit_durations.append(round(prior_visit_duration, 3))
                            visit_durations = visit_durations[-self.visit_history_limit :]
                        visit_count += 1
                        current_visit_started_at = safe_timestamp
                    last_seen = safe_timestamp

                    avg_risk_score = round(risk_score_sum / max(1, risk_observation_count), 4)
                    max_risk_score = round(max(self._clamp_score(row["max_risk_score"]), score), 4)

                computed_flags = self._compute_behavior_flags(
                    visit_count=visit_count,
                    risk_history=risk_history,
                    zone_history=zone_history,
                    visit_durations=visit_durations,
                    current_visit_started_at=current_visit_started_at,
                    last_seen=last_seen,
                    extra_flags=extra_flags,
                )
                behavior_risk_score = self._compute_behavior_risk(
                    avg_risk_score=avg_risk_score,
                    max_risk_score=max_risk_score,
                    behavior_flags=computed_flags,
                )
                updated_at = self._iso_now()

                if created:
                    conn.execute(
                        """
                        INSERT INTO track_profiles (
                          track_id, first_seen, last_seen, visit_count, total_duration, avg_risk_score, max_risk_score,
                          risk_history, zone_history, behavior_flags, behavior_risk_score, visit_durations,
                          risk_score_sum, risk_observation_count, current_visit_started_at, last_zone_key,
                          last_risk_score, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            safe_track_id,
                            safe_timestamp,
                            last_seen,
                            visit_count,
                            round(total_duration, 3),
                            avg_risk_score,
                            max_risk_score,
                            json.dumps(risk_history),
                            json.dumps(zone_history),
                            json.dumps(computed_flags),
                            behavior_risk_score,
                            json.dumps(visit_durations),
                            round(risk_score_sum, 6),
                            risk_observation_count,
                            current_visit_started_at,
                            safe_zone_key,
                            round(score, 4),
                            updated_at,
                        ),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE track_profiles
                        SET
                          last_seen = ?,
                          visit_count = ?,
                          total_duration = ?,
                          avg_risk_score = ?,
                          max_risk_score = ?,
                          risk_history = ?,
                          zone_history = ?,
                          behavior_flags = ?,
                          behavior_risk_score = ?,
                          visit_durations = ?,
                          risk_score_sum = ?,
                          risk_observation_count = ?,
                          current_visit_started_at = ?,
                          last_zone_key = ?,
                          last_risk_score = ?,
                          updated_at = ?
                        WHERE track_id = ?
                        """,
                        (
                            last_seen,
                            visit_count,
                            round(total_duration, 3),
                            avg_risk_score,
                            max_risk_score,
                            json.dumps(risk_history),
                            json.dumps(zone_history),
                            json.dumps(computed_flags),
                            behavior_risk_score,
                            json.dumps(visit_durations[-self.visit_history_limit :]),
                            round(risk_score_sum, 6),
                            risk_observation_count,
                            current_visit_started_at,
                            safe_zone_key,
                            round(score, 4),
                            updated_at,
                            safe_track_id,
                        ),
                    )
                conn.commit()

                saved_row = conn.execute("SELECT * FROM track_profiles WHERE track_id = ?", (safe_track_id,)).fetchone()

        profile = self._row_to_profile(saved_row, archived=False)
        if profile is not None:
            self._log_event(
                "TRACK_UPDATED",
                track_id=safe_track_id,
                zone_key=safe_zone_key,
                risk_score=round(score, 4),
                flags=list(profile.get("behavior_flags", [])),
                behavior_risk=profile.get("behavior_risk_score"),
                visit_count=profile.get("visit_count"),
            )
        return profile

    def get_track_profile(self, track_id: str, *, include_archive: bool = True) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        safe_track_id = self._clean_token(track_id)
        if not safe_track_id:
            return None
        with self._lock:
            self._archive_stale_locked()
            with self._connect() as conn:
                row = conn.execute("SELECT * FROM track_profiles WHERE track_id = ?", (safe_track_id,)).fetchone()
                if row is not None:
                    return self._row_to_profile(row, archived=False)
                if include_archive:
                    archived_row = conn.execute(
                        "SELECT * FROM track_profiles_archive WHERE track_id = ?",
                        (safe_track_id,),
                    ).fetchone()
                    return self._row_to_profile(archived_row, archived=True)
        return None

    def get_high_risk_profiles(
        self,
        *,
        limit: int = 100,
        threshold: Optional[float] = None,
    ) -> list[Dict[str, Any]]:
        if not self.enabled:
            return []
        count = max(1, min(int(limit), 1000))
        safe_threshold = self._clamp_score(self.high_risk_threshold if threshold is None else threshold)
        with self._lock:
            self._archive_stale_locked()
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM track_profiles
                    WHERE behavior_risk_score >= ?
                    ORDER BY behavior_risk_score DESC, last_seen DESC
                    LIMIT ?
                    """,
                    (safe_threshold, count),
                ).fetchall()
        return [profile for profile in (self._row_to_profile(row, archived=False) for row in rows) if profile]
