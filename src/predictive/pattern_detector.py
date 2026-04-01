import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def parse_iso(value: Optional[str]) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def point_distance(left: Dict[str, Any], right: Dict[str, Any]) -> float:
    return math.hypot(float(right.get("x", 0.0)) - float(left.get("x", 0.0)), float(right.get("y", 0.0)) - float(left.get("y", 0.0)))


def recent_points(path: List[Dict[str, Any]], *, within_seconds: float) -> List[Dict[str, Any]]:
    if not path:
        return []
    latest_dt = parse_iso(path[-1].get("ts"))
    out: List[Dict[str, Any]] = []
    for point in reversed(path):
        delta = (latest_dt - parse_iso(point.get("ts"))).total_seconds()
        if delta > float(within_seconds):
            break
        out.append(point)
    out.reverse()
    return out


def current_zone_duration_seconds(path: List[Dict[str, Any]], *, default_start_ts: Optional[str] = None) -> float:
    if not path:
        return 0.0
    current_zone = str(path[-1].get("zone_key") or "")
    latest_dt = parse_iso(path[-1].get("ts"))
    earliest_dt = parse_iso(default_start_ts) if default_start_ts else latest_dt
    for point in reversed(path):
        if str(point.get("zone_key") or "") != current_zone:
            break
        earliest_dt = parse_iso(point.get("ts"))
    return max(0.0, (latest_dt - earliest_dt).total_seconds())


def compressed_zone_sequence(points: List[Dict[str, Any]]) -> List[str]:
    sequence: List[str] = []
    for point in points:
        zone_key = str(point.get("zone_key") or "").strip()
        if not zone_key:
            continue
        if not sequence or sequence[-1] != zone_key:
            sequence.append(zone_key)
    return sequence


def zone_transition_stats(
    path: List[Dict[str, Any]],
    *,
    within_seconds: float,
    transition_threshold: int,
) -> Dict[str, Any]:
    points = recent_points(path, within_seconds=within_seconds)
    sequence = compressed_zone_sequence(points)
    transitions = max(0, len(sequence) - 1)
    score = min(1.0, transitions / max(1, int(transition_threshold)))
    return {
        "transition_count": transitions,
        "transition_sequence": sequence,
        "score": round(score, 4),
    }


def _segment_speeds(points: List[Dict[str, Any]]) -> List[Dict[str, float]]:
    speeds: List[Dict[str, float]] = []
    for index in range(1, len(points)):
        previous = points[index - 1]
        current = points[index]
        if str(previous.get("zone_key") or "") != str(current.get("zone_key") or ""):
            continue
        if str(previous.get("camera_id") or "") != str(current.get("camera_id") or ""):
            continue
        dt = (parse_iso(current.get("ts")) - parse_iso(previous.get("ts"))).total_seconds()
        if dt <= 0.05:
            continue
        distance = point_distance(previous, current)
        speeds.append({"speed": distance / dt, "dt": dt})
    return speeds


def speed_stats(
    path: List[Dict[str, Any]],
    *,
    within_seconds: float,
    speed_threshold: float,
    acceleration_threshold: float,
) -> Dict[str, Any]:
    points = recent_points(path, within_seconds=within_seconds)
    speeds = _segment_speeds(points)
    if not speeds:
        return {
            "score": 0.0,
            "avg_speed": 0.0,
            "max_speed": 0.0,
            "max_acceleration": 0.0,
        }

    values = [item["speed"] for item in speeds]
    avg_speed = sum(values) / len(values)
    max_speed = max(values)
    max_acceleration = 0.0
    for index in range(1, len(speeds)):
        dt = max(speeds[index]["dt"], 0.05)
        acceleration = max(0.0, (speeds[index]["speed"] - speeds[index - 1]["speed"]) / dt)
        max_acceleration = max(max_acceleration, acceleration)

    speed_score = min(1.0, max_speed / max(float(speed_threshold), 0.01))
    accel_score = min(1.0, max_acceleration / max(float(acceleration_threshold), 0.01))
    return {
        "score": round(max(speed_score, accel_score), 4),
        "avg_speed": round(avg_speed, 4),
        "max_speed": round(max_speed, 4),
        "max_acceleration": round(max_acceleration, 4),
    }


def pacing_stats(
    path: List[Dict[str, Any]],
    *,
    within_seconds: float,
    switch_threshold: int,
) -> Dict[str, Any]:
    points = recent_points(path, within_seconds=within_seconds)
    zone_sequence = compressed_zone_sequence(points)
    alternating_hits = 0
    for index in range(2, len(zone_sequence)):
        if zone_sequence[index] == zone_sequence[index - 2] and zone_sequence[index] != zone_sequence[index - 1]:
            alternating_hits += 1
    zone_score = min(1.0, alternating_hits / max(1, int(switch_threshold)))

    recent_same_zone = [point for point in points if str(point.get("zone_key") or "") == str(points[-1].get("zone_key") or "")] if points else []
    deltas_x: List[float] = []
    deltas_y: List[float] = []
    total_distance = 0.0
    displacement = 0.0
    sign_changes = 0
    if len(recent_same_zone) >= 3:
        for index in range(1, len(recent_same_zone)):
            left = recent_same_zone[index - 1]
            right = recent_same_zone[index]
            dx = float(right.get("x", 0.0)) - float(left.get("x", 0.0))
            dy = float(right.get("y", 0.0)) - float(left.get("y", 0.0))
            deltas_x.append(dx)
            deltas_y.append(dy)
            total_distance += math.hypot(dx, dy)
        displacement = point_distance(recent_same_zone[0], recent_same_zone[-1])
        axis = deltas_x if sum(abs(value) for value in deltas_x) >= sum(abs(value) for value in deltas_y) else deltas_y
        previous_sign = 0
        for value in axis:
            if abs(value) < 0.015:
                continue
            current_sign = 1 if value > 0 else -1
            if previous_sign and current_sign != previous_sign:
                sign_changes += 1
            previous_sign = current_sign
    axis_score = 0.0
    if total_distance > 0.0:
        return_ratio = max(0.0, min(1.0, 1.0 - (displacement / total_distance)))
        axis_score = min(1.0, sign_changes / max(2, int(switch_threshold))) * return_ratio

    return {
        "score": round(max(zone_score, axis_score), 4),
        "alternating_hits": alternating_hits,
        "sign_changes": sign_changes,
        "return_ratio": round(axis_score if axis_score <= 1.0 else 1.0, 4),
    }


def circular_stats(
    path: List[Dict[str, Any]],
    *,
    within_seconds: float,
    min_distance: float,
    close_ratio: float,
) -> Dict[str, Any]:
    points = recent_points(path, within_seconds=within_seconds)
    if len(points) < 5:
        return {
            "score": 0.0,
            "distance": 0.0,
            "closure_ratio": 0.0,
        }

    total_distance = 0.0
    min_x = max_x = float(points[0].get("x", 0.0))
    min_y = max_y = float(points[0].get("y", 0.0))
    for index in range(1, len(points)):
        total_distance += point_distance(points[index - 1], points[index])
        min_x = min(min_x, float(points[index].get("x", 0.0)))
        max_x = max(max_x, float(points[index].get("x", 0.0)))
        min_y = min(min_y, float(points[index].get("y", 0.0)))
        max_y = max(max_y, float(points[index].get("y", 0.0)))

    if total_distance < float(min_distance):
        return {
            "score": 0.0,
            "distance": round(total_distance, 4),
            "closure_ratio": 0.0,
        }

    displacement = point_distance(points[0], points[-1])
    closure_ratio = displacement / max(total_distance, 0.0001)
    coverage = min(1.0, (max_x - min_x) / 0.25) * min(1.0, (max_y - min_y) / 0.25)
    if closure_ratio > float(close_ratio):
        score = 0.0
    else:
        score = max(0.0, min(1.0, (1.0 - (closure_ratio / max(float(close_ratio), 0.01))) * coverage))

    return {
        "score": round(score, 4),
        "distance": round(total_distance, 4),
        "closure_ratio": round(closure_ratio, 4),
    }
