import math
import os
from datetime import datetime, timezone
from typing import Any, Dict

import httpx

OVERPASS_API_URL = os.getenv("OVERPASS_API_URL", "https://overpass-api.de/api/interpreter")
OVERPASS_TIMEOUT_SEC = float(os.getenv("OVERPASS_TIMEOUT_SEC", "20"))
ALLOWED_RADIUS_KM = {2, 5, 10}

AMENITY_BUCKET = {
    "hospital": "hospitals",
    "police": "police_stations",
    "fire_station": "fire_stations",
}

DEFAULT_NAME_BY_BUCKET = {
    "hospitals": "Hospital",
    "police_stations": "Police Station",
    "fire_stations": "Fire Station",
}


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius_km = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)

    a = math.sin(d_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return radius_km * c


def _extract_lat_lon(element: Dict[str, Any]) -> tuple[float, float] | None:
    lat = element.get("lat")
    lon = element.get("lon")
    if lat is None or lon is None:
        center = element.get("center") or {}
        lat = center.get("lat")
        lon = center.get("lon")
    if lat is None or lon is None:
        return None
    return float(lat), float(lon)


def _build_overpass_query(lat: float, lon: float, radius_m: int) -> str:
    return f"""
[out:json][timeout:25];
(
  node["amenity"="hospital"](around:{radius_m},{lat:.7f},{lon:.7f});
  way["amenity"="hospital"](around:{radius_m},{lat:.7f},{lon:.7f});
  relation["amenity"="hospital"](around:{radius_m},{lat:.7f},{lon:.7f});
  node["amenity"="police"](around:{radius_m},{lat:.7f},{lon:.7f});
  way["amenity"="police"](around:{radius_m},{lat:.7f},{lon:.7f});
  relation["amenity"="police"](around:{radius_m},{lat:.7f},{lon:.7f});
  node["amenity"="fire_station"](around:{radius_m},{lat:.7f},{lon:.7f});
  way["amenity"="fire_station"](around:{radius_m},{lat:.7f},{lon:.7f});
  relation["amenity"="fire_station"](around:{radius_m},{lat:.7f},{lon:.7f});
);
out center tags;
""".strip()


async def fetch_nearby_services(lat: float, lon: float, radius_km: int = 5) -> Dict[str, Any]:
    if not (-90 <= lat <= 90):
        raise ValueError("Latitude must be between -90 and 90")
    if not (-180 <= lon <= 180):
        raise ValueError("Longitude must be between -180 and 180")
    if radius_km not in ALLOWED_RADIUS_KM:
        allowed = ", ".join(str(v) for v in sorted(ALLOWED_RADIUS_KM))
        raise ValueError(f"radius_km must be one of: {allowed}")

    radius_m = int(radius_km * 1000)
    query = _build_overpass_query(lat=lat, lon=lon, radius_m=radius_m)

    try:
        async with httpx.AsyncClient(timeout=OVERPASS_TIMEOUT_SEC) as client:
            response = await client.post(
                OVERPASS_API_URL,
                data=query,
                headers={"Content-Type": "text/plain", "User-Agent": "ThreatMonitor/2.0"},
            )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        raise RuntimeError(f"Overpass request failed: {exc}") from exc

    buckets: Dict[str, list[Dict[str, Any]]] = {
        "hospitals": [],
        "police_stations": [],
        "fire_stations": [],
    }
    dedupe: set[tuple[str, int, int, str]] = set()

    for element in payload.get("elements", []):
        tags = element.get("tags") or {}
        amenity = str(tags.get("amenity", "")).strip()
        bucket = AMENITY_BUCKET.get(amenity)
        if bucket is None:
            continue

        point = _extract_lat_lon(element)
        if point is None:
            continue

        place_lat, place_lon = point
        distance_km = _distance_km(lat, lon, place_lat, place_lon)
        if distance_km > radius_km + 0.05:
            continue

        name = str(tags.get("name") or DEFAULT_NAME_BY_BUCKET[bucket]).strip()
        key = (bucket, int(round(place_lat * 1_000_000)), int(round(place_lon * 1_000_000)), name.lower())
        if key in dedupe:
            continue
        dedupe.add(key)

        address = ", ".join(
            part
            for part in [
                tags.get("addr:housenumber"),
                tags.get("addr:street"),
                tags.get("addr:city"),
            ]
            if part
        )

        buckets[bucket].append(
            {
                "name": name,
                "lat": round(place_lat, 6),
                "lon": round(place_lon, 6),
                "distance_km": round(distance_km, 3),
                "address": address or None,
                "osm_id": int(element.get("id", 0)),
                "osm_type": str(element.get("type", "")),
            }
        )

    for bucket in buckets.values():
        bucket.sort(key=lambda item: float(item.get("distance_km", 0.0)))

    total = sum(len(v) for v in buckets.values())
    return {
        "camera_location": {"lat": round(lat, 6), "lon": round(lon, 6)},
        "radius_km": radius_km,
        "hospitals": buckets["hospitals"],
        "police_stations": buckets["police_stations"],
        "fire_stations": buckets["fire_stations"],
        "total": total,
        "source": OVERPASS_API_URL,
        "timestamp": _iso_now(),
    }
