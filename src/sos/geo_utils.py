import math
from typing import Tuple


def validate_lat_lon(lat: float, lng: float) -> Tuple[float, float]:
    lat_f = float(lat)
    lng_f = float(lng)
    if lat_f < -90 or lat_f > 90:
        raise ValueError("Latitude must be between -90 and 90")
    if lng_f < -180 or lng_f > 180:
        raise ValueError("Longitude must be between -180 and 180")
    return lat_f, lng_f


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometers."""
    lat1, lon1 = validate_lat_lon(lat1, lon1)
    lat2, lon2 = validate_lat_lon(lat2, lon2)
    radius_km = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return radius_km * c
