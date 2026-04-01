from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cache.redis_client import RedisCache
from db.models import Track


class TrackService:
    def __init__(self, db: AsyncSession, cache: Optional[RedisCache] = None) -> None:
        self.db = db
        self.cache = cache or RedisCache()

    async def get_track(self, track_id: str) -> Optional[Track | Dict[str, Any]]:
        cached = await self.cache.get_track_state(track_id)
        if cached:
            return cached

        result = await self.db.execute(select(Track).where(Track.track_id == track_id))
        track = result.scalar_one_or_none()
        if track:
            await self.cache.cache_track_state(track_id, track.behavior_profile or {})
        return track
