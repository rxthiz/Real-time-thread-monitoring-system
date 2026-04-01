import argparse
import asyncio
import json
from typing import Any, Dict, Optional

from cache.redis_client import RedisCache, get_redis


def _extract_original_payload(dlq_record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    payload = dlq_record.get("original_payload")
    if isinstance(payload, dict):
        return dict(payload)
    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            return None
        return dict(parsed) if isinstance(parsed, dict) else None
    return None


async def replay_dlq(limit: int, dry_run: bool) -> Dict[str, int]:
    cache = RedisCache(get_redis())
    processed = 0
    requeued = 0
    invalid = 0

    for _ in range(limit):
        dlq_record = await cache.pop_alert_dlq()
        if dlq_record is None:
            break
        processed += 1

        original_payload = _extract_original_payload(dlq_record)
        if original_payload is None:
            invalid += 1
            await cache.incr_metric("alerts_dlq_replay_invalid_total", 1)
            continue

        # Reset retry count before replay so worker can retry normally again.
        original_payload["retry_count"] = 0
        if not dry_run:
            await cache.push_alert_queue(original_payload)
            requeued += 1
            await cache.incr_metric("alerts_dlq_replayed_total", 1)

    return {
        "processed": processed,
        "requeued": requeued,
        "invalid": invalid,
        "dry_run": 1 if dry_run else 0,
    }


async def _amain() -> None:
    parser = argparse.ArgumentParser(description="Replay alert messages from Redis DLQ back to main queue.")
    parser.add_argument("--limit", type=int, default=100, help="Max number of DLQ records to process.")
    parser.add_argument("--dry-run", action="store_true", help="Read and validate DLQ records without re-queueing.")
    args = parser.parse_args()

    if args.limit <= 0:
        raise SystemExit("--limit must be > 0")

    summary = await replay_dlq(limit=args.limit, dry_run=args.dry_run)
    print(json.dumps(summary))


if __name__ == "__main__":
    asyncio.run(_amain())
