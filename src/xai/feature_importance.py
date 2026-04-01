from typing import Any, Dict, Iterable, List


def build_feature_importance(
    factors: Iterable[Dict[str, Any]],
    *,
    max_items: int = 5,
) -> List[Dict[str, Any]]:
    items = []
    for factor in factors:
        impact = abs(float(factor.get("impact", 0.0) or 0.0))
        if impact <= 0.0:
            continue
        name = str(factor.get("name", "")).strip() or "factor"
        value = factor.get("value")
        items.append(
            {
                "feature": f"{name}={value}",
                "importance": impact,
            }
        )

    if not items:
        return []

    ranked = sorted(items, key=lambda item: item["importance"], reverse=True)[: max(1, int(max_items))]
    total = sum(item["importance"] for item in ranked) or 1.0
    return [
        {
            "feature": item["feature"],
            "importance": round(item["importance"] / total, 4),
        }
        for item in ranked
    ]
