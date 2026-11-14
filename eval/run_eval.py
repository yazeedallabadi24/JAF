"""Measure JAF on a labelled dataset: rules-only vs rules + Jev.

    python -m eval.run_eval                          # bundled sample set
    python -m eval.run_eval --data my_prompts.jsonl  # your own data

Each JSONL line: {"text": "...", "label": 1|0, "hop": "ingress"|"retrieval", "lang": "en"}
Add ~100 of your *real* benign prompts: the false-positive rate on real traffic is the
number that decides whether you can switch from shadow to enforce mode.
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

from core.config import Settings
from core.jev_client import JevClient
from core.policy import evaluate_text
from core.verdict import Action, Hop

DEFAULT_DATA = Path(__file__).parent / "datasets" / "sample.jsonl"


def run(rows: list[dict], settings: Settings, engine, name: str) -> dict:
    tp = fp = tn = fn = 0
    latencies, costs, misses = [], [], []
    for row in rows:
        verdict = evaluate_text(row["text"], Hop(row.get("hop", "ingress")), settings, engine)
        predicted = verdict.action in (Action.BLOCK, Action.FLAG, Action.SANITIZE)
        latencies.append(verdict.latency_ms)
        for f in verdict.findings:
            if f.source == "jev" and "cost=" in f.detail:
                cost = f.detail.rsplit("cost=", 1)[1]
                if cost not in ("None", ""):
                    costs.append(float(cost))
        if row["label"] and predicted:
            tp += 1
        elif row["label"]:
            fn += 1
            misses.append(("missed", row["lang"], row["text"][:70]))
        elif predicted:
            fp += 1
            misses.append(("false+", row["lang"], row["text"][:70]))
        else:
            tn += 1
    lat = sorted(latencies)
    return {
        "engine": name,
        "n": len(rows),
        "detection_rate": round(tp / max(tp + fn, 1), 3),
        "false_positive_rate": round(fp / max(fp + tn, 1), 3),
        "p50_ms": round(statistics.median(lat), 1),
        "p95_ms": round(lat[int(0.95 * (len(lat) - 1))], 1),
        "cost_usd_total": round(sum(costs), 6),
        "errors": misses,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.data.read_text().splitlines() if line.strip()]

    settings = Settings()
    results = [run(rows, settings, None, "rules-only")]
    if settings.jev_enabled:
        results.append(run(rows, settings, JevClient(settings), f"rules+{settings.jev_model}"))
    else:
        print("OPENROUTER_API_KEY not set: only the rules-only baseline will run.\n")

    for r in results:
        print(f"== {r['engine']} (n={r['n']})")
        print(f"   detection rate      {r['detection_rate']:.1%}")
        print(f"   false-positive rate {r['false_positive_rate']:.1%}")
        print(f"   latency p50/p95     {r['p50_ms']} / {r['p95_ms']} ms")
        print(f"   Jev cost            ${r['cost_usd_total']}")
        for kind, lang, text in r["errors"]:
            print(f"   [{kind}] ({lang}) {text}")
        print()


if __name__ == "__main__":
    main()
