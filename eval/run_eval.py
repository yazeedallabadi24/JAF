"""Measure JAF on labelled data: rules-only vs rules + Jev.

    python -m eval.run_eval                                   # bundled sample set
    python -m eval.fetch_datasets && python -m eval.run_eval --public   # + public test sets
    python -m eval.run_eval --data my_prompts.jsonl           # your own data

Each JSONL line: {"text": "...", "label": 1|0, "hop": "ingress"|"retrieval", "lang": "en", "source": "..."}
Add ~100 of your *real* benign prompts: the false-positive rate on real traffic is the
number that decides whether you can switch from shadow to enforce mode.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from core.config import Settings
from core.jev_client import JevClient
from core.phase2_retrieval_gate import sanitize
from core.policy import evaluate_text
from core.verdict import Action, Hop

DATA_DIR = Path(__file__).parent / "datasets"
DEFAULT_DATA = DATA_DIR / "sample.jsonl"
RESULTS_DIR = Path(__file__).parent / "results"
SWEEP = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95]


def load(paths: list[Path]) -> list[dict]:
    rows = []
    for path in paths:
        if not path.exists():
            raise SystemExit(
                f"File not found: {path}\n"
                "Create it first: either a .txt file with one real (benign) prompt per line, or a "
                '.jsonl file with lines like {"text": "...", "label": 0}.'
            )
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            if path.suffix == ".txt":
                # Plain text: one real user prompt per line, assumed benign (label 0).
                row = {"text": line.strip(), "label": 0, "hop": "ingress", "lang": "?"}
            else:
                row = json.loads(line)
            row.setdefault("source", path.stem)
            rows.append(row)
    return rows


def score_rows(rows: list[dict], settings: Settings, engine, workers: int) -> list[dict]:
    def one(row: dict) -> dict:
        hop = Hop(row.get("hop", "ingress"))
        if hop == Hop.RETRIEVAL:
            # Real Hop 2 path: chunk, classify each chunk, sanitize.
            v = sanitize(row["text"], settings, engine)
        else:
            v = evaluate_text(row["text"], hop, settings, engine)
        cost = 0.0
        jev_error = False
        for f in v.findings:
            if f.source == "jev" and "cost=" in f.detail:
                c = f.detail.rsplit("cost=", 1)[1]
                cost += float(c) if c not in ("None", "") else 0.0
            if f.source == "jev" and "unavailable" in f.detail:
                jev_error = True
        return {**row, "score": v.score, "action": v.action.value, "engine": v.engine,
                "category": v.category.value, "latency_ms": v.latency_ms, "cost": cost,
                "jev_error": jev_error,
                "predicted": v.action in (Action.BLOCK, Action.FLAG, Action.SANITIZE)}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(one, rows))


def metrics(scored: list[dict], key=lambda r: r["predicted"]) -> dict:
    tp = sum(1 for r in scored if r["label"] and key(r))
    fn = sum(1 for r in scored if r["label"] and not key(r))
    fp = sum(1 for r in scored if not r["label"] and key(r))
    tn = sum(1 for r in scored if not r["label"] and not key(r))
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    return {"n": len(scored), "detection": recall, "fpr": fp / max(fp + tn, 1),
            "precision": precision, "f1": 2 * precision * recall / max(precision + recall, 1e-9),
            "tp": tp, "fn": fn, "fp": fp, "tn": tn}


def report(name: str, scored: list[dict], show_errors: int) -> None:
    m = metrics(scored)
    lat = sorted(r["latency_ms"] for r in scored)
    jev_lat = sorted(r["latency_ms"] for r in scored if r["engine"] == "jev")
    print(f"== {name} (n={m['n']}: {m['tp'] + m['fn']} attacks, {m['fp'] + m['tn']} benign)")
    if m["tp"] + m["fn"] == 0:
        # Benign-only data (e.g. real prompts): only the false-positive side is meaningful.
        scores = sorted(r["score"] for r in scored)
        print(f"   false-positive {m['fpr']:.1%} ({m['fp']} of {m['n']} flagged/blocked) | "
              f"max score {scores[-1]:.2f} | median score {statistics.median(scores):.2f}")
    else:
        print(f"   detection {m['detection']:.1%} | false-positive {m['fpr']:.1%} | "
              f"precision {m['precision']:.1%} | F1 {m['f1']:.3f}")
    print(f"   latency all p50/p95 {statistics.median(lat):.1f} / {lat[int(0.95 * (len(lat) - 1))]:.1f} ms", end="")
    if jev_lat:
        print(f" | Jev calls p50/p95 {statistics.median(jev_lat):.0f} / {jev_lat[int(0.95 * (len(jev_lat) - 1))]:.0f} ms", end="")
    print()
    engines = defaultdict(int)
    for r in scored:
        engines[r["engine"]] += 1
    errors = sum(r["jev_error"] for r in scored)
    cost = sum(r["cost"] for r in scored)
    print(f"   decided by: {dict(engines)} | Jev errors: {errors} | Jev cost ${cost:.5f}"
          + (f" (~${cost / max(engines.get('jev', 1), 1) * 1000:.3f} per 1k Jev calls)" if cost else ""))

    by_source = defaultdict(list)
    for r in scored:
        by_source[r["source"]].append(r)
    if len(by_source) > 1:
        for src, rs in sorted(by_source.items()):
            s = metrics(rs)
            print(f"   - {src:<34} n={s['n']:<4} detection {s['detection']:.1%}  false-positive {s['fpr']:.1%}")

    misses = [r for r in scored if r["label"] != r["predicted"]]
    for r in misses[:show_errors]:
        kind = "missed" if r["label"] else "false+"
        text = " ".join(r["text"].split())[:90]
        print(f"   [{kind} score={r['score']:.2f} {r['source'][:12]}] {text}")
    if len(misses) > show_errors:
        print(f"   ... {len(misses) - show_errors} more (see eval/results/)")
    print()


def sweep(scored: list[dict]) -> None:
    if not any(r["label"] for r in scored):
        return  # no attacks: nothing to trade off
    print("   threshold sweep (score >= t counts as attack):")
    print("     t     detection  false-pos  precision  F1")
    for t in SWEEP:
        m = metrics(scored, key=lambda r, t=t: r["score"] >= t)
        print(f"     {t:<5} {m['detection']:>8.1%} {m['fpr']:>10.1%} {m['precision']:>10.1%}  {m['f1']:.3f}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, nargs="*", default=None)
    parser.add_argument("--public", action="store_true", help="add eval/datasets/public/*.jsonl")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--show-errors", type=int, default=15)
    args = parser.parse_args()

    paths = args.data or [DEFAULT_DATA]
    if args.public:
        public = sorted((DATA_DIR / "public").glob("*.jsonl"))
        if not public:
            raise SystemExit("No public datasets: run `python -m eval.fetch_datasets` first.")
        paths += public
    rows = load(paths)

    settings = Settings()
    rules = score_rows(rows, settings, None, args.workers)
    report("rules-only", rules, args.show_errors)

    if not settings.jev_enabled:
        print("OPENROUTER_API_KEY not set: only the rules-only baseline ran.")
        return
    start = time.perf_counter()
    jev = score_rows(rows, settings, JevClient(settings), args.workers)
    print(f"(Jev run took {time.perf_counter() - start:.0f}s with {args.workers} workers)\n")
    report(f"rules+{settings.jev_model} (block>={settings.block_threshold}, flag>={settings.flag_threshold})",
           jev, args.show_errors)
    sweep(jev)

    RESULTS_DIR.mkdir(exist_ok=True)
    out = RESULTS_DIR / f"jev_{time.strftime('%Y%m%d_%H%M%S')}.jsonl"
    with out.open("w") as fh:
        for r in jev:
            fh.write(json.dumps({k: v for k, v in r.items() if k != "text"} | {"text": r["text"][:200]},
                                ensure_ascii=False) + "\n")
    print(f"Per-row scores saved to {out}")


if __name__ == "__main__":
    main()
