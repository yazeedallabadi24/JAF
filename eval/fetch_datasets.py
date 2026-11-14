"""Download public prompt-injection / jailbreak test sets into eval/datasets/public/ (git-ignored).

    python -m eval.fetch_datasets

Uses the Hugging Face datasets-server JSON API, so no extra dependencies are needed.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

OUT = Path(__file__).parent / "datasets" / "public"
API = "https://datasets-server.huggingface.co/rows"

# name -> (hf dataset, split, text field, label fn)
SOURCES = {
    "deepset_prompt_injections_test": (
        "deepset/prompt-injections", "test", "text", lambda r: int(r["label"]),
    ),
    "jackhhao_jailbreak_test": (
        "jackhhao/jailbreak-classification", "test", "prompt", lambda r: int(r["type"] == "jailbreak"),
    ),
}


def fetch(dataset: str, split: str) -> list[dict]:
    rows, offset = [], 0
    with httpx.Client(timeout=30) as http:
        while True:
            resp = http.get(API, params={"dataset": dataset, "config": "default", "split": split,
                                         "offset": offset, "length": 100})
            resp.raise_for_status()
            page = [r["row"] for r in resp.json().get("rows", [])]
            rows += page
            if len(page) < 100:
                return rows
            offset += 100


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, (dataset, split, field, label_fn) in SOURCES.items():
        rows = fetch(dataset, split)
        path = OUT / f"{name}.jsonl"
        with path.open("w") as fh:
            for r in rows:
                text = r.get(field)
                if isinstance(text, str) and text.strip():
                    fh.write(json.dumps({"text": text, "label": label_fn(r), "hop": "ingress",
                                         "lang": "?", "source": name}, ensure_ascii=False) + "\n")
        labels = [json.loads(l)["label"] for l in path.read_text().splitlines()]
        print(f"{name}: {len(labels)} rows ({sum(labels)} attacks, {len(labels) - sum(labels)} benign) -> {path}")


if __name__ == "__main__":
    main()
