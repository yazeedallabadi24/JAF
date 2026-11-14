"""Download public eval sets into eval/datasets/public/ (git-ignored).

    python -m eval.fetch_datasets

Hop 1 (ingress)
  deepset/prompt-injections (test)        injections vs benign, EN/DE
  jackhhao/jailbreak-classification (test) jailbreaks vs benign
  Lakera/gandalf_ignore_instructions (test) real attacks typed into the Gandalf game
  Paul/XSTest                              safe prompts that *sound* dangerous (false-positive test)
                                           + plainly unsafe requests (reported separately)
Hop 2 (retrieval)
  microsoft/BIPIA (email + table, test)    real emails and tables, clean and with injected instructions

Uses the Hugging Face datasets-server JSON API and raw GitHub, so no extra dependencies.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

OUT = Path(__file__).parent / "datasets" / "public"
HF_API = "https://datasets-server.huggingface.co/rows"
BIPIA_RAW = "https://raw.githubusercontent.com/microsoft/BIPIA/main/benchmark"

# output name -> (hf dataset, split, text field, label fn or None to skip the row)
HF_SOURCES = {
    "deepset_prompt_injections_test": (
        "deepset/prompt-injections", "test", "text", lambda r: int(r["label"]),
    ),
    "jackhhao_jailbreak_test": (
        "jackhhao/jailbreak-classification", "test", "prompt", lambda r: int(r["type"] == "jailbreak"),
    ),
    "lakera_gandalf_test": (
        "Lakera/gandalf_ignore_instructions", "test", "text", lambda r: 1,
    ),
    "xstest_safe": (
        "Paul/XSTest", "train", "prompt", lambda r: 0 if r["label"] == "safe" else None,
    ),
    "xstest_unsafe": (
        "Paul/XSTest", "train", "prompt", lambda r: 1 if r["label"] == "unsafe" else None,
    ),
}


def fetch_hf(http: httpx.Client, dataset: str, split: str) -> list[dict]:
    rows, offset = [], 0
    while True:
        resp = http.get(HF_API, params={"dataset": dataset, "config": "default", "split": split,
                                        "offset": offset, "length": 100})
        resp.raise_for_status()
        page = [r["row"] for r in resp.json().get("rows", [])]
        rows += page
        if len(page) < 100:
            return rows
        offset += 100


def inject(context: str, attack: str, position: int) -> str:
    """Insert the attack at the start, middle or end of the email body (BIPIA's 3 positions)."""
    head, sep, body = context.partition("CONTENT:")
    if not sep:
        head, body = "", context
    if position == 0:
        body = f"\n{attack}\n{body}"
    elif position == 1:
        mid = body.find("\n", len(body) // 2)
        mid = mid if mid != -1 else len(body) // 2
        body = f"{body[:mid]}\n{attack}\n{body[mid:]}"
    else:
        body = f"{body}\n{attack}\n"
    return head + sep + body


def build_bipia(http: httpx.Client, task: str) -> list[dict]:
    """Clean documents (label 0) + the same documents with each BIPIA attack injected (label 1)."""
    docs = [json.loads(l)["context"] for l in http.get(f"{BIPIA_RAW}/{task}/test.jsonl").text.splitlines() if l.strip()]
    attacks_by_type = http.get(f"{BIPIA_RAW}/text_attack_test.json").json()
    attacks = [(kind, a) for kind, items in attacks_by_type.items() for a in items]

    rows = [{"text": d, "label": 0} for d in docs]
    for i, (kind, attack) in enumerate(attacks):
        rows.append({"text": inject(docs[i % len(docs)], attack, i % 3), "label": 1, "attack_type": kind})
    return rows


def write(name: str, rows: list[dict], hop: str) -> None:
    path = OUT / f"{name}.jsonl"
    with path.open("w") as fh:
        for r in rows:
            fh.write(json.dumps({"hop": hop, "lang": "?", "source": name, **r}, ensure_ascii=False) + "\n")
    labels = [r["label"] for r in rows]
    print(f"{name}: {len(labels)} rows ({sum(labels)} attacks, {len(labels) - sum(labels)} benign) [{hop}]")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=30, follow_redirects=True) as http:
        cache: dict[tuple[str, str], list[dict]] = {}
        for name, (dataset, split, field, label_fn) in HF_SOURCES.items():
            raw = cache.setdefault((dataset, split), fetch_hf(http, dataset, split))
            rows = []
            for r in raw:
                text, label = r.get(field), label_fn(r)
                if isinstance(text, str) and text.strip() and label is not None:
                    rows.append({"text": text, "label": label})
            write(name, rows, "ingress")
        write("bipia_email_test", build_bipia(http, "email"), "retrieval")
        write("bipia_table_test", build_bipia(http, "table"), "retrieval")


if __name__ == "__main__":
    main()
