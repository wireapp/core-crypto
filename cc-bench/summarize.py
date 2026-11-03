#!/usr/bin/env python3
"""Summarize cc-bench/results/*.json into one markdown table: mean ± σ per variant, relative to main."""

import json
import sys
from pathlib import Path

results = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent / "results")
rows = []
variants = []
for path in sorted(results.glob("*.json")):
    data = json.loads(path.read_text())["results"]
    # hyperfine 2 nests statistics under `summary`; 1.x has them at the top level.
    by_variant = {
        r.get("name") or r["command"]: r["summary"]["time_wall_clock"] if "summary" in r else r for r in data
    }
    for v in by_variant:
        if v not in variants:
            variants.append(v)
    rows.append((path.stem, by_variant))

baseline = "main" if "main" in variants else variants[0]
print("| scenario | " + " | ".join(variants) + " |")
print("|---|" + "---|" * len(variants))
for name, by_variant in rows:
    base = by_variant.get(baseline)
    cells = []
    for v in variants:
        r = by_variant.get(v)
        if r is None:
            cells.append("–")
            continue
        cell = f"{r['mean'] * 1000:.1f} ± {r['stddev'] * 1000:.1f} ms"
        if base is not None and v != baseline:
            cell += f" ({r['mean'] / base['mean']:.2f}×)"
        cells.append(cell)
    print(f"| {name} | " + " | ".join(cells) + " |")
