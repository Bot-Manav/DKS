"""Multi-sequence SP 800-22 run: DKS state stream vs an os.urandom control.

Usage:
    python sp800_22_run.py dks 20        # 20 sequences from DKS
    python sp800_22_run.py urandom 20    # 20 sequences from os.urandom (control)

Each sequence is 2,000,000 bits, the smallest size where all 15 tests are eligible in nistrng.
Results are written to results/sp800_22_<source>.json.

Acceptance rules applied (SP 800-22 Rev 1a section 4.2). These were NOT read from the fetched
source, because section 4 was not reachable. They are the standard rules as recalled:
  * Proportion: with alpha = 0.01 and m sequences, the acceptable range for the proportion
    of passing sequences is (1 - alpha) +/- 3 * sqrt(alpha * (1 - alpha) / m).
  * Uniformity: p-values fall into 10 bins. chi2 = sum((F_i - m/10)^2 / (m/10)), 9 degrees
    of freedom, P_T = igamc(9/2, chi2/2). Pass if P_T >= 0.0001.
"""

from __future__ import annotations

import json
import math
import os
import random
import sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np
import scipy.special

import dks
import sp800_22

BITS_PER_SEQ = 2_000_000
BYTES_PER_SEQ = BITS_PER_SEQ // 8
ALPHA = 0.01


def _dks_sequence(i: int) -> bytes:
    rng = random.Random(2026_10_31 + i)
    key = rng.randbytes(32)
    salt = rng.randbytes(32)
    return dks._state_stream(dks._extract(salt, key), BYTES_PER_SEQ)


def _urandom_sequence(_i: int) -> bytes:
    return os.urandom(BYTES_PER_SEQ)


def _one(args):
    source, i = args
    data = _dks_sequence(i) if source == "dks" else _urandom_sequence(i)
    return sp800_22.run_battery(sp800_22.bits_from_bytes(data))


def _group(per_seq: list[list[dict]]) -> dict[str, list[dict]]:
    """Collect entries by test name across sequences. Entry order is the same every run."""
    grouped: dict[str, list[dict]] = {}
    for seq in per_seq:
        for e in seq:
            grouped.setdefault(e["name"], []).append(e)
    return grouped


def analyse(per_seq: list[list[dict]]) -> dict:
    report = {}
    for name, rows in _group(per_seq).items():
        eligible = [r for r in rows if r["eligible"]]
        passes = sum(1 for r in eligible if r["passed"])
        n = len(eligible)
        if n == 0:
            report[name] = {"eligible": False}
            continue
        p_hat = 1 - ALPHA
        half = 3 * math.sqrt(ALPHA * (1 - ALPHA) / n)
        prop_ok = passes / n >= p_hat - half
        pvals = np.array([r["p"] for r in eligible], dtype=float)
        bins, _ = np.histogram(pvals, bins=10, range=(0.0, 1.0))
        expected = n / 10
        chi2 = float(np.sum((bins - expected) ** 2 / expected))
        p_t = float(scipy.special.gammaincc(9 / 2, chi2 / 2))
        report[name] = {
            "eligible": True,
            "sequences": n,
            "passed": passes,
            "proportion": round(passes / n, 4),
            "proportion_min": round(p_hat - half, 4),
            "proportion_ok": bool(prop_ok),
            "uniformity_P_T": round(p_t, 6),
            "uniformity_ok": bool(p_t >= 0.0001),
            "overall_ok": bool(prop_ok and p_t >= 0.0001),
        }
    return report


def main() -> None:
    source, m = sys.argv[1], int(sys.argv[2])
    if source not in ("dks", "urandom"):
        raise SystemExit("source must be dks or urandom")
    out_dir = Path(__file__).parent / "results"
    out_dir.mkdir(exist_ok=True)
    with Pool(processes=max(1, (os.cpu_count() or 2))) as pool:
        per_seq = []
        for i, res in enumerate(pool.imap(_one, [(source, k) for k in range(m)])):
            per_seq.append(res)
            print(f"[{source}] sequence {i + 1}/{m} done", flush=True)
    report = analyse(per_seq)
    payload = {"source": source, "sequences": m, "bits_per_sequence": BITS_PER_SEQ,
               "alpha": ALPHA, "tests": report}
    (out_dir / f"sp800_22_{source}.json").write_text(json.dumps(payload, indent=2))
    for name, r in report.items():
        if not r["eligible"]:
            print(f"{name:40s} NOT RUN")
            continue
        print(f"{name:40s} passed {r['passed']}/{r['sequences']}  "
              f"min-needed {r['proportion_min']:.4f}  P_T={r['uniformity_P_T']:.4f}  "
              f"{'OK' if r['overall_ok'] else 'FAIL'}")


if __name__ == "__main__":
    main()
