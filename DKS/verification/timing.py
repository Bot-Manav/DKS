"""dudect-style timing test for dks.py (Python, so noisy and only indicative).

Run from the repository root:
    python -m verification.timing            # 60000 measurements per class
    python -m verification.timing 200000

For each test, two input classes are timed in random interleaved order. The statistic is a
Welch t-test on the timings, taking the largest |t| over several upper-percentile crops
(dudect, Reparaz, Balasch and Verbauwhede 2017). Rule of thumb from dudect:
|t| < 4.5 no evidence of a timing difference, |t| > 10 a clear difference.

A difference found by a test marked EXPECTED is not a defect of the harness. It shows the
code path differs (for example valid vs invalid blobs) and is the point of the test.
"""

from __future__ import annotations

import math
import os
import random
import sys
import time

import dks

CROPS = [100, 99, 95, 90, 80]


def welch_t(a: list[int], b: list[int]) -> tuple[float, float]:
    na, nb = len(a), len(b)
    ma, mb = sum(a) / na, sum(b) / nb
    va = sum((x - ma) ** 2 for x in a) / (na - 1)
    vb = sum((x - mb) ** 2 for x in b) / (nb - 1)
    return (ma - mb) / math.sqrt(va / na + vb / nb), ma - mb


def percentile(values: list[int], pct: float) -> int:
    s = sorted(values)
    return s[min(len(s) - 1, int(len(s) * pct / 100))]


def measure(fn_a, fn_b, n: int, rng: random.Random) -> tuple[float, float]:
    """fn_a, fn_b are zero-argument callables. Returns (max |t|, mean difference in ns)."""
    ta: list[int] = []
    tb: list[int] = []
    order = [0] * n + [1] * n
    rng.shuffle(order)
    for _ in range(500):  # warm up
        fn_a()
        fn_b()
    for cls in order:
        f = fn_b if cls else fn_a
        t0 = time.perf_counter_ns()
        f()
        dt = time.perf_counter_ns() - t0
        (tb if cls else ta).append(dt)
    best_t, best_diff = 0.0, 0.0
    for crop in CROPS:
        lim = percentile(ta + tb, crop)
        a = [x for x in ta if x <= lim]
        b = [x for x in tb if x <= lim]
        if len(a) < 100 or len(b) < 100:
            continue
        t, diff = welch_t(a, b)
        if abs(t) > abs(best_t):
            best_t, best_diff = t, diff
    return best_t, best_diff


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60000
    rng = random.Random(int(os.environ.get("DKS_TIMING_SEED", "4242")))
    key = os.urandom(32)
    msg = os.urandom(1024)
    good = dks.encrypt(key, msg)
    bad_tag_last = bytearray(good)
    bad_tag_last[-1] ^= 1
    bad_tag_last = bytes(bad_tag_last)
    bad_tag_first = bytearray(good)
    bad_tag_first[-dks.TAG_LEN] ^= 1
    bad_tag_first = bytes(bad_tag_first)
    wrong_key = os.urandom(32)

    key_zero, key_ones = bytes(32), b"\xff" * 32
    blob_zero = dks.encrypt(key_zero, msg)
    blob_ones = dks.encrypt(key_ones, msg)
    pt_zero, pt_rand = bytes(1024), os.urandom(1024)
    b_pt_zero = dks.encrypt(key, pt_zero)
    b_pt_rand = dks.encrypt(key, pt_rand)

    tests = [
        ("valid blob vs tampered blob (decrypt)", "EXPECTED (code paths differ)",
         lambda: dks.decrypt(key, good), lambda: dks.decrypt(key, bad_tag_last)),
        ("valid blob vs wrong key (decrypt)", "EXPECTED (code paths differ)",
         lambda: dks.decrypt(key, good), lambda: dks.decrypt(wrong_key, good)),
        ("tag mismatch in first byte vs last byte (decrypt)", "should show no leak",
         lambda: dks.decrypt(key, bad_tag_first), lambda: dks.decrypt(key, bad_tag_last)),
        ("tampered vs wrong key (decrypt, both invalid)", "should show no leak",
         lambda: dks.decrypt(key, bad_tag_last), lambda: dks.decrypt(wrong_key, good)),
        ("all-zero key vs all-ones key (decrypt)", "should show no leak",
         lambda: dks.decrypt(key_zero, blob_zero), lambda: dks.decrypt(key_ones, blob_ones)),
        ("all-zero plaintext vs random plaintext (decrypt)", "should show no leak",
         lambda: dks.decrypt(key, b_pt_zero), lambda: dks.decrypt(key, b_pt_rand)),
        ("all-zero key vs all-ones key (encrypt)", "should show no leak",
         lambda: dks.encrypt(key_zero, msg), lambda: dks.encrypt(key_ones, msg)),
    ]
    print(f"{n} measurements per class, 1024-byte message\n")
    for name, expect, fa, fb in tests:
        t, diff = measure(fa, fb, n, rng)
        verdict = "no evidence" if abs(t) < 4.5 else ("LEAK (clear)" if abs(t) > 10 else "possible")
        print(f"{name:55s} t={t:8.1f}  mean diff={diff:9.0f} ns  {verdict:13s} [{expect}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
