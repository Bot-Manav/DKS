"""SP 800-22 Rev 1a harness for DKS v3.

Test sources, chosen by checking each against an os.urandom control (see REQUIREMENTS.md R3):

  * nistrng (BSD-3, Python): Monobit, Frequency within a Block, Runs,
    Longest Run of Ones, Binary Matrix Rank, DFT, Serial, Approximate Entropy, Cumulative Sums.
  * This file: Linear Complexity. nistrng's version is wrong (it reports 30 for a 5-stage LFSR,
    and its bin mapping is off by one), so it is replaced here and tested in test_dks.py.
  * External reference (David Johnston's sp800_22_tests, GPL-3.0, NOT vendored here): Maurer's
    Universal, Non-overlapping Template, Overlapping Template, Random Excursion (8 states) and
    Random Excursion Variant (18 states). nistrng's versions of these fail on os.urandom, so
    they are not used. The external checkout is found through the DKS_SP800_22_REF environment
    variable. If it is not set, those tests are reported as not run.

Each run_battery() entry is one p-value. Multi-state tests return one entry per state.
"""

from __future__ import annotations

import math
import os
import sys
from pathlib import Path

import numpy as np
import scipy.special
from nistrng import SP800_22R1A_BATTERY, run_by_name_battery

ALPHA = 0.01
LC_BLOCK = 512
LC_PROBS = np.array([0.010417, 0.03125, 0.125, 0.5, 0.25, 0.0625, 0.020833])
NISTRNG_TESTS = [
    "monobit", "frequency_within_block", "runs", "longest_run_ones_in_a_block",
    "binary_matrix_rank", "dft", "serial", "approximate_entropy", "cumulative sums",
]
REFERENCE_ONLY = [
    "Maurers Universal", "Non Overlapping Template Matching",
    "Overlapping Template Matching", "Random Excursion", "Random Excursion Variant",
]


def bits_from_bytes(data: bytes) -> np.ndarray:
    """Unpack bytes MSB-first into a 0/1 int64 array."""
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8)).astype(np.int64)


def berlekamp_massey_gf2(bits) -> int:
    """Linear complexity of a binary sequence over GF(2). Integer bit operations.

    C and B are connection polynomials stored as integers (bit i = coefficient of x^i).
    The discrepancy at step n is the parity of C AND history, where history bit i = s[n-i].
    """
    C, B = 1, 1
    L, m = 0, -1
    hist = 0
    for n, sn in enumerate(bits):
        hist = (hist << 1) | int(sn)
        d = (C & hist).bit_count() & 1
        if d:
            T = C
            C ^= B << (n - m)
            if 2 * L <= n:
                L = n + 1 - L
                m = n
                B = T
    return L


def linear_complexity_test(bits) -> tuple[float, bool]:
    """SP 800-22 section 2.10 (Linear Complexity). Returns (p_value, passed)."""
    bits = np.asarray(bits)
    N = bits.size // LC_BLOCK
    M = LC_BLOCK
    mu = (M / 2.0) + (((-1) ** (M + 1)) + 9.0) / 36.0 - ((M / 3.0) + (2.0 / 9.0)) / (2 ** M)
    freq = np.zeros(7, dtype=np.int64)
    for i in range(N):
        block = bits[i * M:(i + 1) * M]
        L = berlekamp_massey_gf2(block)
        T = ((-1.0) ** M) * (L - mu) + (2.0 / 9.0)
        # Category bins are (-inf,-2.5], (-2.5,-1.5], ..., (2.5,inf). Integer T lies inside
        # a bin, so ceil(T + 2.5) gives the right index. int() (truncation) is off by one.
        freq[min(6, max(0, math.ceil(T + 2.5)))] += 1
    chi2 = float(np.sum((freq - N * LC_PROBS) ** 2 / (N * LC_PROBS)))
    p = float(scipy.special.gammaincc(3.0, chi2 / 2.0))
    return p, p >= ALPHA


def _external_reference():
    """Import the external reference tests if DKS_SP800_22_REF points to a checkout."""
    ref = os.environ.get("DKS_SP800_22_REF")
    if not ref or not Path(ref).is_dir():
        return None
    if ref not in sys.path:
        sys.path.insert(0, ref)
    import sp800_22_maurers_universal_test as maurer  # type: ignore[import-not-found]
    import sp800_22_non_overlapping_template_matching_test as nonoverlap  # type: ignore[import-not-found]
    import sp800_22_overlapping_template_matching_test as overlap  # type: ignore[import-not-found]
    import sp800_22_random_excursion_test as re1  # type: ignore[import-not-found]
    import sp800_22_random_excursion_variant_test as re2  # type: ignore[import-not-found]
    return {"maurer": maurer, "nonoverlap": nonoverlap, "overlap": overlap,
            "re": re1, "re_var": re2}


def _entry(name: str, p) -> dict:
    if p is None:
        return {"name": name, "p": None, "passed": None, "eligible": False}
    p = float(p)
    return {"name": name, "p": p, "passed": p >= ALPHA, "eligible": True}


def run_battery(bits) -> list[dict]:
    """Run every available test. Returns one entry per p-value: name, p, passed, eligible."""
    bits = np.asarray(bits, dtype=np.int64)
    entries: list[dict] = []

    for name in NISTRNG_TESTS:
        x = run_by_name_battery(name, bits.copy(), SP800_22R1A_BATTERY, check_eligibility=True)
        if x is None:
            entries.append({"name": name, "p": None, "passed": None, "eligible": False})
            continue
        r, _elapsed = x
        entries.append({"name": r.name, "p": float(r.score), "passed": bool(r.passed),
                        "eligible": True})

    p, ok = linear_complexity_test(bits.copy())
    entries.append({"name": "Linear Complexity", "p": p, "passed": bool(ok), "eligible": True})

    ref = _external_reference()
    if ref is None:
        for name in REFERENCE_ONLY:
            entries.append({"name": name, "p": None, "passed": None, "eligible": False,
                            "note": "DKS_SP800_22_REF not set"})
        return entries

    seq = [int(b) for b in bits]
    _, p_mau, _ = ref["maurer"].maurers_universal_test(seq)
    entries.append(_entry("Maurers Universal", p_mau))
    _, p_no, _ = ref["nonoverlap"].non_overlapping_template_matching_test(seq)
    entries.append(_entry("Non Overlapping Template Matching", p_no))
    _, p_ov, _ = ref["overlap"].overlapping_template_matching_test(seq)
    entries.append(_entry("Overlapping Template Matching", p_ov))
    _, _, re_ps = ref["re"].random_excursion_test(seq)
    for k, p_k in enumerate(re_ps):
        entries.append(_entry(f"Random Excursion state {k + 1}", p_k))
    _, _, rev_ps = ref["re_var"].random_excursion_variant_test(seq)
    for k, p_k in enumerate(rev_ps):
        entries.append(_entry(f"Random Excursion Variant state {k + 1}", p_k))
    return entries
