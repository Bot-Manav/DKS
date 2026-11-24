"""Cross-check dks.py against the independent implementation in dks_ref.py.

dks_ref.py was written from SPEC.md alone, without reference to dks.py,
and uses no third-party code (pure-Python ChaCha20, Poly1305, HKDF).

Run from the repository root:
    python -m verification.crosscheck            # default 3000 cases per group
    python -m verification.crosscheck 20000      # more cases

Exit code is 0 only if every comparison matches. Mismatches on failure inputs are grouped by
kind, because each kind points at a different gap in SPEC.md.
"""

from __future__ import annotations

import collections
import json
import random
import sys
from pathlib import Path

import dks
from verification import dks_ref as ref

ROOT = Path(__file__).resolve().parent.parent
LENGTHS = [0, 1, 2, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 127, 128, 129, 255, 256,
           257, 500, 1000, 2047]
KINDS = ["wrong key", "one bit flipped", "truncated", "wrong version byte", "random bytes"]


def check_ref_primitives() -> int:
    """Validate the pure-Python primitives against Wycheproof (independent of dks.py)."""
    data = json.loads((ROOT / "vectors" / "chacha20_poly1305_test.json").read_text())
    n = bad = 0
    for g in data["testGroups"]:
        if g["keySize"] != 256 or g["ivSize"] != 96 or g["tagSize"] != 128:
            continue
        for t in g["tests"]:
            key, iv = bytes.fromhex(t["key"]), bytes.fromhex(t["iv"])
            aad, msg = bytes.fromhex(t["aad"]), bytes.fromhex(t["msg"])
            ct, tag = bytes.fromhex(t["ct"]), bytes.fromhex(t["tag"])
            if t["result"] == "valid":
                ok = (ref.aead_encrypt(key, iv, msg, aad) == ct + tag
                      and ref.aead_decrypt(key, iv, ct + tag, aad) == msg)
            elif t["result"] == "invalid":
                ok = ref.aead_decrypt(key, iv, ct + tag, aad) is None
            else:
                continue
            n += 1
            if not ok:
                bad += 1
                print(f"  reference AEAD mismatch on Wycheproof tcId {t['tcId']}")
    print(f"[1] reference ChaCha20-Poly1305 vs Wycheproof: {n - bad}/{n} ok")

    h = json.loads((ROOT / "vectors" / "hkdf_sha256_test.json").read_text())
    hn = hbad = 0
    for g in h["testGroups"]:
        for t in g["tests"]:
            if t["result"] != "valid":
                continue
            hn += 1
            prk = ref.hkdf_extract(bytes.fromhex(t["salt"]), bytes.fromhex(t["ikm"]))
            if ref.hkdf_expand(prk, bytes.fromhex(t["info"]), t["size"]) != bytes.fromhex(t["okm"]):
                hbad += 1
    print(f"[2] reference HKDF-SHA256 vs Wycheproof: {hn - hbad}/{hn} ok")
    return bad + hbad


def check_valid_inputs(rng: random.Random, cases: int) -> int:
    bad = 0
    for i in range(cases):
        key, salt, nonce = rng.randbytes(32), rng.randbytes(32), rng.randbytes(12)
        n = LENGTHS[i % len(LENGTHS)] if i % 3 else rng.randrange(0, 1500)
        pt = rng.randbytes(n)
        a = dks._encrypt(key, salt, nonce, pt)
        b = ref.encrypt_with_params(key, salt, nonce, pt)
        prk = dks._extract(salt, key)
        steps = -(-(n + 16) // 32)
        ok = (a == b
              and dks.decrypt(key, b) == pt and ref.decrypt(key, a) == (True, pt)
              and dks.verify(key, b)
              and dks._message_key(prk, n + 16) == ref.message_key(key, salt, n + 16)
              and dks._state_after(prk, steps) == ref.state_after(key, salt, steps))
        if not ok:
            bad += 1
            print(f"  valid-input mismatch: case {i}, plaintext length {n}")
    print(f"[3] valid inputs: ciphertext, message key, state and cross-decrypt: "
          f"{cases - bad}/{cases} ok")
    return bad


def check_failure_inputs(rng: random.Random, cases: int) -> int:
    """Wrong keys, bit flips, truncations, wrong versions. Flag and output must both match."""
    bad = 0
    by_kind: collections.Counter[str] = collections.Counter()
    flag_diff = 0
    for i in range(cases):
        key = rng.randbytes(32)
        blob = bytearray(dks.encrypt(key, rng.randbytes(LENGTHS[i % len(LENGTHS)])))
        kind = i % 5
        use_key = key
        if kind == 0:
            use_key = rng.randbytes(32)
        elif kind == 1:
            blob[rng.randrange(len(blob))] ^= 1 << rng.randrange(8)
        elif kind == 2:
            blob = blob[:rng.randrange(len(blob) + 1)]
        elif kind == 3:
            blob[0] = rng.choice([0x00, 0x01, 0x02, 0x04, 0xFF])
        else:
            blob = bytearray(rng.randbytes(rng.randrange(0, 300)))
        blob = bytes(blob)
        a_out, a_ok = dks._open(use_key, blob)
        b_ok, b_out = ref.decrypt(use_key, blob)
        if (a_out, a_ok) != (b_out, b_ok):
            bad += 1
            by_kind[KINDS[kind]] += 1
            if a_ok != b_ok:
                flag_diff += 1
    print(f"[4] failure inputs, flag and gibberish byte-for-byte: {cases - bad}/{cases} ok")
    for k, v in by_kind.items():
        print(f"      mismatches for '{k}': {v}")
    if bad:
        print(f"      of these, validity flags differ: {flag_diff}; only the gibberish differs: "
              f"{bad - flag_diff}")
    return bad


def main() -> int:
    cases = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    rng = random.Random(20261102)
    bad = check_ref_primitives()
    bad += check_valid_inputs(rng, cases)
    bad += check_failure_inputs(rng, cases)
    print("RESULT:", "ALL MATCH" if bad == 0 else f"{bad} MISMATCHES")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
