"""Differential fuzzing: the pure-Python primitives in dks_ref.py against the cryptography library.

Run from the repository root:
    python -m verification.fuzz_primitives            # 20000 iterations
    python -m verification.fuzz_primitives 100000
"""

from __future__ import annotations

import random
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from verification import dks_ref as ref


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    rng = random.Random(777)
    bad = 0
    for i in range(n):
        key, nonce = rng.randbytes(32), rng.randbytes(12)
        aad = rng.randbytes(rng.choice([0, 1, 15, 16, 17, rng.randrange(0, 200)]))
        pt = rng.randbytes(rng.choice([0, 1, 63, 64, 65, rng.randrange(0, 600)]))
        lib = ChaCha20Poly1305(key)
        mine = ref.aead_encrypt(key, nonce, pt, aad)
        if mine != lib.encrypt(nonce, pt, aad):
            bad += 1
            print(f"AEAD encrypt mismatch at {i}")
        # Corrupt: both must reject.
        broken = bytearray(mine)
        broken[rng.randrange(len(broken))] ^= 1 << rng.randrange(8)
        try:
            lib.decrypt(nonce, bytes(broken), aad)
            lib_rejects = False
        except InvalidTag:
            lib_rejects = True
        if not (lib_rejects and ref.aead_decrypt(key, nonce, bytes(broken), aad) is None):
            bad += 1
            print(f"AEAD tamper handling mismatch at {i}")

        # HKDF extract and expand against the library, including multi-block outputs.
        salt, ikm, info = rng.randbytes(rng.randrange(0, 64)), rng.randbytes(rng.randrange(1, 80)), rng.randbytes(rng.randrange(0, 40))
        length = rng.choice([1, 31, 32, 33, 64, 100, rng.randrange(1, 255 * 32 + 1)])
        prk = ref.hkdf_extract(salt, ikm)
        if ref.hkdf_expand(prk, info, length) != HKDFExpand(hashes.SHA256(), length, info).derive(prk):
            bad += 1
            print(f"HKDF-Expand mismatch at {i}")
        if ref.hkdf_expand(prk, info, length) != HKDF(hashes.SHA256(), length, salt or None, info).derive(ikm):
            bad += 1
            print(f"HKDF (extract+expand) mismatch at {i}")
    print(f"differential fuzz: {n} iterations, {bad} mismatches")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
