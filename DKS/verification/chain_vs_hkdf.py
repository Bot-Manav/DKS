"""Compare the key-state chain with a plain HKDF message key.

Plain variant:  MK' = HKDF-Expand(PRK, "DKS plain message key" || uint64_be(steps)).
Both derive a 32-byte key from (K, salt, steps) and feed the same AEAD, so only the key schedule
differs. This script measures cost. It cannot show that one is more secure than the other.

Run from the repository root:  python -m verification.chain_vs_hkdf
"""

from __future__ import annotations

import os
import struct
import time

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import dks

SIZES = [1024, 64 * 1024, 1024 * 1024, 8 * 1024 * 1024]


def plain_message_key(prk: bytes, body_len: int) -> bytes:
    steps = -(-body_len // dks.BLOCK_LEN)
    return dks._expand(prk, b"DKS plain message key" + struct.pack(">Q", steps))


def timeit(fn, min_time: float = 0.4) -> float:
    n, start = 0, time.perf_counter()
    while True:
        fn()
        n += 1
        elapsed = time.perf_counter() - start
        if elapsed >= min_time:
            return elapsed / n


def main() -> None:
    key, salt = os.urandom(32), os.urandom(32)
    prk = dks._extract(salt, key)
    nonce = os.urandom(12)
    print(f"{'size':>10} {'chain key ms':>14} {'plain key ms':>14} {'AEAD ms':>10} "
          f"{'chain share of encrypt':>24} {'encrypt speedup if plain':>26}")
    for size in SIZES:
        body = size + dks.TAG_LEN
        pt = os.urandom(size)
        t_chain = timeit(lambda body=body: dks._message_key(prk, body))
        t_plain = timeit(lambda body=body: plain_message_key(prk, body))
        mk = os.urandom(32)
        t_aead = timeit(lambda mk=mk, pt=pt: ChaCha20Poly1305(mk).encrypt(nonce, pt, b"h"))
        share = t_chain / (t_chain + t_aead)
        speedup = (t_chain + t_aead) / (t_plain + t_aead)
        print(f"{size:>10} {t_chain * 1e3:>14.3f} {t_plain * 1e3:>14.4f} {t_aead * 1e3:>10.3f} "
              f"{share:>23.1%} {speedup:>25.1f}x")


if __name__ == "__main__":
    main()
