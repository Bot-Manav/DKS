"""Throughput comparison: DKS v3 vs AES-256-GCM vs ChaCha20-Poly1305."""
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

import dks

KEY = os.urandom(32)
SIZES = [1024, 64 * 1024, 1024 * 1024]


def bench(fn, data, min_time=0.5):
    n = 0
    start = time.perf_counter()
    while True:
        fn(data)
        n += 1
        elapsed = time.perf_counter() - start
        if elapsed >= min_time:
            break
    return (n * len(data)) / elapsed / 1e6  # MB/s


def aes_enc(data):
    AESGCM(KEY).encrypt(os.urandom(12), data, None)


def chacha_enc(data):
    ChaCha20Poly1305(KEY).encrypt(os.urandom(12), data, None)


def dks_enc(data):
    dks.encrypt(KEY, data)


if __name__ == "__main__":
    print(f"{'size':>10} {'DKS v3 MB/s':>12} {'AES-GCM MB/s':>14} {'ChaCha MB/s':>13}")
    for size in SIZES:
        data = os.urandom(size)
        d = bench(dks_enc, data, min_time=1.0)
        a = bench(aes_enc, data)
        c = bench(chacha_enc, data)
        print(f"{size:>10} {d:>12.3f} {a:>14.1f} {c:>13.1f}")
