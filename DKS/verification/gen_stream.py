"""Write a binary stream for external statistical batteries (Dieharder, TestU01).

    python -m verification.gen_stream dks 1024 out.bin        # 1024 MB of DKS key-state stream
    python -m verification.gen_stream urandom 1024 control.bin

The DKS stream is the concatenation of 4 MiB key-state chains, each from a fresh key and salt
(derived from a fixed seed so the file is reproducible).
"""

from __future__ import annotations

import os
import random
import sys

import dks

SEGMENT = 4 * 1024 * 1024


def main() -> int:
    kind, mb, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    total = mb * 1024 * 1024
    rng = random.Random(20261102)
    written = 0
    with open(out, "wb") as f:
        while written < total:
            n = min(SEGMENT, total - written)
            if kind == "dks":
                prk = dks._extract(rng.randbytes(32), rng.randbytes(32))
                f.write(dks._state_stream(prk, n))
            elif kind == "urandom":
                f.write(os.urandom(n))
            else:
                raise SystemExit("kind must be dks or urandom")
            written += n
    print(f"wrote {written} bytes to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
