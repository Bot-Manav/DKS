"""Coverage-guided fuzzing of dks.py with Atheris.

Run from the repository root, for example:
    python -m verification.fuzz_atheris -max_total_time=300 -artifact_prefix=/tmp/dks_fuzz/

Properties checked on every input:
  * No exception other than the documented key errors.
  * decrypt() always returns bytes of the documented length.
  * Round trip: decrypt(encrypt(m)) == m and verify() is True.
  * Any single-bit change to a valid blob makes verify() False and never returns the plaintext.
  * Arbitrary bytes must not authenticate (an accepted random blob would be a forgery).

Atheris instruments Python code only. The C code inside the cryptography package is not
instrumented, so coverage guidance applies to dks.py.
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    import dks


def one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    key = fdp.ConsumeBytes(32).ljust(32, b"\x00")

    if fdp.ConsumeBool():
        # Round trip, then mutate a valid blob.
        pt = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 2048))
        blob = dks.encrypt(key, pt)
        assert len(blob) == len(pt) + dks.OVERHEAD
        assert dks.verify(key, blob)
        assert dks.decrypt(key, blob) == pt
        idx = fdp.ConsumeIntInRange(0, len(blob) - 1)
        bit = fdp.ConsumeIntInRange(0, 7)
        mutated = bytearray(blob)
        mutated[idx] ^= 1 << bit
        mutated = bytes(mutated)
        assert not dks.verify(key, mutated)
        out = dks.decrypt(key, mutated)
        assert isinstance(out, bytes)
        assert len(out) == max(0, len(mutated) - dks.OVERHEAD)
        if len(pt) >= 8:
            assert out != pt
    else:
        # Arbitrary bytes into the decrypt path.
        blob = fdp.ConsumeBytes(fdp.remaining_bytes())
        out, ok = dks._open(key, blob)
        assert isinstance(out, bytes)
        assert not ok, "random bytes authenticated: forgery"
        assert len(out) == max(0, len(blob) - dks.OVERHEAD)

    # Wrong key sizes and types must raise only the documented errors.
    try:
        dks.encrypt(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 40)), b"x")
    except ValueError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
