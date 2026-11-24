# Verification: results and how to reproduce them

Everything below was run in a Linux environment (2 cores, Python 3). Numbers come from `verification/results/`.
**None of this makes DKS a standard or reviewed construction. Use it at your own risk.**

## Setup (from the repository root)

```
pip install cryptography pytest hypothesis atheris nistrng numpy
sudo apt install dieharder        # only for the Dieharder step
```

## Results and commands

| # | Check | Command | Result found |
|---|---|---|---|
| 1 | Unit, vector and property tests | `python3 -m pytest -q` | 617 passed |
| 2 | Reference implementation self-test (RFC 8439, RFC 5869 vectors) | `python3 -I verification/dks_ref_selftest.py` | passes |
| 3 | Reference vs `dks.py`, 20,000 cases | `python3 -m verification.crosscheck 20000` | Wycheproof 316/316 and 83/83; valid 20000/20000; failure (gibberish bytes + flag) 20000/20000; ALL MATCH |
| 4 | Differential fuzz of primitives | `python3 -m verification.fuzz_primitives 50000` | 0 mismatches |
| 5 | Coverage-guided fuzz of `dks.py` | `python3 -m verification.fuzz_atheris -max_total_time=300 -artifact_prefix=/tmp/dks_fuzz/` | 1,512,288 runs, no crash, no property violation |
| 6 | Timing (dudect-style, run alone) | `python3 -m verification.timing` | no evidence of leak in 5 of 7 comparisons; valid vs tampered t=-7.3 and valid vs wrong key t=-6.2 (about 150 ns), which is expected because the returned flag differs |
| 7 | Chain vs plain HKDF cost | `python3 -m verification.chain_vs_hkdf` | chain 17x to 254x slower for key derivation, same inputs |
| 8 | Dieharder, 256 MB streams | `python3 -m verification.gen_stream dks 256 dks.bin` then `DH_TIMEOUT=600 sh verification/dieharder_run.sh dks.bin dh.log` (repeat with `urandom`) | DKS: 52 PASSED, 1 WEAK (`marsaglia_tsang_gcd`), 1 FAILED (`rgb_minimum_distance`). `os.urandom`: 52 PASSED, 2 FAILED (same two). Inconclusive |
| 9 | Dieharder `rgb_minimum_distance`, 4 GB streamed, no rewind | `python3 -m verification.gen_stream urandom 4096 /dev/stdout \| dieharder -g 200 -d 201` | FAILED on `os.urandom` too. This test fails on known-good data in this build, so it says nothing about DKS |
| 10 | SP 800-22 (30 x 2,000,000 bits) | `python3 sp800_22_run.py dks 30` and `... urandom 30` (needs the external reference via `DKS_SP800_22_REF` for 5 tests) | DKS 2/39 entries under the proportion threshold, `os.urandom` 4/39. Inconclusive, not a clean pass |

## What these results do and do not show

- They show the code matches its written spec, the primitives match published vectors, and no crash or inconsistency was found in the tested inputs.
- They do not show security. Statistical tests cannot prove an encryption scheme secure, and a pass would not either.
- The independent implementation was written from the same spec without reference to dks.py. It is not the work of an independent team.
- `verification/DESIGN_ANALYSIS.md` is an unreviewed draft. The chain reads only key, salt and length, not content.

## Still needed

Cryptographer review, a checked security proof, the official NIST STS code with 1,000+ sequences, TestU01 BigCrush, constant-time testing in a compiled language, and public cryptanalysis.
