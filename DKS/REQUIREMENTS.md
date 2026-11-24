# DKS v3 — Requirements and compliance matrix

This file lists every requirement the implementation is checked against, where it comes from,
and whether it is met. Sources were read directly where marked **[fetched]**. Items marked
**[not fetched]** could not be read in this session and are not claimed as verified.

## 0. Sources

| Ref | Document | How obtained |
|---|---|---|
| S1 | RFC 8439, ChaCha20 and Poly1305 for IETF Protocols | [fetched] datatracker.ietf.org/doc/rfc8439 |
| S2 | RFC 5869, HKDF | [fetched] datatracker.ietf.org/doc/rfc5869 (and rfc-editor errata page was not reachable) |
| S3 | RFC 9106, Argon2 (not used in v3; see D4) | [fetched] datatracker.ietf.org/doc/rfc9106 |
| S4 | NIST SP 800-132, Password-Based Key Derivation | [fetched] nvlpubs.nist.gov (legacy 800-132 PDF) |
| S5 | NIST SP 800-22 Rev 1a, Statistical Test Suite | [fetched] sections 1.1.5 and 2.x only. Section 4 (acceptance rules) was **not** readable, so the proportion and uniformity rules are as recalled |
| S6 | Wycheproof test vectors (C2SP), Apache-2.0 | [fetched] git clone, `testvectors_v1/` (vendored into `vectors/`) |
| S7 | nistrng 1.2.3 (Python implementation of SP 800-22 Rev 1a, BSD-3) | installed from PyPI. Used for 9 tests only |
| S7b | David Johnston's sp800_22_tests (GPL-3.0) | cloned from GitHub. Used as an external oracle only. **Not vendored**, to keep the MIT licence clean |
| S8 | NIST CAVP (ACVTS), FIPS 140-3, ISO/IEC 18033, ISO/IEC 19790 | [not fetched] csrc.nist.gov and iso.org were not on the allowlist |

## 1. Requirements and status

### 1.1 AEAD (RFC 8439 — S1)

| ID | Requirement | Source | Status | Evidence |
|---|---|---|---|---|
| A1 | Key is 256 bits (32 octets) | S1 §2.8, §2.8.2 | Met | `_check_key`; `test_key_must_be_exactly_32_bytes` |
| A2 | Nonce is 96 bits, unique per invocation with the same key | S1 §2.3, §2.8 | Met | Random 12-byte nonce per message in the header. Each message also has its own derived key, so a repeat needs both a salt and a nonce collision |
| A3 | Nonce MUST NOT be repeated for the same key | S1 §2.3 | Met (probabilistic) | Random 96-bit nonce under a per-message key. Collision probability is negligible for normal message counts |
| A4 | Tag is 128 bits, full, never truncated | S1 §2.8, §4 | Met | `test_tag_is_full_16_bytes_and_not_truncated` |
| A5 | Tag verified before any plaintext is accepted; message accepted only if tags match | S1 §2.8 | Met | `decrypt` returns the real plaintext only when `ChaCha20Poly1305.decrypt` succeeds |
| A6 | Constant-time tag comparison for online protocols | S1 §4 | Met by library | The tag check is done inside `cryptography`'s AEAD. The library is not audited by this project |
| A7 | AAD is authenticated | S1 §2.8 | Met | The version byte, salt and nonce are passed as AAD. `test_header_swap_rejected` |
| A8 | Known-answer correctness | S1 §2.8.2 + S6 | Met | `test_wycheproof_chacha20_poly1305` (all valid and invalid vectors for 256-bit keys, 96-bit nonces, 128-bit tags) and the RFC 8439 §2.8.2 vector in v2 |
| A9 | Poly1305 key must be unpredictable | S1 §4 | Met | The AEAD key comes from the state chain, which depends on the master key |

### 1.2 Key derivation (RFC 5869 — S2)

| ID | Requirement | Source | Status | Evidence |
|---|---|---|---|---|
| K1 | Use Extract, then Expand, not the PRK directly as output | S2 §3.3 | Met | `_extract` then `_expand` for every derived key |
| K2 | Salt should be random, of length HashLen (32 bytes for SHA-256) | S2 §3.1 | Met | `SALT_LEN = 32`, `os.urandom` |
| K3 | Salt is independent of the IKM and not attacker-controlled | S2 §3.4 | Met | Salt is generated locally and sent in the header. It is authenticated as AAD |
| K4 | Output length at most 255 × HashLen | S2 §2.3 | Met | `hkdf()` raises above the limit. `test_hkdf_length_limit` |
| K5 | Expand output matches the RFC test vectors | S2 Appendix A + S6 | Met | `test_wycheproof_hkdf_sha256` (all 86 Wycheproof HKDF-SHA256 vectors) |
| K6 | Passwords are not used as IKM directly | S2 §4 | Met | `encrypt` requires a 32-byte key. Passwords go through K7 first |
| K7 | Password-derived keys use a password KDF with a salt | S4 §5, S2 §4 | Met | `derive_master_key` uses PBKDF2-HMAC-SHA256 |

### 1.3 Password-based keys (NIST SP 800-132 — S4)

| ID | Requirement | Source | Status | Evidence |
|---|---|---|---|---|
| P1 | Random salt portion at least 128 bits | S4 §5.1 | Met | `PBKDF_MIN_SALT_LEN = 16`, enforced |
| P2 | Iteration count as large as practical; minimum 1,000 | S4 §5.2 | Met for the minimum | `PBKDF_MIN_ITERATIONS = 1000`, enforced. Default is 600,000 (see D3) |
| P3 | Derived key at least 112 bits | S4 §5 | Met | 256-bit output |
| P4 | Approved PRF: PBKDF2 with HMAC using an approved hash | S4 §5.3 | Met | HMAC-SHA256 |
| P5 | User passwords must not be used directly as keys | S4 §5 | Met | Passwords go through PBKDF2 only |
| P6 | Password entropy: passphrases under 20 characters are weak | S4 Appendix A.1 | Met | `PASSWORD_MIN_CHARS = 20`, enforced. This is a floor, not a guarantee of strength |

### 1.4 Randomness (NIST SP 800-22 Rev 1a — S5, S7)

| ID | Requirement | Source | Status | Evidence |
|---|---|---|---|---|
| R1 | Significance level α in [0.001, 0.01] | S5 §1.1.5 | Met | α = 0.01 used in the test rule |
| R2 | Per-test minimum sequence length | S5 §2.1.7, §2.2.7, §2.3.7, §2.4.2, §2.5.7, §2.6.7 | Met | 1,000,000-bit sequence, larger than every minimum listed |
| R3 | All 15 tests run on the state stream | S5 §2 | Met, with sources. 9 tests from nistrng; Linear Complexity from `sp800_22.py` (nistrng's version is wrong); Maurer, the two template tests and both Random Excursion tests from an external GPL-3.0 reference (not vendored; set `DKS_SP800_22_REF`). Each source was checked against an `os.urandom` control | `test_sp800_22_battery_returns_valid_p_values`, `test_sp800_22_harness_rejects_bad_data`, `sp800_22_run.py`. nistrng's Maurer, template and excursion tests fail on random data, so they are not used |
| R4 | Proportion of passing sequences within the acceptance interval | S5 §4.2.1 (rule as recalled, not fetched) | **Inconclusive.** Run on 30 sequences of 2,000,000 bits. DKS: 2 of 39 entries fall below the threshold (Linear Complexity 28/30, Random Excursion Variant state 14 28/30; threshold 0.9355). Control on `os.urandom`: 4 of 39 entries at 28/30 | `results/sp800_22_dks.json`, `results/sp800_22_urandom.json`. Random data fails the rule as often as DKS, so the rule at m=30 cannot separate them. A decisive run needs many more sequences |
| R5 | P-value uniformity across sequences | S5 §4.2.2 (rule as recalled, not fetched) | **Met for DKS.** P_T ≥ 0.0001 for all 39 entries (lowest 0.0669) | `sp800_22_run.py` (10 bins, 9 degrees of freedom) |
| R6 | The SP 800-22 suite validates a generator, not an algorithm | S5 §1 | Acknowledged | The tests check the keystream stream, not the security of the construction |

### 1.5 Validation programmes (not applicable to a custom scheme)

| ID | Requirement | Source | Status | Note |
|---|---|---|---|---|
| V1 | CAVP known-answer and Monte Carlo tests for approved algorithms | S8 | Not applicable to DKS as a whole | CAVP validates implementations of approved algorithms. The primitives (ChaCha20-Poly1305, HKDF, HMAC-SHA256, PBKDF2) are in scope only through the libraries that implement them |
| V2 | FIPS 140-3 validated module (power-up tests, zeroisation, physical security) | S8 | Not applicable | A custom construction cannot be validated. Compliance would require replacing DKS with an approved mode of an approved module |
| V3 | ISO/IEC 18033 (encryption), ISO/IEC 19790 | S8 | Not fetched | Not claimed |

## 2. Deviations from standard practice

| ID | Deviation | Why it was kept | Risk |
|---|---|---|---|
| D1 | `decrypt` returns gibberish on failure instead of raising an error | Deliberate Stage 5 design decision | Standard libraries raise an error. Gibberish can confuse callers, and `verify` gives a clear oracle. Use `verify` only where the caller is trusted |
| D2 | The state chain is a non-standard key schedule | Main logic of the original idea, kept by design | No standard approves this component. Its security is argued in SPEC.md, not proven |
| D3 | Default PBKDF2 iterations are 600,000 | Not from any fetched source. Chosen from common practice (OWASP guidance, not verified here) | Callers can pass any value of at least 1,000 (the S4 minimum). Values below 1,000 raise an error. Higher values are slower for everyone, so tune them to your hardware |
| D4 | Argon2id (RFC 9106) is not used | NIST SP 800-132 approves PBKDF2, and Argon2 is not a NIST-approved KDF. RFC 9106 parameters were read (first option: 2 GiB memory, 1 iteration, 4 lanes; second: 64 MiB, 3 iterations, 4 lanes) | Argon2id is stronger against GPU attacks. Switching is a one-function change if standards compliance is not required |
| D5 | Master key must be 32 random bytes, not a password | RFC 8439 needs a 256-bit key, and S2 §4 warns about passwords | Users must call `derive_master_key` themselves |

## 3. Common misconceptions

These claims are often made about encryption and do not match the sources:

- **50% avalanche for a 1-bit input flip** applies to hash functions and block-cipher outputs. For a stream cipher, one plaintext bit flip changes exactly one ciphertext bit. The implementation tests this property directly, and the tag gets the 50% test.
- **"Constant time (O(1))"** is the wrong term. Constant time means the running time does not depend on secret data. It does not mean O(1) complexity.
- **"256 bits for top-secret"** is a government policy statement, not a requirement from the sources listed above. It is not claimed here.

## 4. How to re-check

```
pip install -e ".[dev]"
pytest -q                  # fast: Wycheproof, RFC requirements, KAT, avalanche, property tests
pytest -q -m slow -s       # SP 800-22 battery, about 8 minutes
ruff check . && mypy dks.py && bandit -q -r dks.py
```

Last run results are in README.md.
