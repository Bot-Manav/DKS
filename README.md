# DKS — Dynamic Key-State Encryption (v3)

> ## ⚠️ Read this first
>
> **This is a research prototype. It is not a verified or standard encryption technique.**
>
> - It has **not** been reviewed by a cryptographer.
> - Its central mechanism (the key-state chain) is **not** part of any standard, and no proof of its security exists.
> - Several standard requirements are **not implemented** or **cannot be verified** yet. See [What is not verified](#what-is-not-verified).
> - Use it **at your own risk**. Do **not** use it to protect real data, secrets, money or personal information.
>
> The code is provided under the MIT licence, **without any warranty**.

---

## Open to everyone

DKS is free and open for anyone to use, study, copy, modify and share, for any purpose, under the [MIT licence](LICENSE). No permission is needed.

- **Learn from it.** Read the code, the spec and the verification notes.
- **Break it.** Cryptanalysis, bug reports and critical review are the most useful contributions. See [Path to verification](#path-to-verification).
- **Build on it.** Fork it, change the construction, or port it to another language.
- **Contribute.** Issues and pull requests are welcome.

The warning above still applies to every use: this is an experiment, not a tool for protecting real data.

---

## What it does

DKS encrypts a message with a secret key, and it authenticates the result so that tampering is detected.

The idea that makes it different: **the key does not encrypt the message directly.** The key (with a random per-message salt) starts a *state*, and the state is advanced by a one-way step once for every 32 bytes of message **length**. The final state is turned into the key that actually encrypts the message. Decryption rebuilds the same chain from the key and the blob length.

**Honest note:** the chain reads only the key, the salt and the message length. It never reads the message content, so it behaves like a length-indexed key schedule. A plain `HKDF-Expand(PRK, label || steps)` takes the same inputs and is up to ~250x cheaper in key derivation (see `verification/results/chain_vs_hkdf.txt`). The protection comes from HKDF, HMAC and ChaCha20-Poly1305, not from the chain. The chain is kept because it is the project's original idea.

In short: *encryption and decryption both depend on the previous state and the key, and they produce the result accordingly.*

## How it works

Each encryption uses a fresh random **salt** and a fresh random **nonce**.

```
Setup (per message)
  PRK     = HMAC-SHA256(key = salt, data = K)                      HKDF-Extract
  S_0     = HKDF-Expand(PRK, "DKS-v3 state", 32)

Key-state chain (one step per 32 bytes of ciphertext+tag)
  S_{i+1} = HMAC-SHA256(S_i, "DKS-v3 ratchet" || uint64_be(i))

Message key
  MK      = HKDF-Expand(S_steps, "DKS-v3 message key", 32)

Encrypt
  header  = 0x03 || salt (32 bytes) || nonce (12 bytes)
  blob    = header || ChaCha20-Poly1305(MK, nonce, plaintext, aad = header)

Decrypt
  rebuild PRK and MK from the header, then run ChaCha20-Poly1305 decryption.
  If the tag does not match, return gibberish of the same length (see "Failure behaviour").
```

Blob overhead is 61 bytes: 1 version byte, 32 salt bytes, 12 nonce bytes, 16 tag bytes.

The standard building blocks are HKDF (RFC 5869), HMAC-SHA256, and ChaCha20-Poly1305 (RFC 8439). The **key-state chain** between them is the part that is new and unverified.

### Failure behaviour

When authentication fails, `decrypt()` returns random-looking bytes of the correct length instead of raising an error. `verify()` returns `False`. This was a deliberate design choice. It is **not** standard practice, and it has trade-offs: see deviation D1 in [REQUIREMENTS.md](REQUIREMENTS.md).

### Password keys

Passwords are never used directly as keys. `derive_master_key()` turns a password of at least 20 characters into a 256-bit key with PBKDF2-HMAC-SHA256 and a random salt of at least 16 bytes. The caller stores the salt and iteration count.

## Usage

```python
import os
import dks

key = os.urandom(32)                       # 256-bit random master key
blob = dks.encrypt(key, b"hello")          # store or send blob
assert dks.verify(key, blob)               # True only for the right key and untampered data
print(dks.decrypt(key, blob))              # b'hello'

# From a password
salt = os.urandom(16)
key = dks.derive_master_key("a passphrase of at least twenty chars", salt)
```

## Mathematics

All values are bit strings. `‖` is concatenation, `⊕` is XOR, `⌈x⌉` is round up, `uint64_be(i)` is `i` as 8 big-endian bytes.

### Building blocks

```
HMAC(k, m)  = SHA256( (k' ⊕ opad) ‖ SHA256( (k' ⊕ ipad) ‖ m ) )       k' = k padded to 64 bytes (hashed first if longer)
                                                                         ipad = 0x36 repeated, opad = 0x5C repeated  (RFC 2104)
HKDF-Extract(salt, IKM)  = HMAC(salt, IKM)                              (RFC 5869 §2.2)
HKDF-Expand(PRK, info, 32) = HMAC(PRK, info ‖ 0x01)                     one 32-byte block, T(1)  (RFC 5869 §2.3)
```

### DKS key derivation (the non-standard part)

```
PRK     = HMAC(salt, K)                                  K = 256-bit master key, salt = 32 random bytes
S_0     = HMAC(PRK, "DKS-v3 state" ‖ 0x01)
S_{i+1} = HMAC(S_i, "DKS-v3 ratchet" ‖ uint64_be(i))     i = 0, 1, 2, ...
n       = len(plaintext) + 16                            length of ciphertext plus tag (public)
t       = ⌈ n / 32 ⌉                                     number of chain steps
MK      = HMAC(S_t, "DKS-v3 message key" ‖ 0x01)         256-bit one-time key for this message
```

Unrolled, the whole chain is one function of three inputs: `MK = F(K, salt, t)`. This is why the chain behaves like a length-indexed key schedule, and why it cannot add secrecy beyond the 256 bits already in `K`.

### Encryption (ChaCha20-Poly1305, RFC 8439)

```
H       = 0x03 ‖ salt ‖ nonce                            45-byte header, authenticated but not encrypted
Block_j = ChaCha20(MK, counter = j, nonce)               64-byte keystream blocks
C       = P ⊕ (Block_1 ‖ Block_2 ‖ ...)                  encryption starts at counter 1
(r, s)  = first 32 bytes of Block_0                      Poly1305 one-time key; r is "clamped" per the RFC
M       = H ‖ pad16 ‖ C ‖ pad16 ‖ le64(len(H)) ‖ le64(len(C))
tag     = ( ( Σ_i  m_i · r^(q−i+1) )  mod (2^130 − 5)  +  s )  mod 2^128        m_i = 16-byte blocks of M, each with a 0x01 byte appended
blob    = H ‖ C ‖ tag
```

ChaCha20 itself works on a 4×4 matrix of 32-bit words (4 constants, 8 key words, 1 counter, 3 nonce words). One quarter round on words `(a, b, c, d)` is:

```
a ← a + b;  d ← (d ⊕ a) <<< 16
c ← c + d;  b ← (b ⊕ c) <<< 12
a ← a + b;  d ← (d ⊕ a) <<< 8
c ← c + d;  b ← (b ⊕ c) <<< 7          (all additions mod 2^32)
```

Twenty rounds (10 column rounds alternating with 10 diagonal rounds) are applied, then the original matrix is added back. The output is one 64-byte block.

### Decryption

```
PRK, MK  rebuilt from K, salt (in the header) and n = len(blob) − 45
valid    = ( recomputed_tag == tag )                     constant-time comparison
output   = P = C ⊕ keystream      if valid
         = decoy                  otherwise (random-looking bytes of the same length)
```

### Password keys

```
K = PBKDF2-HMAC-SHA256(password, kdf_salt, c, 32) = U_1 ⊕ U_2 ⊕ ... ⊕ U_c
U_1 = HMAC(password, kdf_salt ‖ 0x00000001),   U_j = HMAC(password, U_{j−1})        c = 600,000 by default
```

## Attack probabilities (brute force)

An attacker who has a blob but not the key has to find `K`, which is 256 bits long. Every guess can be checked, because the 128-bit tag either matches or it does not (`verify()`, or any re-implementation of the tag check). So the work needed is a plain search of the key space.

| Quantity | Exact value |
|---|---|
| Number of possible keys, 2^256 | **115,792,089,237,316,195,423,570,985,008,687,907,853,269,984,665,640,564,039,457,584,007,913,129,639,936** (≈ 1.158 × 10^77) |
| Probability that one random guess is right, 2^−256 | ≈ 8.636 × 10^−78 |
| Expected guesses before success, 2^255 | 57,896,044,618,658,097,711,785,492,504,343,953,926,634,992,332,820,282,019,728,792,003,956,564,819,968 |
| Probability of success after N guesses | N / 2^256 |
| Probability that a random forged blob is accepted, per attempt | 2^−128 ≈ 2.94 × 10^−39 (nominal tag size; the proven Poly1305 bound for long messages is somewhat weaker) |
| Quantum attacker (Grover's algorithm) | about 2^128 = 340,282,366,920,938,463,463,374,607,431,768,211,456 sequential steps |
| Chance that two messages ever share a salt, for n messages | about n² / 2^257. For n = 2^64 this is about 2^−129 |

How long that takes (expected time, 2^255 guesses):

| Guess rate | Expected time |
|---|---|
| 10^9 per second (one fast machine) | ≈ 1.8 × 10^60 years |
| 10^12 per second (a large cluster) | ≈ 1.8 × 10^57 years |
| 10^18 per second (far beyond anything that exists) | ≈ 1.8 × 10^51 years, about 10^41 times the age of the universe |

For scale: 2^256 is about 0.1 % of the estimated number of atoms in the observable universe (about 10^80).

**Small caveat on "the exact message".** A wrong key passes the 128-bit tag check with probability 2^−128. Across all 2^256 keys, about 2^128 wrong keys would therefore also pass the tag check for one blob. In practice the attacker picks the real key because it is the one that produces readable plaintext, so this changes nothing for any message longer than a few dozen bytes.

### When the key comes from a password

The 2^256 figure holds only when the key is 32 uniformly random bytes (`os.urandom(32)`). If the key is made with `derive_master_key()`, the attacker searches **passwords**, not keys, and the search space is the password's entropy, not 256 bits.

| Password | Possibilities | Bits |
|---|---|---|
| 20 characters, each random from the 95 printable ASCII characters | 95^20 = 3,584,859,224,085,422,343,574,104,404,449,462,890,625 | 131.4 |
| 6 random words from a 7,776-word diceware list | 7,776^6 = 221,073,919,720,733,357,899,776 | 77.5 |
| 10 random words from a 7,776-word diceware list | 7,776^10 | 129.2 |
| A password a human chose | far fewer than any row above | usually under 40 |

PBKDF2 with 600,000 iterations makes each password guess cost 600,000 HMAC computations, which is about 19.2 bits of extra work per guess. It adds work, not entropy.

### What these numbers do and do not mean

- They assume `K` is uniformly random and that HMAC-SHA256, HKDF and ChaCha20-Poly1305 behave as their standards say. They count the cost of the **generic** attack. They are not a proof that no faster attack exists.
- The key-state chain adds **no** extra bits. Its output is 256 bits and depends only on `K`, the salt and the length, so the best case is the 2^256 of `K` itself.
- Nothing here covers side channels, bad randomness, key theft, reused or weak passwords, or bugs. A custom construction has not had public cryptanalysis, so an unknown shortcut cannot be ruled out.

## Standard parameters implemented

| Area | Parameter | Source | Status |
|---|---|---|---|
| AEAD | ChaCha20-Poly1305, 256-bit key, 96-bit nonce, full 128-bit tag, header authenticated as AAD | RFC 8439 §2.8, §4 | Implemented. Matches all Wycheproof ChaCha20-Poly1305 vectors for these sizes |
| AEAD | Nonce unique per key | RFC 8439 §2.3 | Random 96-bit nonce per message, under a per-message key |
| KDF | HKDF-Extract and HKDF-Expand, salt of 32 bytes (HashLen), output at most 255 × HashLen | RFC 5869 §2, §3.1, §2.3 | Implemented. Matches all 86 Wycheproof HKDF-SHA256 vectors |
| KDF | Passwords are not used as keys directly | RFC 5869 §4, SP 800-132 §5 | Implemented |
| Password KDF | PBKDF2-HMAC-SHA256, salt ≥ 128 bits, iterations ≥ 1,000, derived key ≥ 112 bits | NIST SP 800-132 §5, §5.1, §5.2, §5.3 | Implemented. Default 600,000 iterations is from common guidance, not from the fetched sources |
| Passwords | Passphrases of at least 20 characters | SP 800-132 Appendix A.1 | Enforced as a floor, not a strength guarantee |
| PRF | HMAC-SHA256 as the pseudorandom function | SP 800-132 §5.3, RFC 5869 | Implemented. Matches all 174 Wycheproof HMAC-SHA256 vectors |
| Randomness (test) | NIST SP 800-22 Rev 1a, 15 tests run on the key-state stream | SP 800-22 §1.1.5, §2 | Run. Results below |

## Results

Full details are in [REQUIREMENTS.md](REQUIREMENTS.md) and `results/`.

- **Test suite:** 617 fast tests pass. They cover the Wycheproof vectors, the RFC requirements, known-answer vectors, failure behaviour, avalanche, and property tests.
- **Static checks:** ruff is clean. mypy was clean earlier but currently reports 5 `import-not-found` errors for `cryptography` in the test environment (environment issue, not re-checked).
- **Speed:** about 10 MB/s for DKS, against about 9,000 MB/s for AES-256-GCM and about 3,100 MB/s for ChaCha20-Poly1305 (1 MiB, this machine). DKS is slow because the chain runs in pure Python, one HMAC per 32 bytes.
- **Independent reference implementation:** 316/316 Wycheproof ChaCha20-Poly1305 and 83/83 HKDF vectors, and 20,000/20,000 valid and 20,000/20,000 failure cases byte-identical to `dks.py`.
- **Fuzzing:** Atheris 300 s (1,512,288 runs), no findings; differential fuzz 50,000 iterations, 0 mismatches.
- **Chain vs plain HKDF key derivation:** the chain is 17x to 254x slower for the same inputs (table in `verification/results/chain_vs_hkdf.txt`).
- **SP 800-22 (30 sequences × 2,000,000 bits):** DKS has 2 of 39 test entries below the proportion threshold. `os.urandom` has 4 of 39 under the same rule. The run cannot tell DKS apart from random data at this sample size. It is **not** a clean pass.

## What is not verified

These items are required for a standard-grade encryption technique and are **not** done, or cannot be done for a custom construction.

| Item | Source | Status |
|---|---|---|
| Security proof for the key-state chain | Standard practice for new constructions | **Not done.** Only the reduction sketch in SPEC.md exists. The chain adds no provable property beyond the standard parts so far |
| Independent cryptanalysis / peer review | Standard practice | **Not done** |
| SP 800-22 acceptance over a large sample (proportion and uniformity) | SP 800-22 §4.2 (rules as recalled, not fetched) | **Inconclusive**. Needs far more sequences |
| Official NIST STS reference implementation | SP 800-22 | Not run. The tests here use nistrng and an external GPL reference |
| Stronger statistical batteries (Dieharder, TestU01 BigCrush) | Practice | **Dieharder partly run, inconclusive.** 256 MB streams; 52 of 54 results PASSED for DKS and 52 of 54 for `os.urandom`. `rgb_minimum_distance` FAILED on both, even on 4 GB of fresh `os.urandom`, so it is a test or build problem, not evidence about DKS. `marsaglia_tsang_gcd` was WEAK for DKS and FAILED for `os.urandom` on a rewound file. TestU01 not run |
| NIST CAVP known-answer and Monte Carlo tests | NIST CAVP | Not applicable as a whole to a custom scheme. Only the primitives are in scope, through their libraries |
| FIPS 140-3 validated module | FIPS 140-3, ISO/IEC 19790 | **Not applicable.** A custom construction cannot be validated. Compliance would need an approved algorithm in an approved module |
| ISO/IEC 18033 (encryption) | ISO/IEC | Not fetched or reviewed |
| Constant-time implementation | RFC 8439 §4 (for the AEAD) and general practice | Not verified. A dudect-style test in Python found no evidence of a leak in 5 of 7 comparisons; valid-vs-invalid differs by ~150 ns (t = -7), which is expected because the result flag differs (`verification/results/timing.txt`). The chain does not branch on secret data, and the tag check runs inside the cryptography library. Timing has not been measured, and Python cannot guarantee constant time |
| Memory erasure | Practice | Best effort only. Python `bytes` cannot be reliably wiped |
| Second independent implementation | Practice (interoperability) | **Done in Python**, written from SPEC.md without reference to `dks.py` (same project, not an independent team). Byte-identical on 20,000 valid and 20,000 failure cases |
| Fuzzing of the parser and decrypt path | Practice | **Done, limited.** Atheris 300 s, 1.5M runs, no crash or property violation; 50,000-case differential fuzz of the reference vs `cryptography`, 0 mismatches |
| Honey Encryption | Future work | Not included. It conflicts with the current failure behaviour |

## Path to verification

Here is what must be done before this could be called a standard-grade technique, in order of importance. Each step has a pass criterion.

1. **Decide whether the key-state chain stays.** Compare it with the standard alternative `MK = HKDF(K, salt, info)`, which is faster and simpler. If the chain is kept, it must be justified by a property the standard alternative lacks. *Pass:* a written security claim that is either proven or explicitly scoped as unproven.

2. **Write a security proof.** Use game-based definitions of IND-CPA and INT-CTXT, and reduce them to the PRF security of HKDF and HMAC and the AEAD security of ChaCha20-Poly1305. A cryptographer should check it. *Tools:* the paper form, reviewed on the Cryptography Stack Exchange, the IACR ePrint archive, or by a university group. *Pass:* a reviewer agrees the reduction is sound.

3. **Formal verification of the proof, if the proof is kept.** *Tools:* EasyCrypt or CryptoVerif for game-based proofs; Tamarin or ProVerif for protocol-level properties. *Pass:* machine-checked proof of the stated goals.

4. **Public cryptanalysis.** Publish the spec and the code, and invite attacks. Run a public challenge with a prize, similar to the public review of AES and SHA-3. *Pass:* a period with no unresolved attacks, reviewed by people outside the project.

5. **Full SP 800-22 with many sequences.** Use the official NIST STS reference code, not only nistrng and external ports. Run at least 1,000 sequences of 1,000,000 bits or more, and apply the proportion and uniformity rules from SP 800-22 §4.2 read directly from the source. *Pass:* all tests inside the acceptance interval, with the control run for comparison.

6. **Stronger statistics.** Run Dieharder and TestU01 BigCrush on large output. *Pass:* no failures beyond the expected random rate.

7. **Constant-time and side-channel review.** Move the implementation to a language that can guarantee constant time, such as Rust with the `subtle` crate or C with libsodium. Measure timing with dudect and check for cache effects with ctgrind or Valgrind-based tools. *Pass:* no statistically significant timing dependence on secret data.

8. **Fuzzing.** Run coverage-guided fuzzing (libFuzzer or Atheris) on `decrypt` and on the parser for at least 24 hours, and differential-fuzz against the `cryptography` library's ChaCha20-Poly1305. *Pass:* no crashes, no mismatches, no hangs.

9. **Second implementation.** Write an independent implementation from SPEC.md alone. Both implementations must produce the same known-answer vectors. *Pass:* identical output on a large generated set.

10. **Key management and misuse review.** Document safe key generation, storage, rotation and password policy. Check the nonce and salt handling under real usage. *Pass:* a written threat model and misuse analysis reviewed by someone outside the project.

11. **Standards route, only if wanted.** A custom scheme is not accepted by NIST, ISO or IETF without years of public review. The realistic route is to write an IETF Internet-Draft or a CFRG discussion, and to ask whether a standard primitive can replace the chain. *Pass:* review by the relevant working group.

Until steps 1–4 are passed, treat DKS as a teaching and research artefact only.

## Repository layout

| File | Purpose |
|---|---|
| `dks.py` | The construction: `encrypt`, `decrypt`, `verify`, `derive_master_key`, `hkdf` |
| `sp800_22.py` | SP 800-22 harness: nistrng tests, corrected Linear Complexity, optional external reference |
| `sp800_22_run.py` | Multi-sequence SP 800-22 run against an `os.urandom` control |
| `test_dks.py` | Wycheproof, RFC requirements, known-answer vectors, failure behaviour, avalanche, SP 800-22 checks |
| `test_properties.py` | Hypothesis property tests |
| `bench.py` | Throughput against AES-256-GCM and ChaCha20-Poly1305 |
| `SPEC.md` | Exact construction, security goals, and limits |
| `REQUIREMENTS.md` | Every requirement, its source, status, and deviations |
| `vectors/` | Wycheproof test vectors (Apache-2.0, see `vectors/WYCHEPROOF_LICENSE`) |
| `results/` | Output of the 30-sequence SP 800-22 runs |

## Running

```bash
pip install -e ".[dev]"
pytest -q                      # fast suite
pytest -q -m slow -s           # SP 800-22 checks, about 2 minutes
ruff check . && mypy --ignore-missing-imports dks.py sp800_22.py && bandit -q -r dks.py sp800_22.py
python bench.py
```

For the full SP 800-22 comparison with the external reference (GPL-3.0, not included here), clone `dj-on-github/sp800_22_tests` and set `DKS_SP800_22_REF` to its path before running `sp800_22_run.py`.

## Licence

MIT. See [LICENSE](LICENSE). The software is provided **as is**, with no warranty of any kind, and no fitness for any purpose.
