# DKS v3 Specification

Status: research prototype. Not reviewed by a cryptographer. Do not use to protect real data.
Every standard requirement referenced here is listed with its source in REQUIREMENTS.md.

## 1. Overview

A 256-bit master key K and a fresh random salt start a state. The state advances once per
32 bytes of message length (the chain depends on the key, the salt and the message length, and does not read the message content). The state after the last step is expanded into a one-time key for
that message. ChaCha20-Poly1305 (RFC 8439) encrypts and authenticates the message under that
key. Decryption rebuilds the same chain from K, so it needs the right K.

The main logic is the chain: each state depends on the previous state and the key. The standard
parts are HKDF (RFC 5869), HMAC-SHA256, and ChaCha20-Poly1305 (RFC 8439). The chain itself has
no standard behind it.

## 2. Parameters

| Name | Value | Source |
|---|---|---|
| Version byte | `0x03` | this document |
| Master key K | 32 bytes (256 bits) | RFC 8439 §2.8 |
| Salt | 32 bytes, random per message | RFC 5869 §3.1 (HashLen) |
| Nonce | 12 bytes, random per message | RFC 8439 §2.8 |
| AEAD tag | 16 bytes, full | RFC 8439 §2.8, §4 |
| Block length | 32 bytes | this document |
| Hash / MAC | SHA-256, HMAC-SHA256 | RFC 5869 §2 |

## 3. Derivations

```
PRK      = HMAC-SHA256(key = salt, data = K)                 HKDF-Extract (RFC 5869 §2.2)
S_0      = HKDF-Expand(PRK, "DKS-v3 state", 32)              RFC 5869 §2.3
S_{i+1}  = HMAC-SHA256(S_i, "DKS-v3 ratchet" || uint64_be(i))   i = 0, 1, ...
steps    = ceil(body_len / 32)
MK       = HKDF-Expand(S_steps, "DKS-v3 message key", 32)
decoy    = HKDF-Expand(PRK, "DKS-v3 decoy", 32)
```

`body_len` is `len(plaintext) + 16`, the length of ciphertext plus tag. It is public.

## 4. Encryption

```
header = 0x03 || salt || nonce                     (45 bytes)
ct     = ChaCha20Poly1305.encrypt(key = MK, nonce = nonce, plaintext, aad = header)
blob   = header || ct
```

Blob length is `len(plaintext) + 61`: 45 header bytes and a 16-byte tag.

## 5. Decryption and Stage 5

Parsing. Let `blob` be the input. For parsing only, copy it and pad the copy on the right with zero bytes to 45 bytes if it is shorter. Then `version = blob[0]`, `salt = blob[1:33]`, `nonce = blob[33:45]`, `body = blob[45:]`.

1. Compute `PRK = HKDF-Extract(salt, K)`.
2. The blob is **well formed** if `len(blob) >= 61` and `version == 0x03`.
3. If it is well formed, compute `MK` from `PRK` and `len(body)` (section 3) and run ChaCha20-Poly1305 decryption with nonce `nonce`, input `body`, and AAD equal to the first 45 bytes of the original blob. If the tag matches, return the plaintext and report valid.
4. In every other case (not well formed, or the tag does not match), report invalid and return the gibberish `G`, defined as the first `max(0, len(blob) - 61)` bytes of the ChaCha20 keystream (RFC 8439 §2.4) with key `decoy`, block counter 0, and a nonce of 12 zero bytes. `G` does not depend on the nonce or the tag in the blob, only on K and the salt bytes.

The length of `G` is the same for every failure of a given blob length, so the output length does not reveal why decryption failed. `decrypt` returns only the output. `verify` returns only the flag. Only a key of the wrong type or length raises an error.

This is deviation D1 in REQUIREMENTS.md. RFC 8439 says a message is accepted only if its tag matches, and that holds here: gibberish is never presented as an authenticated message. The deviation is that the failure is not signalled as an error.

**Why this section is so exact.** An independent implementation written from an earlier version of this section agreed with `dks.py` on every valid message, but disagreed on the gibberish bytes, because the earlier text did not give the decoy's nonce or counter and did not say what a wrong-version blob returns. See `verification/results/`.

## 5a. Exact encodings

- All strings used as HMAC data or HKDF `info` are the ASCII bytes shown, with no terminator, no length prefix and no separator before any index bytes.
- HKDF-Extract: HMAC-SHA256 with the salt as the key and the input keying material as the data (RFC 5869 §2.2). HKDF-Expand always requests 32 bytes, so it is the single block `T(1) = HMAC(PRK, info || 0x01)`.
- Ratchet: `S_{i+1} = HMAC-SHA256(key = S_i, data = "DKS-v3 ratchet" || uint64_be(i))`, with `i` starting at 0. So `S_1` uses `i = 0`.
- `steps = ceil(body_len / 32)`, where `body_len = len(ciphertext) + 16 = len(plaintext) + 16`. Because the tag counts, `body_len >= 16` and `steps >= 1` for every real message, so `S_0` is never used directly as the key input. A plaintext of 0 to 16 bytes uses 1 step, 17 to 48 bytes uses 2 steps, and so on.
- ChaCha20-Poly1305 follows RFC 8439 §2.8: the Poly1305 key is the first 32 bytes of the ChaCha20 block with counter 0, encryption starts at counter 1, the MAC input is `aad || pad16(aad) || ciphertext || pad16(ciphertext) || le64(len(aad)) || le64(len(ciphertext))`, and the tag follows the ciphertext. ChaCha20 words and the length fields are little-endian.
- Wrong sizes: a key that is not 32 bytes raises `ValueError`, a key that is not bytes raises `TypeError`. A salt or nonce of the wrong size is an error in `encrypt`. Blobs of any length are accepted by `decrypt` and never raise.

## 6. Password keys

```
K = PBKDF2-HMAC-SHA256(password, kdf_salt, iterations, 32 bytes)
```

Requirements (SP 800-132 §5, §5.1, §5.2; Appendix A.1): `kdf_salt` at least 16 bytes random,
`iterations` at least 1,000 (default 600,000, see D3), password at least 20 characters.
The caller stores `kdf_salt` and `iterations`. They are not in the blob.

## 7. Security goals (to test and argue, not proven)

**G1. Confidentiality (IND-CPA).** If HKDF and HMAC-SHA256 act as PRFs and ChaCha20-Poly1305 is IND-CPA, then MK is pseudorandom to an adversary who does not know K, and encryption is IND-CPA.

**G2. Integrity (INT-CTXT).** If HMAC acts as a PRF and ChaCha20-Poly1305 is INT-CTXT, a forged blob that `verify` accepts has negligible probability. The version byte and salt are in the AAD, so changing them also breaks validity.

**G3. Key dependence.** Without K, the chain values S_i and MK cannot be computed. This is tested as key-bit avalanche (`test_dks.py`), which is evidence, not proof.

**G4. Backward secrecy within a message.** Given S_i, the earlier values S_j (j < i) cannot be computed without inverting HMAC. Not directly tested.

**Not claimed:** forward secrecy across messages (each message restarts from K), resistance to side channels in Python, or post-quantum security.

## 8. What the chain adds

The chain costs time and adds a non-standard component. Compared with a standard design that derives MK = HKDF(K, salt, info) directly, the chain does not provide a security property that the standard design lacks, as far as this project has shown. A reviewer should ask whether it earns its place. Keeping it is the choice in the original idea, and this document does not claim it adds security.

## 9. Known limits

- Python cannot guarantee that intermediate `bytes` are erased. The wipe is best effort.
- The chain costs one HMAC per 32 bytes in Python, so throughput is far below native AEADs. See `bench.py` and the results in README.md.
- The SP 800-22 results cover the state stream only, and run on 30 sequences. The proportion rule cannot separate DKS from random data at that size. See REQUIREMENTS.md R4.
- Honey Encryption is not included. Its plausible-plaintext behaviour conflicts with the Stage 5 behaviour kept here.
