# DKS v3 — design analysis, proof sketch and threat model

**Status: unreviewed draft. Not written or checked by a cryptographer. Nothing here is a proof that has been checked by anyone else. Treat every claim as a hypothesis to be reviewed.**

## A. What the key-state chain actually computes

For a message with `body_len = len(plaintext) + 16` and `steps = ceil(body_len / 32)`:

```
MK = HMAC(S_steps, "DKS-v3 message key" || 0x01)
S_0 = HMAC(PRK, "DKS-v3 state" || 0x01),  S_{i+1} = HMAC(S_i, "DKS-v3 ratchet" || uint64_be(i))
PRK = HMAC(salt, K)
```

So `MK` is a function of exactly three things: the key K, the salt, and the integer `steps`. **The chain never reads the message content.** The state does not "evolve as the message is processed" in the sense of absorbing the message. It evolves once per 32 bytes of message *length*. Two plaintexts of the same length under the same (K, salt) get the same `MK`.

Consequences:

1. The chain is a length-indexed key schedule: `MK = G(K, salt, steps)`.
2. Keys for different lengths under the same (K, salt) lie on one chain, so they are related. This does not matter in practice, because each message has its own random salt, so each (K, salt) is used once.
3. The cost is `steps` HMAC calls, so key derivation time grows linearly with message length. Length is already public from the blob size.
4. A plain construction `MK' = HKDF-Expand(PRK, "message key" || uint64_be(steps))` has the same inputs and the same interface with one HMAC call and no chain. The chain adds no input and no property that `MK'` lacks. This is measured in `results/chain_vs_hkdf.txt`.
5. Brute-forcing a 256-bit random K is impossible either way. The chain gives no useful key stretching: for password keys, the stretching comes from PBKDF2 (SP 800-132), not from the chain.

**Conclusion of A:** the chain is a valid but unnecessary key schedule. It is the project's distinguishing idea, but this analysis shows it is not what protects the data. The protection comes from HKDF, HMAC and ChaCha20-Poly1305. A reviewer will ask why the chain is there. A truthful answer today is "because it is the original idea", not "because it adds security".

## B. Reduction sketch (unreviewed)

**Goal.** Show that DKS-v3 encryption is IND-CPA and INT-CTXT, assuming standard properties of its parts.

**Assumptions** (each is an assumption, not a theorem):

- **A1. HMAC-SHA256 is a PRF when the key input is secret.** Used for `S_0 = HMAC(PRK, ·)`, the ratchet `S_{i+1} = HMAC(S_i, ·)`, and `MK = HMAC(S_steps, ·)`.
- **A2. HMAC-SHA256 is a dual PRF.** `PRK = HMAC(salt, K)` has a *public* salt as the HMAC key and the secret K as the message. A1 does not cover this. The standard proof for HMAC as a PRF treats the first input as the key. A2 is the assumption that HMAC is also pseudorandom in its second input when the first is public and arbitrary. It is used in analyses of HKDF-Extract and the TLS 1.3 key schedule, but it is a separate assumption.
- **A3. ChaCha20-Poly1305 is IND-CPA and INT-CTXT** under a uniformly random 256-bit key, with a unique nonce.

**Sketch.**

1. By A2, for a fresh uniform salt, `PRK` is pseudorandom. The adversary sees the salt but not K. Forgery attempts choose their own salts, so A2 is needed at adversary-chosen salts too.
2. By A1 and a hybrid argument over the `steps` calls, `S_steps` is pseudorandom, and so is `MK`. The security loss is at most `steps_max × Adv(A1)` per message.
3. With a pseudorandom `MK` that is independent across messages (distinct salts), A3 gives IND-CPA and INT-CTXT for the whole scheme. The header (version, salt, nonce) is authenticated as AAD.
4. **Collisions.** If two messages share a salt, they share `PRK`, and equal-length messages share `MK`. The salt collision probability over `q` messages is about `q² / 2^257`. The random-nonce collision under a repeated key is at most `q² / 2^97`.
5. **The failure gibberish.** `decrypt` returns `G` (a keystream under a key derived from PRK) on failure. `G` depends only on K, the salt and the length. A simulator can answer decryption queries on invalid blobs with consistent random bytes per salt, so the usual argument that IND-CPA and INT-CTXT give IND-CCA still goes through. The `verify` flag is an explicit validity oracle, and no deniability is claimed.

**Approximate bound:** `Adv ≤ q·Adv_A2 + q·steps_max·Adv_A1 + Adv_A3 + q²/2^97`.

**Not shown here, and what a reviewer must check:** the exact security of the hybrid in step 2; whether A2 is acceptable for HMAC-SHA256 in this role; the simulator for step 5; and that nothing else in the code leaks information about K. None of this has been checked by anyone but the author.

## C. Threat model

**Assets.** Message confidentiality, message integrity and authenticity, secrecy of the master key K.

**Attacker.** Knows the algorithm and all blobs. Can obtain encryptions of chosen plaintexts, can submit chosen blobs to `decrypt` and `verify`, and can observe blob lengths. Cannot read K.

**In scope**

- Confidentiality of content under chosen plaintexts (A3, B).
- Detection of modification of any byte of the blob, including the header (tested by single-bit-flip tests and fuzzing).
- Wrong keys never authenticate (tested).

**Out of scope or not provided**

| Item | Detail |
|---|---|
| Length hiding | The blob length is exactly `len(plaintext) + 61`. Lengths are not padded. |
| Replay, reordering, deletion | Not detected. Each blob is independent. |
| Context binding | `encrypt(key, plaintext)` takes no associated data, so callers cannot bind a blob to a user, file name or version. A caller must put that inside the plaintext. This is a real limitation. Adding an `aad` parameter is a straightforward fix. |
| Streaming and chunking | The whole message is processed in memory. There is no chunk authentication. |
| Key commitment | ChaCha20-Poly1305 is known not to be key-committing in general. A blob crafted by someone who knows two keys may be able to authenticate under both. Not tested here. |
| Validity oracle | `verify` returns whether authentication succeeded. A caller that exposes it, or whose behaviour differs on valid and invalid blobs, gives an attacker a validity oracle. The gibberish output does not remove that. |
| Side channels | The implementation is Python. Timing and memory-wipe guarantees cannot be given. A timing test is in `results/timing.txt` and is only indicative. |
| Key storage and rotation | Not provided. The caller manages K. Do not reuse a password-derived key without a fresh KDF salt per key. |
| Quantum attackers | ChaCha20 and HMAC-SHA256 have 256-bit keys, so Grover-style search costs about 2^128. Nothing else was analysed. |
| Denial of service | Cost is linear in message length (one HMAC per 32 bytes plus the AEAD). There is no size limit in the code. |

**Misuse cases the code does guard against:** keys of the wrong length or type raise errors; passwords shorter than 20 characters, KDF salts under 16 bytes and iteration counts under 1,000 are rejected; the salt and nonce are always freshly random in the public `encrypt`.

**Misuse cases it does not guard against:** weak but long passwords, reusing a key across unrelated purposes, storing keys next to ciphertexts, calling the internal deterministic `_encrypt` with a repeated salt or nonce.
