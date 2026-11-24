"""
Dynamic Key-State Encryption (DKS) - v3.

Main logic (unchanged from the original idea): the key starts a state, the state
evolves as the message is processed, and the state chain produces the key that
encrypts the message. Decryption rebuilds the same chain from the key.

Standard parts, and the source each one follows (see REQUIREMENTS.md):
  * Extract / Expand: HKDF, RFC 5869 (Extract = HMAC(salt, IKM), Expand via
    cryptography's HKDFExpand).
  * AEAD: ChaCha20-Poly1305, RFC 8439 (32-byte key, 96-bit nonce unique per key,
    full 128-bit tag, AAD authenticated).
  * Password keys: PBKDF2-HMAC-SHA256, NIST SP 800-132 (salt >= 128 bits,
    derived key >= 112 bits, approved PRF).

Non-standard part (no standard approves it): the state chain. It is a key
schedule built from HMAC, and its security is argued in SPEC.md, not established.

Stage 5 (design decision): decrypt() returns gibberish of the correct length
when authentication fails. It never raises for bad data. Non-standard, see
REQUIREMENTS.md, deviation D1.

Research prototype. Not reviewed by a cryptographer.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VERSION = 0x03

KEY_LEN = 32            # RFC 8439 section 2.8: 256-bit key
NONCE_LEN = 12          # RFC 8439 section 2.8: 96-bit nonce
TAG_LEN = 16            # RFC 8439 section 2.8: full 128-bit tag, no truncation
SALT_LEN = 32           # RFC 5869 section 3.1: salt ideally HashLen (32 bytes)
HASH_LEN = 32           # SHA-256 output length
BLOCK_LEN = 32          # state advances once per 32 bytes of body
HEADER_LEN = 1 + SALT_LEN + NONCE_LEN
OVERHEAD = HEADER_LEN + TAG_LEN

PBKDF_MIN_SALT_LEN = 16         # SP 800-132 section 5.1: >= 128 bits random salt
PBKDF_MIN_ITERATIONS = 1000     # SP 800-132 section 5.2 minimum
PBKDF_DEFAULT_ITERATIONS = 600_000  # not from the fetched sources; OWASP guidance
PASSWORD_MIN_CHARS = 20         # SP 800-132 Appendix A.1: passphrases under 20 chars are weak
PBKDF_OUT_LEN = KEY_LEN         # 256 bits >= 112 bits required (SP 800-132 section 5)

_LABEL_STATE = b"DKS-v3 state"
_LABEL_RATCHET = b"DKS-v3 ratchet"
_LABEL_MSG_KEY = b"DKS-v3 message key"
_LABEL_DECOY = b"DKS-v3 decoy"


def _check_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    if len(key) != KEY_LEN:
        raise ValueError(f"key must be exactly {KEY_LEN} bytes (256 bits)")


def _wipe(buf: bytearray) -> None:
    """Best-effort overwrite. Python cannot guarantee this for immutable bytes."""
    for i in range(len(buf)):
        buf[i] = 0


def _extract(salt: bytes, key: bytes) -> bytes:
    """HKDF-Extract, RFC 5869 section 2.2: PRK = HMAC-Hash(salt, IKM)."""
    return hmac.new(salt, key, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int = HASH_LEN) -> bytes:
    """HKDF-Expand, RFC 5869 section 2.3."""
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(prk)


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """Full HKDF (Extract then Expand). Exposed so Wycheproof vectors can test it."""
    if length > 255 * HASH_LEN:
        raise ValueError("HKDF output length limit is 255 * HashLen (RFC 5869 section 2.3)")
    return _expand(_extract(salt, ikm), info, length)


def _ratchet(state: bytes, i: int) -> bytes:
    """One state transition: S_{i+1} = HMAC(S_i, label || uint64_be(i))."""
    return hmac.new(state, _LABEL_RATCHET + struct.pack(">Q", i), hashlib.sha256).digest()


def _state_after(prk: bytes, steps: int) -> bytes:
    """Return S_steps. S_0 = HKDF-Expand(PRK, state label)."""
    state = bytearray(_expand(prk, _LABEL_STATE))
    for i in range(steps):
        nxt = bytearray(_ratchet(bytes(state), i))
        _wipe(state)
        state = nxt
    result = bytes(state)
    _wipe(state)
    return result


def _message_key(prk: bytes, body_len: int) -> bytes:
    """Per-message AEAD key: the state after ceil(body_len / 32) steps, then Expand."""
    steps = -(-body_len // BLOCK_LEN)
    return _expand(_state_after(prk, steps), _LABEL_MSG_KEY)


def _state_stream(prk: bytes, n_bytes: int) -> bytes:
    """The raw state sequence S_1, S_2, ... concatenated. Used by the randomness tests."""
    out = bytearray()
    state = _expand(prk, _LABEL_STATE)
    i = 0
    while len(out) < n_bytes:
        state = _ratchet(state, i)
        out += state
        i += 1
    return bytes(out[:n_bytes])


def _decoy(prk: bytes, n: int) -> bytes:
    """Gibberish of length n, keyed by a secret derived from the key. Used on failure."""
    key = _expand(prk, _LABEL_DECOY)
    enc = Cipher(algorithms.ChaCha20(key, bytes(16)), mode=None).encryptor()
    return enc.update(bytes(n))


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt. Returns version || salt || nonce || ChaCha20-Poly1305(ciphertext || tag)."""
    _check_key(key)
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    return _encrypt(key, salt, nonce, bytes(plaintext))


def _encrypt(key: bytes, salt: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """Deterministic core, exposed for tests and known-answer vectors."""
    _check_key(key)
    header = bytes([VERSION]) + salt + nonce
    prk = _extract(salt, key)
    mk = _message_key(prk, len(plaintext) + TAG_LEN)
    ct = ChaCha20Poly1305(mk).encrypt(nonce, plaintext, header)
    return header + ct


def _open(key: bytes, blob: bytes) -> tuple[bytes, bool]:
    """Return (output, valid). output is the plaintext if valid, else gibberish."""
    _check_key(key)
    blob = bytes(blob)
    well_formed = len(blob) >= OVERHEAD and blob[0] == VERSION
    padded = blob.ljust(HEADER_LEN, b"\x00")
    header = padded[:HEADER_LEN]
    salt = header[1:1 + SALT_LEN]
    nonce = header[1 + SALT_LEN:HEADER_LEN]
    body = blob[HEADER_LEN:]

    prk = _extract(salt, key)
    n_ct = max(0, len(body) - TAG_LEN)
    decoy = _decoy(prk, n_ct)
    if not well_formed:
        # Length and version are public, so branching on them leaks nothing secret.
        return decoy, False

    # Timing hardening: no exception is raised on a bad tag, the decoy is always computed,
    # and the output is chosen with a bitmask. The tag is recomputed by re-encrypting the
    # candidate plaintext (which reproduces the received ciphertext) and compared with
    # hmac.compare_digest. Python still cannot guarantee constant time (see SPEC.md).
    mk = _message_key(prk, len(body))
    ct, tag = body[:-TAG_LEN], body[-TAG_LEN:]
    candidate = _keystream_xor(mk, nonce, ct)
    expected = ChaCha20Poly1305(mk).encrypt(nonce, candidate, header)[-TAG_LEN:]
    valid = hmac.compare_digest(expected, tag)
    return _select(valid, candidate, decoy), valid


def _keystream_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """ChaCha20 with block counter 1, as used for the AEAD payload (RFC 8439 section 2.8)."""
    enc = Cipher(algorithms.ChaCha20(key, b"\x01\x00\x00\x00" + nonce), mode=None).encryptor()
    return enc.update(data)


def _select(valid: bool, real: bytes, decoy: bytes) -> bytes:
    """Return real if valid else decoy, using a mask instead of a branch."""
    n = len(real)
    if n == 0:
        return b""
    # A leading 0x01 byte keeps both operands the same size. Python big integers drop leading
    # zero limbs, which would make an all-zero plaintext measurably faster to process.
    a = int.from_bytes(b"\x01" + real, "big")
    b = int.from_bytes(b"\x01" + decoy, "big")
    mask = (-int(not valid)) & ((1 << (8 * n)) - 1)   # all ones if invalid, zero if valid
    return (a ^ ((a ^ b) & mask)).to_bytes(n + 1, "big")[1:]


def decrypt(key: bytes, blob: bytes) -> bytes:
    """Return the plaintext if the blob is authentic, otherwise gibberish of the same length.

    Never raises for malformed or tampered data. Only a wrong key type or length raises.
    """
    return _open(key, blob)[0]


def verify(key: bytes, blob: bytes) -> bool:
    """True only if the blob was produced by encrypt() with this key and is untampered."""
    return _open(key, blob)[1]


def derive_master_key(password: str, kdf_salt: bytes,
                      iterations: int = PBKDF_DEFAULT_ITERATIONS) -> bytes:
    """Turn a user password into a 256-bit master key (SP 800-132, PBKDF2-HMAC-SHA256).

    Store kdf_salt and iterations alongside the ciphertext. Passwords shorter than
    PASSWORD_MIN_CHARS characters are rejected.
    """
    if not isinstance(password, str):
        raise TypeError("password must be str")
    if len(password) < PASSWORD_MIN_CHARS:
        raise ValueError(f"password must be at least {PASSWORD_MIN_CHARS} characters")
    if len(kdf_salt) < PBKDF_MIN_SALT_LEN:
        raise ValueError(f"kdf_salt must be at least {PBKDF_MIN_SALT_LEN} bytes")
    if iterations < PBKDF_MIN_ITERATIONS:
        raise ValueError(f"iterations must be at least {PBKDF_MIN_ITERATIONS}")
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=PBKDF_OUT_LEN,
                      salt=bytes(kdf_salt), iterations=iterations).derive(
        password.encode("utf-8"))
