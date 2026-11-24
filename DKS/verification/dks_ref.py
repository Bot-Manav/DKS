"""Independent reference implementation of DKS v3 (written from SPEC.md only).

Spec sections implemented: 2 (parameters), 3 (derivations), 4 (encryption),
5 (decryption and Stage 5 gibberish on failure). Section 6 (PBKDF2 password keys)
is not implemented here. Pure stdlib: ChaCha20, Poly1305, RFC 8439 AEAD,
HKDF-Extract/Expand (RFC 5869) are written by hand.
"""
import hashlib
import hmac
import os
import struct

VERSION = b"\x03"
HEADER_LEN = 45
TAG_LEN = 16
BLOCK = 32
M32 = 0xFFFFFFFF


# ---------------- ChaCha20 (RFC 8439 s2.3, 2.4) ----------------
def _rotl(v, n):
    return ((v << n) & M32) | (v >> (32 - n))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & M32; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & M32; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & M32; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & M32; s[b] = _rotl(s[b] ^ s[c], 7)


def chacha20_block(key, counter, nonce):
    st = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    st += list(struct.unpack("<8I", key))
    st += [counter & M32]
    st += list(struct.unpack("<3I", nonce))
    w = st[:]
    for _ in range(10):
        _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13); _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
        _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12); _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(w[i] + st[i]) & M32 for i in range(16)])


def chacha20_xor(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha20_block(key, counter + i // 64, nonce)
        chunk = data[i:i + 64]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


# ---------------- Poly1305 (RFC 8439 s2.5) ----------------
def poly1305_mac(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16] + b"\x01", "little")
        acc = ((acc + n) * r) % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b):
    return b"\x00" * (-len(b) % 16)


def _aead_mac(otk, aad, ct):
    data = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    return poly1305_mac(otk, data)


def aead_encrypt(key, nonce, plaintext, aad):
    otk = chacha20_block(key, 0, nonce)[:32]
    ct = chacha20_xor(key, 1, nonce, plaintext)
    return ct + _aead_mac(otk, aad, ct)


def aead_decrypt(key, nonce, ct_tag, aad):
    """Returns plaintext or None."""
    if len(ct_tag) < TAG_LEN:
        return None
    ct, tag = ct_tag[:-TAG_LEN], ct_tag[-TAG_LEN:]
    otk = chacha20_block(key, 0, nonce)[:32]
    if not hmac.compare_digest(_aead_mac(otk, aad, ct), tag):
        return None
    return chacha20_xor(key, 1, nonce, ct)


# ---------------- HKDF (RFC 5869) ----------------
def hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt, ikm):
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk, info, length):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac_sha256(prk, t + info + bytes([i]))
        out += t
        i += 1
    return out[:length]


# ---------------- DKS v3 ----------------
def _check(key, salt=None, nonce=None):
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if salt is not None and len(salt) != 32:
        raise ValueError("salt must be 32 bytes")
    if nonce is not None and len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")


def _prk(key, salt):
    return hkdf_extract(bytes(salt), bytes(key))


def _state_from_prk(prk, steps):
    s = hkdf_expand(prk, b"DKS-v3 state", 32)
    for i in range(steps):
        s = hmac_sha256(s, b"DKS-v3 ratchet" + struct.pack(">Q", i))
    return s


def state_after(key, salt, steps):
    _check(key, salt)
    return _state_from_prk(_prk(key, salt), steps)


def message_key(key, salt, body_len):
    _check(key, salt)
    steps = -(-body_len // BLOCK)
    return hkdf_expand(state_after(key, salt, steps), b"DKS-v3 message key", 32)


def encrypt_with_params(key, salt, nonce, plaintext):
    _check(key, salt, nonce)
    header = VERSION + bytes(salt) + bytes(nonce)
    mk = message_key(key, salt, len(plaintext) + TAG_LEN)
    return header + aead_encrypt(mk, bytes(nonce), bytes(plaintext), header)


def encrypt(key, plaintext):
    return encrypt_with_params(key, os.urandom(32), os.urandom(12), plaintext)


def decrypt(key, blob):
    """Returns (valid, output). Failure output follows SPEC.md section 5 (revised).

    History: the first version of this function was written from the earlier SPEC.md, which did
    not define the decoy nonce or the output for a wrong-version blob. That version used the
    blob's nonce and returned b"" for malformed blobs, and disagreed with dks.py on the
    gibberish bytes (see results/crosscheck_before_spec_fix.txt). Only this failure branch was
    changed after the spec was clarified. The cryptographic core above is untouched.
    """
    _check(key)
    blob = bytes(blob)
    padded = blob.ljust(HEADER_LEN, b"\x00")           # parsing copy only (spec section 5)
    salt, nonce = padded[1:33], padded[33:45]
    prk = _prk(key, salt)
    if len(blob) >= HEADER_LEN + TAG_LEN and blob[0:1] == VERSION:
        header, body = blob[:HEADER_LEN], blob[HEADER_LEN:]
        steps = -(-len(body) // BLOCK)
        mk = hkdf_expand(_state_from_prk(prk, steps), b"DKS-v3 message key", 32)
        pt = aead_decrypt(mk, nonce, body, header)
        if pt is not None:
            return (True, pt)
    decoy = hkdf_expand(prk, b"DKS-v3 decoy", 32)
    n = max(0, len(blob) - (HEADER_LEN + TAG_LEN))
    return (False, chacha20_xor(decoy, 0, b"\x00" * 12, b"\x00" * n))
