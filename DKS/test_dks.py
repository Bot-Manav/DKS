"""Verification suite for DKS v3. Each group maps to a requirement in REQUIREMENTS.md."""
import hashlib
import hmac
import json
import math
import os
import random
from collections import Counter
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import dks

VECTORS = Path(__file__).parent / "vectors"

KEY = bytes(range(32))
SALT = bytes(range(32))
NONCE = bytes(range(12))
PRK = dks._extract(SALT, KEY)

# Known-answer vectors generated from dks v3. A change here means the construction changed.
KAT_STATE_STREAM = bytes.fromhex(
    "c98b0fe5c26812cb67dbcc1132f0c156829dc4db22f6d5b01fc4fe1d6110cb72"
    "252bbcac55d4f62fc457fe5b0472dd7d7f9650d9b4134397349d10e98cc7371f")
KAT_MESSAGE_KEY = bytes.fromhex(
    "d6d858d077333230aa5a1d73ad4cd8fad86a2baf03ac9dd3a4b1d1929177813b")
KAT_CT = bytes.fromhex(
    "03000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "000102030405060708090a0b5bf2c47cfd1b63dd4af8a0219b3a8bad126c553cf7"
    "8e0edcd96e81b94b66a41ccddce7c62ffd6a62bf5d84")


def _load(name):
    return json.loads((VECTORS / name).read_text())


def bits_of(data):
    return [(b >> i) & 1 for b in data for i in range(8)]


def shannon_entropy_per_byte(data):
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def hamming_fraction(a, b):
    return sum((x ^ y).bit_count() for x, y in zip(a, b)) / (8 * len(a))


# ---------- A. Wycheproof vectors for the standard primitives (RFC 8439, RFC 5869, HMAC) ----------

def _wycheproof_aead_cases():
    for g in _load("chacha20_poly1305_test.json")["testGroups"]:
        if g["keySize"] != 256 or g["ivSize"] != 96 or g["tagSize"] != 128:
            continue  # cryptography supports only 256-bit keys, 96-bit nonces, 128-bit tags
        for t in g["tests"]:
            yield pytest.param(t, id=f"tc{t['tcId']}-{t['result']}")


@pytest.mark.parametrize("t", list(_wycheproof_aead_cases()))
def test_wycheproof_chacha20_poly1305(t):
    """RFC 8439 requirements: correct output for valid vectors; rejection for invalid ones."""
    key, iv = bytes.fromhex(t["key"]), bytes.fromhex(t["iv"])
    aad, msg = bytes.fromhex(t["aad"]), bytes.fromhex(t["msg"])
    ct, tag = bytes.fromhex(t["ct"]), bytes.fromhex(t["tag"])
    aead = ChaCha20Poly1305(key)
    if t["result"] == "valid":
        assert aead.encrypt(iv, msg, aad) == ct + tag
        assert aead.decrypt(iv, ct + tag, aad) == msg
    elif t["result"] == "invalid":
        with pytest.raises(InvalidTag):
            aead.decrypt(iv, ct + tag, aad)
    else:  # "acceptable": implementation may go either way
        pass


def _wycheproof_hkdf_cases():
    for g in _load("hkdf_sha256_test.json")["testGroups"]:
        for t in g["tests"]:
            yield pytest.param(t, id=f"tc{t['tcId']}-{t['result']}")


@pytest.mark.parametrize("t", list(_wycheproof_hkdf_cases()))
def test_wycheproof_hkdf_sha256(t):
    """RFC 5869 requirements, through dks.hkdf (Extract then Expand)."""
    args = {"salt": bytes.fromhex(t["salt"]), "ikm": bytes.fromhex(t["ikm"]),
                "info": bytes.fromhex(t["info"]), "length": t["size"]}
    okm = bytes.fromhex(t["okm"])
    if t["result"] == "valid":
        assert dks.hkdf(**args) == okm
    elif t["result"] == "invalid":
        try:
            out = dks.hkdf(**args)
        except ValueError:
            return  # rejected, e.g. length above 255 * HashLen
        assert out != okm


def _wycheproof_hmac_cases():
    for g in _load("hmac_sha256_test.json")["testGroups"]:
        for t in g["tests"]:
            yield pytest.param(g["tagSize"], t, id=f"tc{t['tcId']}-{t['result']}")


@pytest.mark.parametrize("tag_bits,t", list(_wycheproof_hmac_cases()))
def test_wycheproof_hmac_sha256(tag_bits, t):
    """The ratchet and extract both rely on HMAC-SHA256 being correct."""
    key, msg = bytes.fromhex(t["key"]), bytes.fromhex(t["msg"])
    tag = bytes.fromhex(t["tag"])
    full = hmac.new(key, msg, hashlib.sha256).digest()
    n = tag_bits // 8
    if t["result"] == "valid":
        assert full[:n] == tag
    elif t["result"] == "invalid":
        assert full[:n] != tag


# ---------- B. Requirements on sizes and formats (RFC 8439, RFC 5869, SP 800-132) ----------

def test_key_must_be_exactly_32_bytes():
    for bad in (b"", b"x" * 16, b"x" * 31, b"x" * 33):
        with pytest.raises(ValueError):
            dks.encrypt(bad, b"m")
    with pytest.raises(TypeError):
        dks.encrypt("string key", b"m")


def test_salt_is_32_bytes_and_nonce_is_12_bytes():
    blob = dks.encrypt(KEY, b"hello")
    assert blob[0] == dks.VERSION
    assert len(blob) == 1 + 32 + 12 + 5 + 16


def test_tag_is_full_16_bytes_and_not_truncated():
    blob = dks.encrypt(KEY, b"hello")
    assert len(blob) - dks.HEADER_LEN - 5 == 16


def test_hkdf_length_limit():
    with pytest.raises(ValueError):
        dks.hkdf(SALT, KEY, b"", 255 * 32 + 1)
    assert len(dks.hkdf(SALT, KEY, b"", 255 * 32)) == 255 * 32


def test_password_requirements():
    salt = os.urandom(16)
    with pytest.raises(ValueError):
        dks.derive_master_key("short", salt, iterations=1000)            # < 20 chars
    with pytest.raises(ValueError):
        dks.derive_master_key("a" * 20, os.urandom(15), iterations=1000)  # salt < 128 bits
    with pytest.raises(ValueError):
        dks.derive_master_key("a" * 20, salt, iterations=999)             # < 1000 iterations
    with pytest.raises(TypeError):
        dks.derive_master_key(b"a" * 20, salt)
    k = dks.derive_master_key("correct horse battery staple!", salt, iterations=1000)
    assert len(k) == 32  # >= 112 bits required, 256 bits provided


def test_password_key_is_deterministic_for_same_salt():
    salt = bytes(range(16))
    a = dks.derive_master_key("correct horse battery staple!", salt, iterations=1000)
    b = dks.derive_master_key("correct horse battery staple!", salt, iterations=1000)
    c = dks.derive_master_key("correct horse battery staple?", salt, iterations=1000)
    assert a == b and a != c


def test_password_key_round_trip():
    salt = os.urandom(16)
    mk = dks.derive_master_key("correct horse battery staple!", salt, iterations=1000)
    blob = dks.encrypt(mk, b"ACCOUNT 1")
    assert dks.decrypt(mk, blob) == b"ACCOUNT 1"


# ---------- C. Functional behaviour ----------

@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 31, 32, 33, 100, 4096])
def test_roundtrip(n):
    p = os.urandom(n)
    blob = dks.encrypt(KEY, p)
    assert len(blob) == n + dks.OVERHEAD
    assert dks.verify(KEY, blob)
    assert dks.decrypt(KEY, blob) == p


def test_encryption_is_randomised():
    assert dks.encrypt(KEY, b"same") != dks.encrypt(KEY, b"same")


def test_known_answer_state_stream():
    assert dks._state_stream(PRK, 64) == KAT_STATE_STREAM


def test_known_answer_message_key():
    assert dks._message_key(PRK, 24 + 16) == KAT_MESSAGE_KEY


def test_known_answer_ciphertext():
    msg = b"TRANSFER 50000 TO ACCOUNT A"
    assert dks._encrypt(KEY, SALT, NONCE, msg) == KAT_CT
    assert dks.verify(KEY, KAT_CT)
    assert dks.decrypt(KEY, KAT_CT) == msg


# ---------- D. Stage 5 (authentication, gibberish on failure) ----------

def test_wrong_key_rejected_and_gibberish():
    p = b"TRANSFER 50000 TO ACCOUNT A" * 20
    blob = dks.encrypt(KEY, p)
    wrong = bytes([KEY[0] ^ 1]) + KEY[1:]
    assert not dks.verify(wrong, blob)
    out = dks.decrypt(wrong, blob)
    assert len(out) == len(p) and out != p
    assert shannon_entropy_per_byte(out) > 4.5


def test_every_single_bit_flip_rejected():
    p = b"x" * 24
    blob = dks.encrypt(KEY, p)
    for byte_i in range(len(blob)):
        for bit in range(8):
            t = bytearray(blob)
            t[byte_i] ^= 1 << bit
            assert not dks.verify(KEY, bytes(t)), (byte_i, bit)


def test_tampered_blob_never_returns_plaintext():
    p = b"ACCOUNT STATEMENT 2026"
    blob = bytearray(dks.encrypt(KEY, p))
    blob[-1] ^= 1
    assert dks.decrypt(KEY, bytes(blob)) != p


def test_truncated_and_empty_inputs_do_not_raise():
    blob = dks.encrypt(KEY, b"hello")
    for n in range(len(blob)):
        assert not dks.verify(KEY, blob[:n])
        dks.decrypt(KEY, blob[:n])
    assert not dks.verify(KEY, b"")
    assert dks.decrypt(KEY, b"") == b""


def test_appended_data_rejected():
    assert not dks.verify(KEY, dks.encrypt(KEY, b"hello") + b"\x00")


def test_header_swap_rejected():
    a = dks.encrypt(KEY, b"message A")
    b = dks.encrypt(KEY, b"message B")
    franken = a[:1] + b[1:dks.HEADER_LEN] + a[dks.HEADER_LEN:]
    assert not dks.verify(KEY, franken)


# ---------- E. Avalanche and key sensitivity ----------

def test_key_bit_flip_avalanche():
    rng = random.Random(1234)
    fractions = []
    for _ in range(200):
        key = rng.randbytes(32)
        bit = rng.randrange(256)
        k2 = bytearray(key)
        k2[bit // 8] ^= 1 << (bit % 8)
        salt = rng.randbytes(32)
        s1 = dks._state_stream(dks._extract(salt, key), 1024)
        s2 = dks._state_stream(dks._extract(salt, bytes(k2)), 1024)
        fractions.append(hamming_fraction(s1, s2))
    mean = sum(fractions) / len(fractions)
    assert 0.495 < mean < 0.505, mean
    assert min(fractions) > 0.45 and max(fractions) < 0.55


def test_salt_bit_flip_avalanche():
    rng = random.Random(99)
    fractions = []
    for _ in range(200):
        salt = rng.randbytes(32)
        s2 = bytearray(salt)
        bit = rng.randrange(256)
        s2[bit // 8] ^= 1 << (bit % 8)
        key = rng.randbytes(32)
        s1 = dks._state_stream(dks._extract(salt, key), 1024)
        t = dks._state_stream(dks._extract(bytes(s2), key), 1024)
        fractions.append(hamming_fraction(s1, t))
    mean = sum(fractions) / len(fractions)
    assert 0.495 < mean < 0.505, mean


def test_plaintext_bit_flip_maps_to_one_ciphertext_bit():
    """Stream-cipher property. Not 50%: that target applies to hash outputs, not stream ciphers."""
    rng = random.Random(7)
    for _ in range(200):
        p = bytearray(rng.randbytes(256))
        p2 = bytearray(p)
        bit = rng.randrange(256 * 8)
        p2[bit // 8] ^= 1 << (bit % 8)
        c1 = dks._encrypt(KEY, SALT, NONCE, bytes(p))
        c2 = dks._encrypt(KEY, SALT, NONCE, bytes(p2))
        ct1 = c1[dks.HEADER_LEN:-dks.TAG_LEN]
        ct2 = c2[dks.HEADER_LEN:-dks.TAG_LEN]
        assert sum((x ^ y).bit_count() for x, y in zip(ct1, ct2)) == 1


def test_tag_avalanche_on_plaintext_bit():
    rng = random.Random(8)
    fractions = []
    for _ in range(200):
        p = bytearray(rng.randbytes(256))
        p2 = bytearray(p)
        bit = rng.randrange(256 * 8)
        p2[bit // 8] ^= 1 << (bit % 8)
        c1 = dks._encrypt(KEY, SALT, NONCE, bytes(p))
        c2 = dks._encrypt(KEY, SALT, NONCE, bytes(p2))
        fractions.append(hamming_fraction(c1[-dks.TAG_LEN:], c2[-dks.TAG_LEN:]))
    mean = sum(fractions) / len(fractions)
    assert 0.46 < mean < 0.54, mean


# ---------- F. Randomness: NIST SP 800-22 Rev 1a (see sp800_22.py and REQUIREMENTS.md R3) ----------

import sp800_22


def _lfsr(n, taps, init):
    s = list(init)
    while len(s) < n:
        s.append(sum(s[-t] for t in taps) & 1)
    return s


@pytest.mark.parametrize("taps,init,n,expected", [
    ([2, 5], [1, 0, 0, 1, 1], 60, 5),
    ([3, 8], [1, 0, 1, 1, 0, 0, 1, 0], 80, 8),
])
def test_berlekamp_massey_known_lfsr(taps, init, n, expected):
    """Validates the linear complexity routine on sequences whose complexity is known.

    nistrng's own routine fails this (it reports 30 for the first case)."""
    assert sp800_22.berlekamp_massey_gf2(_lfsr(n, taps, init)) == expected


def test_linear_complexity_on_fixed_random_passes():
    bits = sp800_22.bits_from_bytes(random.Random(42).randbytes(125_000))
    p, ok = sp800_22.linear_complexity_test(bits)
    assert ok, p


@pytest.fixture(scope="module")
def sp800_22_results():
    """One 1,000,000-bit DKS state-stream sequence through every available test."""
    stream = dks._state_stream(PRK, 125_000)
    return sp800_22.run_battery(sp800_22.bits_from_bytes(stream))


@pytest.mark.slow
def test_sp800_22_battery_returns_valid_p_values(sp800_22_results):
    """A single sequence cannot decide pass or fail (about 1% per test by chance).
    The verdict comes from sp800_22_run.py over many sequences. Here we check the battery
    runs and every p-value is a valid probability."""
    eligible = [r for r in sp800_22_results if r["eligible"]]
    assert len(eligible) >= 10, [r["name"] for r in sp800_22_results if not r["eligible"]]
    assert all(0.0 <= r["p"] <= 1.0 for r in eligible)
    assert any(r["name"] == "Linear Complexity" for r in eligible)


@pytest.mark.slow
def test_sp800_22_harness_rejects_bad_data():
    """Negative control: a periodic sequence must fail somewhere. Shows the battery can fail."""
    bad = bytes([0b10101010]) * 125_000
    results = sp800_22.run_battery(sp800_22.bits_from_bytes(bad))
    assert any(r["eligible"] and not r["passed"] for r in results)


def test_no_repeated_blocks():
    data = dks._state_stream(PRK, 32 * 10_000)
    blocks = {data[i:i + 32] for i in range(0, len(data), 32)}
    assert len(blocks) == 10_000


def test_different_salts_give_unrelated_streams():
    a = dks._state_stream(dks._extract(os.urandom(32), KEY), 4096)
    b = dks._state_stream(dks._extract(os.urandom(32), KEY), 4096)
    assert abs(hamming_fraction(a, b) - 0.5) < 0.02


def test_ciphertext_looks_random():
    c = dks.encrypt(KEY, bytes(8192))
    assert shannon_entropy_per_byte(c[dks.HEADER_LEN:-dks.TAG_LEN]) > 7.9
