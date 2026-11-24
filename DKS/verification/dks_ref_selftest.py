import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dks_ref as d


def h(s): return bytes.fromhex(s.replace(":", "").replace(" ", ""))

# RFC 8439 2.5.2 Poly1305
k = h("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
assert d.poly1305_mac(k, b"Cryptographic Forum Research Group") == h("a8061dc1305136c6c22b8baf0c0127a9")
print("poly1305 2.5.2 ok")

# RFC 8439 2.4.2 ChaCha20 (counter 1)
pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
ck = bytes(range(32)); cn = h("000000000000004a00000000")
ct = d.chacha20_xor(ck, 1, cn, pt)
assert ct[:16] == h("6e2e359a2568f98041ba0728dd0d6981"), ct[:16].hex()
print("chacha20 2.4.2 ok")

# RFC 8439 2.8.2 AEAD
key = bytes(range(0x80, 0xa0)); nonce = h("070000004041424344454647")
aad = h("50515253c0c1c2c3c4c5c6c7")
out = d.aead_encrypt(key, nonce, pt, aad)
assert out[:16] == h("d31a8d34648e60db7b86afbc53ef7ec2"), out[:16].hex()
assert out[-16:] == h("1ae10b594f09e26a7e902ecbd0600691"), out[-16:].hex()
assert d.aead_decrypt(key, nonce, out, aad) == pt
assert d.aead_decrypt(key, nonce, out[:-1] + b"\x00", aad) is None
print("aead 2.8.2 ok")

# RFC 5869 A.1
ikm = b"\x0b" * 22; salt = bytes(range(13)); info = bytes(range(0xf0, 0xfa))
prk = d.hkdf_extract(salt, ikm)
assert prk == h("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
assert d.hkdf_expand(prk, info, 42) == h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
print("hkdf A.1 ok")

# DKS round trips
K = os.urandom(32)
for n in (0, 1, 15, 16, 17, 31, 32, 33, 100, 1000):
    p = os.urandom(n); b = d.encrypt(K, p)
    assert len(b) == n + 61
    v, o = d.decrypt(K, b); assert v and o == p, n
    v, o = d.decrypt(os.urandom(32), b); assert not v and len(o) == n and (n == 0 or o != p)
    t = bytearray(b); t[-1] ^= 1
    v, o = d.decrypt(K, bytes(t)); assert not v and len(o) == n
print("dks round-trip, wrong-key, tamper ok")
print("state_after(0)=", d.state_after(bytes(32), bytes(32), 0).hex())
print("ALL OK")
