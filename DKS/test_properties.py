from hypothesis import given, settings
from hypothesis import strategies as st

import dks

keys = st.binary(min_size=dks.KEY_LEN, max_size=dks.KEY_LEN)
messages = st.binary(max_size=512)


@settings(max_examples=200, deadline=None)
@given(keys, messages)
def test_roundtrip_property(key, msg):
    blob = dks.encrypt(key, msg)
    assert dks.verify(key, blob)
    assert dks.decrypt(key, blob) == msg


@settings(max_examples=200, deadline=None)
@given(keys, keys, messages)
def test_wrong_key_property(key, other, msg):
    if key == other:
        return
    blob = dks.encrypt(key, msg)
    assert not dks.verify(other, blob)
    assert len(dks.decrypt(other, blob)) == len(msg)


@settings(max_examples=200, deadline=None)
@given(keys, messages, st.data())
def test_single_flip_property(key, msg, data):
    blob = bytearray(dks.encrypt(key, msg))
    idx = data.draw(st.integers(min_value=0, max_value=len(blob) - 1))
    bit = data.draw(st.integers(min_value=0, max_value=7))
    blob[idx] ^= 1 << bit
    assert not dks.verify(key, bytes(blob))


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=200))
def test_arbitrary_blob_never_raises(blob):
    key = b"k" * dks.KEY_LEN
    out = dks.decrypt(key, blob)
    assert isinstance(out, bytes)
    assert not dks.verify(key, blob) or len(blob) >= dks.OVERHEAD
