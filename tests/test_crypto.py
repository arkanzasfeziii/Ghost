"""Tests for crypto utilities."""

from ghost.utils.crypto import calc_entropy, rand_var, xor_bytes


def test_rand_var_length():
    v = rand_var(12)
    assert len(v) == 12


def test_rand_var_starts_with_letter():
    for _ in range(20):
        v = rand_var()
        assert v[0].isalpha()


def test_xor_bytes_roundtrip():
    data = b"hello world"
    key = b"\xaa"
    encrypted = xor_bytes(data, key)
    decrypted = xor_bytes(encrypted, key)
    assert decrypted == data


def test_xor_bytes_multi_key():
    data = b"test data here"
    key = b"\xde\xad"
    encrypted = xor_bytes(data, key)
    decrypted = xor_bytes(encrypted, key)
    assert decrypted == data


def test_calc_entropy_empty():
    assert calc_entropy(b"") == 0.0


def test_calc_entropy_single_byte():
    assert calc_entropy(b"\x00" * 100) == 0.0


def test_calc_entropy_random():
    data = bytes(range(256))
    e = calc_entropy(data)
    assert 7.9 < e <= 8.0


def test_calc_entropy_text():
    e = calc_entropy(b"hello world")
    assert 2.0 < e < 4.0
