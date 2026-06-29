"""Boundary tests for ghost.utils.crypto functions."""

from ghost.utils.crypto import calc_entropy, rand_var, xor_bytes


# ── rand_var ────────────────────────────────────────────────────────────────

def test_rand_var_length_1():
    v = rand_var(1)
    assert len(v) == 1 and v.isalpha()


def test_rand_var_length_100():
    v = rand_var(100)
    assert len(v) == 100


def test_rand_var_starts_alpha():
    for _ in range(50):
        assert rand_var()[0].isalpha()


def test_rand_var_default_length():
    assert len(rand_var()) == 8


def test_rand_var_uniqueness():
    results = {rand_var(12) for _ in range(100)}
    assert len(results) > 90


# ── xor_bytes ───────────────────────────────────────────────────────────────

def test_xor_empty_data():
    assert xor_bytes(b"", b"\xaa") == b""


def test_xor_single_byte_key():
    data = b"AAAA"
    key = b"\xff"
    result = xor_bytes(data, key)
    assert len(result) == 4
    assert xor_bytes(result, key) == data


def test_xor_same_length_key():
    data = b"hello"
    key = b"world"
    result = xor_bytes(data, key)
    assert xor_bytes(result, key) == data


def test_xor_long_key():
    data = b"AB"
    key = b"\xde\xad\xbe\xef\x00\x01\x02\x03"
    result = xor_bytes(data, key)
    assert len(result) == 2


def test_xor_all_zeros():
    data = b"\x00" * 256
    key = b"\x00"
    assert xor_bytes(data, key) == data


# ── calc_entropy ────────────────────────────────────────────────────────────

def test_entropy_empty():
    assert calc_entropy(b"") == 0.0


def test_entropy_single_byte_repeated():
    assert calc_entropy(b"\x41" * 1000) == 0.0


def test_entropy_two_bytes_equal():
    data = b"\x00\x01" * 500
    e = calc_entropy(data)
    assert 0.9 < e < 1.1


def test_entropy_full_range():
    data = bytes(range(256))
    e = calc_entropy(data)
    assert 7.9 < e <= 8.0


def test_entropy_short_data():
    e = calc_entropy(b"ab")
    assert e == 1.0
