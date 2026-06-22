"""Cryptographic and encoding utilities for payload manipulation."""

from __future__ import annotations

import math
import os
import random
import string


def rand_var(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=1)) + \
           "".join(random.choices(string.ascii_lowercase + string.digits, k=length - 1))


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])


def calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy
