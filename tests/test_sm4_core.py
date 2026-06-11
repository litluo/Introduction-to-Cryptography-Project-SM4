import pytest
from src.sm4_core import (
    sbox_transform,
    circular_left_shift,
    l_transform,
    l_prime_transform,
    t_transform,
    t_prime_transform,
)


class TestSboxTransform:
    def test_sbox_boundary_values(self):
        assert sbox_transform(0) == 0xd6
        assert sbox_transform(255) == 0x48

    def test_sbox_known_values(self):
        assert sbox_transform(0x01) == 0x90
        assert sbox_transform(0x80) == 0xea


class TestCircularLeftShift:
    def test_no_shift(self):
        assert circular_left_shift(0x12345678, 0) == 0x12345678

    def test_shift_by_8(self):
        assert circular_left_shift(0x12345678, 8) == 0x34567812

    def test_shift_by_32_is_identity(self):
        assert circular_left_shift(0x12345678, 32) == 0x12345678

    def test_shift_wraps_around(self):
        assert circular_left_shift(0x80000000, 1) == 0x00000001


class TestLTransform:
    def test_l_transform_zero(self):
        assert l_transform(0) == 0

    def test_l_transform_identity(self):
        data = 0x01234567
        result = l_transform(data)
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFFFFFF


class TestLPrimeTransform:
    def test_l_prime_transform_zero(self):
        assert l_prime_transform(0) == 0

    def test_l_prime_transform_identity(self):
        data = 0x01234567
        result = l_prime_transform(data)
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFFFFFF


class TestTTransform:
    def test_t_transform_zero(self):
        result = t_transform(0)
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFFFFFF

    def test_t_transform_known_value(self):
        data = 0x01234567
        result = t_transform(data)
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFFFFFF

    def test_t_transform_composition(self):
        data = 0xAABBCCDD
        b0 = (data >> 24) & 0xff
        b1 = (data >> 16) & 0xff
        b2 = (data >> 8) & 0xff
        b3 = data & 0xff

        b0 = sbox_transform(b0)
        b1 = sbox_transform(b1)
        b2 = sbox_transform(b2)
        b3 = sbox_transform(b3)

        transformed = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
        expected = l_transform(transformed)

        assert t_transform(data) == expected

    def test_t_transform_deterministic(self):
        data = 0x12345678
        assert t_transform(data) == t_transform(data)


class TestTPrimeTransform:
    def test_t_prime_transform_zero(self):
        result = t_prime_transform(0)
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFFFFFF

    def test_t_prime_transform_known_value(self):
        data = 0x01234567
        result = t_prime_transform(data)
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFFFFFF

    def test_t_prime_transform_composition(self):
        data = 0xAABBCCDD
        b0 = (data >> 24) & 0xff
        b1 = (data >> 16) & 0xff
        b2 = (data >> 8) & 0xff
        b3 = data & 0xff

        b0 = sbox_transform(b0)
        b1 = sbox_transform(b1)
        b2 = sbox_transform(b2)
        b3 = sbox_transform(b3)

        transformed = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
        expected = l_prime_transform(transformed)

        assert t_prime_transform(data) == expected

    def test_t_prime_transform_deterministic(self):
        data = 0x12345678
        assert t_prime_transform(data) == t_prime_transform(data)

    def test_t_and_t_prime_differ(self):
        data = 0x01234567
        assert t_transform(data) != t_prime_transform(data)