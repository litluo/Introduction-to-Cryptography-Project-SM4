import pytest
from src.sm4_core import (
    sbox_transform,
    circular_left_shift,
    l_transform,
    l_prime_transform,
    t_transform,
    t_prime_transform,
    encrypt_block,
    decrypt_block,
    key_expansion,
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


class TestKeyExpansion:
    def test_key_expansion_generates_32_round_keys(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        rk = key_expansion(key)
        assert len(rk) == 32

    def test_key_expansion_round_keys_are_32bit(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        rk = key_expansion(key)
        for r in rk:
            assert 0 <= r < (1 << 32)

    def test_key_expansion_invalid_length(self):
        with pytest.raises(ValueError, match="密钥长度必须为16字节"):
            key_expansion(b"short_key")

    def test_key_expansion_deterministic(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        assert key_expansion(key) == key_expansion(key)


class TestEncryptDecrypt:
    def test_official_test_vector(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")
        expected_ciphertext = bytes.fromhex("681edf34d206965e86b3e94f536e4246")
        ciphertext = encrypt_block(plaintext, key)
        assert ciphertext == expected_ciphertext

    def test_official_test_vector_decrypt(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        ciphertext = bytes.fromhex("681edf34d206965e86b3e94f536e4246")
        expected_plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")
        plaintext = decrypt_block(ciphertext, key)
        assert plaintext == expected_plaintext

    def test_encrypt_decrypt_consistency(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")
        ciphertext = encrypt_block(plaintext, key)
        decrypted = decrypt_block(ciphertext, key)
        assert decrypted == plaintext

    def test_invalid_key_length_encrypt(self):
        plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")
        with pytest.raises(ValueError, match="密钥长度必须为16字节"):
            encrypt_block(plaintext, b"short_key")

    def test_invalid_key_length_decrypt(self):
        ciphertext = bytes.fromhex("0123456789abcdeffedcba9876543210")
        with pytest.raises(ValueError, match="密钥长度必须为16字节"):
            decrypt_block(ciphertext, b"short_key")

    def test_invalid_plaintext_length(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        with pytest.raises(ValueError, match="明文长度必须为16字节"):
            encrypt_block(b"short", key)

    def test_invalid_ciphertext_length(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        with pytest.raises(ValueError, match="密文长度必须为16字节"):
            decrypt_block(b"short", key)

    def test_different_keys(self):
        plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")
        key1 = bytes.fromhex("0123456789abcdeffedcba9876543210")
        key2 = bytes.fromhex("fedcba98765432100123456789abcdef")
        ciphertext1 = encrypt_block(plaintext, key1)
        ciphertext2 = encrypt_block(plaintext, key2)
        assert ciphertext1 != ciphertext2

    def test_different_plaintexts(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        plaintext1 = bytes.fromhex("0123456789abcdeffedcba9876543210")
        plaintext2 = bytes.fromhex("fedcba98765432100123456789abcdef")
        ciphertext1 = encrypt_block(plaintext1, key)
        ciphertext2 = encrypt_block(plaintext2, key)
        assert ciphertext1 != ciphertext2

    def test_multiple_blocks(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        plaintexts = [
            bytes.fromhex("0123456789abcdeffedcba9876543210"),
            bytes.fromhex("fedcba98765432100123456789abcdef"),
            bytes.fromhex("00000000000000000000000000000000"),
            bytes.fromhex("ffffffffffffffffffffffffffffffff"),
        ]
        for plaintext in plaintexts:
            ciphertext = encrypt_block(plaintext, key)
            decrypted = decrypt_block(ciphertext, key)
            assert decrypted == plaintext

    def test_encrypt_with_precomputed_rk(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")
        expected_ciphertext = bytes.fromhex("681edf34d206965e86b3e94f536e4246")

        rk = key_expansion(key)
        ciphertext = encrypt_block(plaintext, rk=rk)
        assert ciphertext == expected_ciphertext

    def test_decrypt_with_precomputed_rk(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        ciphertext = bytes.fromhex("681edf34d206965e86b3e94f536e4246")
        expected_plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")

        rk = key_expansion(key)
        rk_reversed = list(reversed(rk))
        plaintext = decrypt_block(ciphertext, rk=rk_reversed)
        assert plaintext == expected_plaintext

    def test_encrypt_decrypt_with_precomputed_rk_consistency(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")

        rk = key_expansion(key)
        rk_reversed = list(reversed(rk))

        ciphertext = encrypt_block(plaintext, rk=rk)
        decrypted = decrypt_block(ciphertext, rk=rk_reversed)
        assert decrypted == plaintext

    def test_no_key_no_rk_raises_error(self):
        plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")
        with pytest.raises(ValueError, match="必须提供key或rk之一"):
            encrypt_block(plaintext)