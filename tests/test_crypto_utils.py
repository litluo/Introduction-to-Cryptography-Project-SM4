import pytest
from src.crypto_utils import pbkdf2_hmac_sha256, generate_salt, generate_key, generate_nonce


class TestPBKDF2:
    """PBKDF2密钥派生测试"""

    def test_key_length(self):
        """测试派生密钥长度"""
        password = "test_password"
        salt = generate_salt()
        key = pbkdf2_hmac_sha256(password, salt)
        assert len(key) == 32

    def test_deterministic(self):
        """测试确定性"""
        password = "test_password"
        salt = b'\x00' * 32
        key1 = pbkdf2_hmac_sha256(password, salt)
        key2 = pbkdf2_hmac_sha256(password, salt)
        assert key1 == key2

    def test_different_passwords(self):
        """测试不同密码"""
        salt = generate_salt()
        key1 = pbkdf2_hmac_sha256("password1", salt)
        key2 = pbkdf2_hmac_sha256("password2", salt)
        assert key1 != key2

    def test_different_salts(self):
        """测试不同盐值"""
        password = "test_password"
        salt1 = generate_salt()
        salt2 = generate_salt()
        key1 = pbkdf2_hmac_sha256(password, salt1)
        key2 = pbkdf2_hmac_sha256(password, salt2)
        assert key1 != key2


class TestRandomGeneration:
    """随机数生成测试"""

    def test_salt_length(self):
        """测试盐值长度"""
        salt = generate_salt()
        assert len(salt) == 32

    def test_key_length(self):
        """测试密钥长度"""
        key = generate_key()
        assert len(key) == 16

    def test_nonce_length(self):
        """测试nonce长度"""
        nonce = generate_nonce()
        assert len(nonce) == 8

    def test_randomness(self):
        """测试随机性"""
        salt1 = generate_salt()
        salt2 = generate_salt()
        assert salt1 != salt2
