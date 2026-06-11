import pytest
import os
import tempfile
from src.sm4_cipher import generate_keystream, ctr_encrypt, ctr_decrypt, encrypt_file, decrypt_file


class TestGenerateKeystream:
    def test_keystream_length(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        nonce = bytes.fromhex("0123456789abcdef")
        keystream = generate_keystream(key, nonce, 32)
        assert len(keystream) == 32

    def test_keystream_deterministic(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        nonce = bytes.fromhex("0123456789abcdef")
        keystream1 = generate_keystream(key, nonce, 32)
        keystream2 = generate_keystream(key, nonce, 32)
        assert keystream1 == keystream2

    def test_invalid_key_length(self):
        nonce = bytes.fromhex("0123456789abcdef")
        with pytest.raises(ValueError, match="密钥长度必须为16字节"):
            generate_keystream(b"short_key", nonce, 32)

    def test_invalid_nonce_length(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        with pytest.raises(ValueError, match="nonce长度必须为8字节"):
            generate_keystream(key, b"short", 32)


class TestCtrEncryptDecrypt:
    def test_encrypt_decrypt_consistency(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        nonce = bytes.fromhex("0123456789abcdef")
        data = b"Hello, World! This is a test message."
        ciphertext = ctr_encrypt(key, nonce, data)
        decrypted = ctr_decrypt(key, nonce, ciphertext)
        assert decrypted == data

    def test_empty_data(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        nonce = bytes.fromhex("0123456789abcdef")
        ciphertext = ctr_encrypt(key, nonce, b'')
        assert ciphertext == b''

    def test_different_lengths(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        nonce = bytes.fromhex("0123456789abcdef")
        for length in [0, 1, 15, 16, 17, 32, 100]:
            data = os.urandom(length)
            ciphertext = ctr_encrypt(key, nonce, data)
            decrypted = ctr_decrypt(key, nonce, ciphertext)
            assert decrypted == data
            assert len(ciphertext) == length

    def test_different_keys(self):
        nonce = bytes.fromhex("0123456789abcdef")
        data = b"Test data"
        key1 = bytes.fromhex("0123456789abcdeffedcba9876543210")
        key2 = bytes.fromhex("fedcba98765432100123456789abcdef")
        ciphertext1 = ctr_encrypt(key1, nonce, data)
        ciphertext2 = ctr_encrypt(key2, nonce, data)
        assert ciphertext1 != ciphertext2

    def test_different_nonces(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        data = b"Test data"
        nonce1 = bytes.fromhex("0123456789abcdef")
        nonce2 = bytes.fromhex("fedcba9876543210")
        ciphertext1 = ctr_encrypt(key, nonce1, data)
        ciphertext2 = ctr_encrypt(key, nonce2, data)
        assert ciphertext1 != ciphertext2


class TestFileEncryptDecrypt:
    def test_file_encrypt_decrypt(self):
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        nonce = bytes.fromhex("0123456789abcdef")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            input_path = f.name
            f.write(b"Hello, World! This is a test file.")
        try:
            encrypted_path = input_path + ".enc"
            encrypt_file(input_path, encrypted_path, key, nonce)
            decrypted_path = input_path + ".dec"
            decrypt_file(encrypted_path, decrypted_path, key, nonce)
            with open(decrypted_path, 'rb') as f:
                decrypted_data = f.read()
            assert decrypted_data == b"Hello, World! This is a test file."
        finally:
            os.unlink(input_path)
            if os.path.exists(encrypted_path):
                os.unlink(encrypted_path)
            if os.path.exists(decrypted_path):
                os.unlink(decrypted_path)

    def test_large_file_encrypt_decrypt(self):
        """测试大文件加密解密（多个分块）"""
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        nonce = bytes.fromhex("0123456789abcdef")
        # 创建大于1MB的数据，确保多个分块
        data = os.urandom(2 * 1024 * 1024 + 37)  # > 1MB, non-aligned
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            input_path = f.name
            f.write(data)
        
        try:
            encrypted_path = input_path + ".enc"
            encrypt_file(input_path, encrypted_path, key, nonce, chunk_size=1024*1024)
            
            decrypted_path = input_path + ".dec"
            decrypt_file(encrypted_path, decrypted_path, key, nonce, chunk_size=1024*1024)
            
            with open(decrypted_path, 'rb') as f:
                decrypted_data = f.read()
            
            assert decrypted_data == data
        finally:
            for p in [input_path, encrypted_path, decrypted_path]:
                if os.path.exists(p):
                    os.unlink(p)
