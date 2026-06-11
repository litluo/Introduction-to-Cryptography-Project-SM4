import time
import pytest
from src.sm4_core import encrypt_block, decrypt_block


class TestSM4Performance:
    """SM4性能测试类"""

    def test_encrypt_performance(self):
        """测试加密性能"""
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")

        # 预热
        for _ in range(100):
            encrypt_block(plaintext, key)

        # 性能测试
        iterations = 10000
        start_time = time.time()

        for _ in range(iterations):
            encrypt_block(plaintext, key)

        end_time = time.time()
        elapsed = end_time - start_time

        print(f"\n加密性能: {iterations}次加密耗时{elapsed:.3f}秒")
        print(f"平均每次加密: {elapsed/iterations*1000:.3f}毫秒")
        print(f"加密速度: {iterations/elapsed:.0f}次/秒")

        # 性能应该在合理范围内（每次加密不超过10毫秒）
        assert elapsed/iterations < 0.01

    def test_decrypt_performance(self):
        """测试解密性能"""
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        ciphertext = bytes.fromhex("681edf34d206965e86b3e94f536e4246")

        # 预热
        for _ in range(100):
            decrypt_block(ciphertext, key)

        # 性能测试
        iterations = 10000
        start_time = time.time()

        for _ in range(iterations):
            decrypt_block(ciphertext, key)

        end_time = time.time()
        elapsed = end_time - start_time

        print(f"\n解密性能: {iterations}次解密耗时{elapsed:.3f}秒")
        print(f"平均每次解密: {elapsed/iterations*1000:.3f}毫秒")
        print(f"解密速度: {iterations/elapsed:.0f}次/秒")

        # 性能应该在合理范围内（每次解密不超过10毫秒）
        assert elapsed/iterations < 0.01
