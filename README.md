# SM4核心算法实现

国密SM4分组密码算法的Python实现。

## 功能特性

- 严格按照GB/T 32907-2016标准实现
- 支持128位密钥和128位分组长度
- 包含完整的加解密功能
- 通过官方测试向量验证

## 使用方法

```python
from src.sm4_core import encrypt_block, decrypt_block

# 加密
key = bytes.fromhex("0123456789abcdeffedcba9876543210")
plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")
ciphertext = encrypt_block(plaintext, key)

# 解密
decrypted = decrypt_block(ciphertext, key)
assert decrypted == plaintext
```

## 运行测试

```bash
# 运行所有测试
pytest tests/ -v

# 运行性能测试
pytest tests/test_performance.py -v -s
```

## 项目结构

```
src/
├── __init__.py          # Python包初始化
├── constants.py         # SM4常量定义
├── sm4_core.py          # SM4核心算法实现
tests/
├── __init__.py          # Python包初始化
├── test_sm4_core.py     # 核心算法测试
└── test_performance.py  # 性能测试
```
