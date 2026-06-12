# SM4核心算法实现

国密SM4分组密码算法的Python实现，包含CTR工作模式和保密文件库管理。

## 功能特性

- 严格按照GB/T 32907-2016标准实现
- 支持128位密钥和128位分组长度
- 包含完整的加解密功能
- 支持CTR工作模式，可加密任意长度数据
- 支持文件加密解密
- 支持保密文件库管理
- 支持命令行界面
- 通过官方测试向量验证

## 使用方法

### 命令行界面

```bash
# 启动CLI
python -m src.cli
```

CLI功能：
1. 初始化新文件库
2. 打开现有文件库
3. 导入文件
4. 导出文件
5. 查看文件列表
6. 删除文件
7. 修改密码
8. 性能测试

### 基础加解密

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

### CTR模式加解密

```python
from src.sm4_cipher import ctr_encrypt, ctr_decrypt

key = bytes.fromhex("0123456789abcdeffedcba9876543210")
nonce = bytes.fromhex("0123456789abcdef")
data = b"Hello, World! This is a test message."

# 加密
ciphertext = ctr_encrypt(key, nonce, data)

# 解密
decrypted = ctr_decrypt(key, nonce, ciphertext)
assert decrypted == data
```

### 文件加密解密

```python
from src.sm4_cipher import encrypt_file, decrypt_file

key = bytes.fromhex("0123456789abcdeffedcba9876543210")
nonce = bytes.fromhex("0123456789abcdef")

# 加密文件
encrypt_file("input.txt", "encrypted.bin", key, nonce)

# 解密文件
decrypt_file("encrypted.bin", "decrypted.txt", key, nonce)
```

### 保密文件库管理

```python
from src.vault_manager import VaultManager

# 初始化文件库
vault = VaultManager("./my_vault")
vault.initialize("my_password")

# 导入文件
vault.import_file("secret.txt")

# 列出文件
files = vault.list_files()
print(files)

# 导出文件
vault.export_file(files[0]["id"], "exported.txt")

# 修改密码
vault.change_password("my_password", "new_password")
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
├── sm4_cipher.py        # CTR工作模式实现
├── crypto_utils.py      # 密码学工具函数
├── vault_manager.py     # 文件库管理核心
├── cli.py               # 命令行界面
tests/
├── __init__.py          # Python包初始化
├── test_sm4_core.py     # 核心算法测试
├── test_sm4_cipher.py   # CTR模式测试
├── test_crypto_utils.py # 工具函数测试
├── test_vault.py        # 文件库功能测试
├── test_cli.py          # CLI测试
└── test_performance.py  # 性能测试
```
