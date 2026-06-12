import hashlib
import secrets
import os


def pbkdf2_hmac_sha256(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    """
    PBKDF2-HMAC-SHA256密钥派生

    Args:
        password: 用户密码
        salt: 盐值
        iterations: 迭代次数

    Returns:
        派生的密钥（32字节）
    """
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations,
        dklen=32
    )


def generate_salt() -> bytes:
    """生成256位随机盐值"""
    return secrets.token_bytes(32)


def generate_key() -> bytes:
    """生成128位随机密钥"""
    return secrets.token_bytes(16)


def generate_nonce() -> bytes:
    """生成64位随机nonce"""
    return secrets.token_bytes(8)


def secure_delete_file(file_path: str, passes: int = 3) -> None:
    """
    安全删除文件（多次覆写）

    Args:
        file_path: 文件路径
        passes: 覆写次数（默认3次）
    """
    file_size = os.path.getsize(file_path)

    with open(file_path, 'wb') as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(file_size))
            f.flush()
            os.fsync(f.fileno())

        # 最后一次覆写全零
        f.seek(0)
        f.write(b'\x00' * file_size)
        f.flush()
        os.fsync(f.fileno())

    os.remove(file_path)
