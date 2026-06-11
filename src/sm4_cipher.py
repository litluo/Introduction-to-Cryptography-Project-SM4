import os
from .sm4_core import key_expansion, encrypt_block


def generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """
    生成CTR模式密钥流

    Args:
        key: 16字节密钥
        nonce: 8字节nonce
        length: 需要的密钥流长度（字节）

    Returns:
        密钥流字节序列

    Raises:
        ValueError: 密钥或nonce长度不正确
    """
    if len(key) != 16:
        raise ValueError("密钥长度必须为16字节")
    if len(nonce) != 8:
        raise ValueError("nonce长度必须为8字节")

    rk = key_expansion(key)

    keystream = b''
    counter = 0

    while len(keystream) < length:
        counter_block = nonce + counter.to_bytes(8, byteorder='big')
        encrypted_block = encrypt_block(counter_block, rk=rk)
        keystream += encrypted_block
        counter += 1

    return keystream[:length]


def ctr_encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """
    CTR模式加密

    Args:
        key: 16字节密钥
        nonce: 8字节nonce
        data: 待加密数据

    Returns:
        密文
    """
    if not data:
        return b''

    keystream = generate_keystream(key, nonce, len(data))

    ciphertext = bytes(a ^ b for a, b in zip(data, keystream))

    return ciphertext


def ctr_decrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """
    CTR模式解密（与加密完全相同）

    Args:
        key: 16字节密钥
        nonce: 8字节nonce
        data: 密文

    Returns:
        明文
    """
    return ctr_encrypt(key, nonce, data)


def encrypt_file(input_path: str, output_path: str, key: bytes, nonce: bytes, chunk_size: int = 1024*1024) -> None:
    """
    加密文件
    
    Args:
        input_path: 输入文件路径
        output_path: 输出文件路径
        key: 16字节密钥
        nonce: 8字节nonce
        chunk_size: 分块大小（默认1MB）
    """
    if len(key) != 16:
        raise ValueError("密钥长度必须为16字节")
    if len(nonce) != 8:
        raise ValueError("nonce长度必须为8字节")
    
    rk = key_expansion(key)
    
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        while True:
            chunk = f_in.read(chunk_size)
            if not chunk:
                break
            
            keystream = generate_keystream(key, nonce, len(chunk))
            
            encrypted_chunk = bytes(a ^ b for a, b in zip(chunk, keystream))
            
            f_out.write(encrypted_chunk)


def decrypt_file(input_path: str, output_path: str, key: bytes, nonce: bytes, chunk_size: int = 1024*1024) -> None:
    """
    解密文件（与加密完全相同）
    
    Args:
        input_path: 输入文件路径
        output_path: 输出文件路径
        key: 16字节密钥
        nonce: 8字节nonce
        chunk_size: 分块大小（默认1MB）
    """
    encrypt_file(input_path, output_path, key, nonce, chunk_size)
