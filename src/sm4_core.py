from .constants import SBOX, FK, CK


def sbox_transform(data: int) -> int:
    """
    S盒变换（非线性变换τ）
    
    Args:
        data: 8位整数 (0-255)
    
    Returns:
        经过S盒变换后的8位整数
    """
    return SBOX[data & 0xff]


def circular_left_shift(data: int, shift: int, bits: int = 32) -> int:
    """
    循环左移
    
    Args:
        data: 要移位的数据
        shift: 左移位数
        bits: 数据位数（默认32位）
    
    Returns:
        循环左移后的结果
    """
    shift = shift % bits
    return ((data << shift) | (data >> (bits - shift))) & ((1 << bits) - 1)


def l_transform(data: int) -> int:
    """
    线性变换L
    
    L(B) = B ⊕ (B<<<2) ⊕ (B<<<10) ⊕ (B<<<18) ⊕ (B<<<24)
    
    Args:
        data: 32位整数
    
    Returns:
        经过线性变换L后的32位整数
    """
    return (data ^ 
            circular_left_shift(data, 2) ^ 
            circular_left_shift(data, 10) ^ 
            circular_left_shift(data, 18) ^ 
            circular_left_shift(data, 24))


def l_prime_transform(data: int) -> int:
    """
    密钥扩展中的线性变换L'
    
    L'(B) = B ⊕ (B<<<13) ⊕ (B<<<23)
    
    Args:
        data: 32位整数
    
    Returns:
        经过线性变换L'后的32位整数
    """
    return (data ^ 
            circular_left_shift(data, 13) ^ 
            circular_left_shift(data, 23))


def t_transform(data: int) -> int:
    """
    复合变换T = L ∘ τ
    
    先进行S盒变换（τ），再进行线性变换L
    
    Args:
        data: 32位整数
    
    Returns:
        经过复合变换T后的32位整数
    """
    b0 = (data >> 24) & 0xff
    b1 = (data >> 16) & 0xff
    b2 = (data >> 8) & 0xff
    b3 = data & 0xff

    b0 = sbox_transform(b0)
    b1 = sbox_transform(b1)
    b2 = sbox_transform(b2)
    b3 = sbox_transform(b3)

    transformed = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3

    return l_transform(transformed)


def t_prime_transform(data: int) -> int:
    """
    密钥扩展中的复合变换T' = L' ∘ τ
    
    先进行S盒变换（τ），再进行线性变换L'
    
    Args:
        data: 32位整数
    
    Returns:
        经过复合变换T'后的32位整数
    """
    b0 = (data >> 24) & 0xff
    b1 = (data >> 16) & 0xff
    b2 = (data >> 8) & 0xff
    b3 = data & 0xff

    b0 = sbox_transform(b0)
    b1 = sbox_transform(b1)
    b2 = sbox_transform(b2)
    b3 = sbox_transform(b3)

    transformed = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3

    return l_prime_transform(transformed)


def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, byteorder='big')


def int_to_bytes(data: int, length: int = 4) -> bytes:
    return data.to_bytes(length, byteorder='big')


def key_expansion(key: bytes) -> list:
    if len(key) != 16:
        raise ValueError("密钥长度必须为16字节")

    MK = [
        bytes_to_int(key[0:4]),
        bytes_to_int(key[4:8]),
        bytes_to_int(key[8:12]),
        bytes_to_int(key[12:16])
    ]

    K = [
        MK[0] ^ FK[0],
        MK[1] ^ FK[1],
        MK[2] ^ FK[2],
        MK[3] ^ FK[3]
    ]

    rk = []
    for i in range(32):
        rk.append(K[i] ^ t_prime_transform(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]))
        K.append(rk[-1])

    return rk


def round_function(x0: int, x1: int, x2: int, x3: int, rk: int) -> int:
    """
    轮函数F

    F(X0,X1,X2,X3,rk) = X0 ⊕ T(X1⊕X2⊕X3⊕rk)

    Args:
        x0, x1, x2, x3: 4个32位整数
        rk: 轮密钥

    Returns:
        轮函数输出
    """
    return x0 ^ t_transform(x1 ^ x2 ^ x3 ^ rk)


def encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    """
    加密单个16字节分组

    Args:
        plaintext: 16字节明文
        key: 16字节密钥

    Returns:
        16字节密文

    Raises:
        ValueError: 明文或密钥长度不是16字节
    """
    if len(plaintext) != 16:
        raise ValueError("明文长度必须为16字节")
    if len(key) != 16:
        raise ValueError("密钥长度必须为16字节")

    rk = key_expansion(key)

    X = [
        bytes_to_int(plaintext[0:4]),
        bytes_to_int(plaintext[4:8]),
        bytes_to_int(plaintext[8:12]),
        bytes_to_int(plaintext[12:16])
    ]

    for i in range(32):
        X.append(round_function(X[i], X[i+1], X[i+2], X[i+3], rk[i]))

    Y = [X[35], X[34], X[33], X[32]]

    ciphertext = b''
    for y in Y:
        ciphertext += int_to_bytes(y)

    return ciphertext


def decrypt_block(ciphertext: bytes, key: bytes) -> bytes:
    """
    解密单个16字节分组

    Args:
        ciphertext: 16字节密文
        key: 16字节密钥

    Returns:
        16字节明文

    Raises:
        ValueError: 密文或密钥长度不是16字节
    """
    if len(ciphertext) != 16:
        raise ValueError("密文长度必须为16字节")
    if len(key) != 16:
        raise ValueError("密钥长度必须为16字节")

    rk = key_expansion(key)
    rk.reverse()

    X = [
        bytes_to_int(ciphertext[0:4]),
        bytes_to_int(ciphertext[4:8]),
        bytes_to_int(ciphertext[8:12]),
        bytes_to_int(ciphertext[12:16])
    ]

    for i in range(32):
        X.append(round_function(X[i], X[i+1], X[i+2], X[i+3], rk[i]))

    Y = [X[35], X[34], X[33], X[32]]

    plaintext = b''
    for y in Y:
        plaintext += int_to_bytes(y)

    return plaintext
