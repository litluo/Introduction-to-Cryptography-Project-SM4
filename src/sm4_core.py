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
