from .constants import SBOX


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
