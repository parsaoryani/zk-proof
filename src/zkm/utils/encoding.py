"""Encoding and decoding utilities."""

from typing import Union


def bytes_to_hex(data: bytes) -> str:
    """
    Convert bytes to hexadecimal string.
    
    Args:
        data: Bytes to convert
        
    Returns:
        str: Hexadecimal string with '0x' prefix
    """
    return "0x" + data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """
    Convert hexadecimal string to bytes.
    
    Args:
        hex_str: Hexadecimal string (with or without '0x' prefix)
        
    Returns:
        bytes: Decoded bytes
        
    Raises:
        ValueError: If hex string is invalid
    """
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    
    if len(hex_str) % 2 != 0:
        raise ValueError("Hex string must have even number of characters")
    
    return bytes.fromhex(hex_str)


def ensure_bytes(data: Union[bytes, str]) -> bytes:
    """
    Ensure data is in bytes format.
    
    Args:
        data: Bytes or string
        
    Returns:
        bytes: Data as bytes
    """
    if isinstance(data, bytes):
        return data
    elif isinstance(data, str):
        return data.encode('utf-8')
    else:
        raise TypeError(f"Expected bytes or str, got {type(data)}")


def ensure_hex_string(data: Union[bytes, str]) -> str:
    """
    Ensure data is in hexadecimal string format.
    
    Args:
        data: Bytes or string
        
    Returns:
        str: Hex string with '0x' prefix
    """
    if isinstance(data, bytes):
        return bytes_to_hex(data)
    elif isinstance(data, str):
        return data if data.startswith("0x") else "0x" + data
    else:
        raise TypeError(f"Expected bytes or str, got {type(data)}")
