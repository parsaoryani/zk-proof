"""Extended tests for encoding utilities to improve coverage."""

import pytest
from zkm.utils.encoding import bytes_to_hex, hex_to_bytes, ensure_bytes, ensure_hex_string


class TestBytesToHex:
    """Test bytes_to_hex function."""

    def test_bytes_to_hex_basic(self):
        """Test basic bytes to hex conversion."""
        data = b"hello"
        result = bytes_to_hex(data)
        assert result == "0x68656c6c6f"

    def test_bytes_to_hex_empty(self):
        """Test empty bytes."""
        result = bytes_to_hex(b"")
        assert result == "0x"

    def test_bytes_to_hex_binary_data(self):
        """Test binary data conversion."""
        data = bytes([0, 1, 2, 255, 254, 253])
        result = bytes_to_hex(data)
        assert result == "0x000102fffefd"

    def test_bytes_to_hex_unicode_representation(self):
        """Test with various byte values."""
        data = bytes(range(256))[:16]
        result = bytes_to_hex(data)
        assert result.startswith("0x")
        assert len(result) == 2 + 32  # 0x + 16 bytes * 2 hex chars


class TestHexToBytes:
    """Test hex_to_bytes function."""

    def test_hex_to_bytes_with_prefix(self):
        """Test hex conversion with 0x prefix."""
        hex_str = "0x68656c6c6f"
        result = hex_to_bytes(hex_str)
        assert result == b"hello"

    def test_hex_to_bytes_without_prefix(self):
        """Test hex conversion without 0x prefix."""
        hex_str = "68656c6c6f"
        result = hex_to_bytes(hex_str)
        assert result == b"hello"

    def test_hex_to_bytes_empty(self):
        """Test empty hex string."""
        result = hex_to_bytes("0x")
        assert result == b""

    def test_hex_to_bytes_binary(self):
        """Test binary hex data."""
        hex_str = "0x000102fffefd"
        result = hex_to_bytes(hex_str)
        assert result == bytes([0, 1, 2, 255, 254, 253])

    def test_hex_to_bytes_odd_length_error(self):
        """Test that odd-length hex string raises error."""
        with pytest.raises(ValueError, match="even number of characters"):
            hex_to_bytes("0x6a8")

    def test_hex_to_bytes_invalid_chars(self):
        """Test that invalid hex characters raise error."""
        with pytest.raises(ValueError):
            hex_to_bytes("0xGGGG")

    def test_hex_to_bytes_case_insensitive(self):
        """Test case-insensitive hex."""
        result1 = hex_to_bytes("0xABCD")
        result2 = hex_to_bytes("0xabcd")
        assert result1 == result2 == b"\xab\xcd"


class TestEnsureBytes:
    """Test ensure_bytes function."""

    def test_ensure_bytes_from_bytes(self):
        """Test with bytes input."""
        data = b"test"
        result = ensure_bytes(data)
        assert result == b"test"
        assert result is data  # Should be same object

    def test_ensure_bytes_from_string(self):
        """Test with string input."""
        data = "test"
        result = ensure_bytes(data)
        assert result == b"test"

    def test_ensure_bytes_from_unicode_string(self):
        """Test with unicode string."""
        data = "héllo"
        result = ensure_bytes(data)
        assert result == b"h\xc3\xa9llo"

    def test_ensure_bytes_empty_string(self):
        """Test with empty string."""
        result = ensure_bytes("")
        assert result == b""

    def test_ensure_bytes_empty_bytes(self):
        """Test with empty bytes."""
        result = ensure_bytes(b"")
        assert result == b""

    def test_ensure_bytes_invalid_type(self):
        """Test with invalid type raises TypeError."""
        with pytest.raises(TypeError, match="Expected bytes or str"):
            ensure_bytes(123)

    def test_ensure_bytes_invalid_type_list(self):
        """Test with list type."""
        with pytest.raises(TypeError, match="Expected bytes or str"):
            ensure_bytes([1, 2, 3])

    def test_ensure_bytes_invalid_type_none(self):
        """Test with None."""
        with pytest.raises(TypeError, match="Expected bytes or str"):
            ensure_bytes(None)


class TestEnsureHexString:
    """Test ensure_hex_string function."""

    def test_ensure_hex_string_from_bytes(self):
        """Test with bytes input."""
        data = b"test"
        result = ensure_hex_string(data)
        assert result.startswith("0x")
        assert hex_to_bytes(result) == data

    def test_ensure_hex_string_from_hex_string_with_prefix(self):
        """Test with hex string that has prefix."""
        data = "0x12345678"
        result = ensure_hex_string(data)
        assert result == "0x12345678"

    def test_ensure_hex_string_from_hex_string_without_prefix(self):
        """Test with hex string without prefix."""
        data = "12345678"
        result = ensure_hex_string(data)
        assert result == "0x12345678"

    def test_ensure_hex_string_from_empty_bytes(self):
        """Test with empty bytes."""
        result = ensure_hex_string(b"")
        assert result == "0x"

    def test_ensure_hex_string_from_empty_string(self):
        """Test with empty string."""
        result = ensure_hex_string("")
        assert result == "0x"

    def test_ensure_hex_string_invalid_type(self):
        """Test with invalid type raises TypeError."""
        with pytest.raises(TypeError, match="Expected bytes or str"):
            ensure_hex_string(123)

    def test_ensure_hex_string_invalid_type_list(self):
        """Test with list."""
        with pytest.raises(TypeError, match="Expected bytes or str"):
            ensure_hex_string([1, 2, 3])


class TestRoundTrips:
    """Test round-trip conversions."""

    def test_bytes_hex_bytes_roundtrip(self):
        """Test bytes -> hex -> bytes."""
        original = b"test data"
        hex_form = bytes_to_hex(original)
        recovered = hex_to_bytes(hex_form)
        assert recovered == original

    def test_various_byte_values_roundtrip(self):
        """Test with various byte values."""
        for i in range(0, 256, 16):
            original = bytes([i, i + 1, i + 2])
            hex_form = bytes_to_hex(original)
            recovered = hex_to_bytes(hex_form)
            assert recovered == original

    def test_large_data_roundtrip(self):
        """Test with large data."""
        original = b"x" * 10000
        hex_form = bytes_to_hex(original)
        recovered = hex_to_bytes(hex_form)
        assert recovered == original

    def test_ensure_bytes_hex_roundtrip(self):
        """Test ensure_bytes -> ensure_hex_string roundtrip."""
        original_str = "hello world"
        as_bytes = ensure_bytes(original_str)
        as_hex = ensure_hex_string(as_bytes)
        recovered_bytes = hex_to_bytes(as_hex)
        assert recovered_bytes == b"hello world"
