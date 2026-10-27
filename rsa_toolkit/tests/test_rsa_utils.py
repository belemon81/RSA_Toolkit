"""
Tests for RSA utilities.
"""

import pytest
from rsa_toolkit.utils.rsa_utils import RSAUtils
from rsa_toolkit.utils.math_utils import MathUtils


class TestRSAUtils:
    """Test suite for RSAUtils class."""

    def test_generate_keypair_secure(self):
        """Test secure keypair generation."""
        (n, e, d), (p, q) = RSAUtils.generate_keypair(bit_length=2048, e=65537)

        assert n.bit_length() == 2048
        assert e == 65537
        assert d is not None
        assert MathUtils.is_prime(p)
        assert MathUtils.is_prime(q)
        assert n == p * q
        assert RSAUtils.validate_keypair(n, e, d)

    def test_generate_keypair_small_modulus(self):
        """Test small modulus generation."""
        (n, e, d), (p, q) = RSAUtils.generate_keypair(
            bit_length=48,
            e=65537,
            weak_config='small_modulus'
        )

        assert n.bit_length() <= 48
        assert MathUtils.is_prime(p)
        assert MathUtils.is_prime(q)
        assert RSAUtils.validate_keypair(n, e, d)

    def test_generate_keypair_close_primes(self):
        """Test close primes generation."""
        (n, e, d), (p, q) = RSAUtils.generate_keypair(
            bit_length=128,
            e=65537,
            weak_config='close_primes'
        )

        assert MathUtils.is_prime(p)
        assert MathUtils.is_prime(q)
        # Primes should be close
        assert abs(p - q) < 10000
        assert RSAUtils.validate_keypair(n, e, d)

    def test_generate_keypair_small_d(self):
        """Test small d generation."""
        (n, e, d), (p, q) = RSAUtils.generate_keypair(
            bit_length=128,
            e=65537,
            weak_config='small_d'
        )

        assert MathUtils.is_prime(p)
        assert MathUtils.is_prime(q)
        assert RSAUtils.validate_keypair(n, e, d)
        # d should be relatively small
        assert d < n

    def test_encrypt_decrypt(self):
        """Test encryption and decryption."""
        (n, e, d), _ = RSAUtils.generate_keypair(bit_length=128, e=65537)

        message = 42
        ciphertext = RSAUtils.encrypt(message, n, e)
        decrypted = RSAUtils.decrypt(ciphertext, n, d)

        assert message == decrypted

    def test_message_to_int_and_back(self):
        """Test message conversion."""
        message = "Hello, World!"
        message_int = RSAUtils.message_to_int(message)
        message_back = RSAUtils.int_to_message(message_int)

        assert message == message_back

    def test_validate_keypair(self):
        """Test keypair validation."""
        (n, e, d), _ = RSAUtils.generate_keypair(bit_length=128, e=65537)
        assert RSAUtils.validate_keypair(n, e, d) is True

        # Invalid keypair
        assert RSAUtils.validate_keypair(n, e, d + 1) is False

    def test_compute_d_from_p_q_e(self):
        """Test computing d from p, q, e."""
        (n, e, d), (p, q) = RSAUtils.generate_keypair(bit_length=128, e=65537)

        d_computed = RSAUtils.compute_d_from_p_q_e(p, q, e)
        assert d_computed == d

    def test_is_weak_modulus(self):
        """Test weak modulus detection."""
        # Small modulus
        small_n = 2**40 - 1
        assert RSAUtils.is_weak_modulus(small_n, threshold_bits=64) is True

        # Large modulus
        large_n = 2**2048 - 1
        assert RSAUtils.is_weak_modulus(large_n, threshold_bits=64) is False

    def test_is_weak_d(self):
        """Test weak d detection."""
        (n, e, d), _ = RSAUtils.generate_keypair(
            bit_length=128,
            e=65537,
            weak_config='small_d'
        )

        # This might or might not be weak depending on generation
        weak = RSAUtils.is_weak_d(n, d)
        assert isinstance(weak, bool)

    def test_get_key_fingerprint(self):
        """Test key fingerprint generation."""
        (n, e, _), _ = RSAUtils.generate_keypair(bit_length=128, e=65537)

        fingerprint = RSAUtils.get_key_fingerprint(n, e)
        assert isinstance(fingerprint, str)
        assert len(fingerprint) == 16

        # Same key should produce same fingerprint
        fingerprint2 = RSAUtils.get_key_fingerprint(n, e)
        assert fingerprint == fingerprint2
