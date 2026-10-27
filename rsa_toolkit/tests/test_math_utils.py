"""
Tests for mathematical utilities.
"""

import pytest
from rsa_toolkit.utils.math_utils import MathUtils


class TestMathUtils:
    """Test suite for MathUtils class."""

    def test_gcd(self):
        """Test GCD computation."""
        assert MathUtils.gcd(48, 18) == 6
        assert MathUtils.gcd(17, 5) == 1
        assert MathUtils.gcd(100, 10) == 10

    def test_extended_gcd(self):
        """Test extended Euclidean algorithm."""
        g, x, y = MathUtils.extended_gcd(48, 18)
        assert g == 6
        assert 48 * x + 18 * y == g

        g, x, y = MathUtils.extended_gcd(35, 15)
        assert g == 5
        assert 35 * x + 15 * y == g

    def test_mod_inverse(self):
        """Test modular inverse."""
        assert MathUtils.mod_inverse(3, 11) == 4  # 3*4 = 12 ≡ 1 (mod 11)
        assert MathUtils.mod_inverse(7, 26) == 15  # 7*15 = 105 ≡ 1 (mod 26)
        assert MathUtils.mod_inverse(2, 4) is None  # No inverse exists

    def test_is_prime(self):
        """Test primality testing."""
        assert MathUtils.is_prime(2) is True
        assert MathUtils.is_prime(3) is True
        assert MathUtils.is_prime(17) is True
        assert MathUtils.is_prime(97) is True
        assert MathUtils.is_prime(100) is False
        assert MathUtils.is_prime(1) is False
        assert MathUtils.is_prime(0) is False

    def test_is_perfect_square(self):
        """Test perfect square detection."""
        assert MathUtils.is_perfect_square(16) == (True, 4)
        assert MathUtils.is_perfect_square(25) == (True, 5)
        assert MathUtils.is_perfect_square(26) == (False, None)
        assert MathUtils.is_perfect_square(-1) == (False, None)

    def test_integer_nth_root(self):
        """Test integer n-th root."""
        root, exact = MathUtils.integer_nth_root(27, 3)
        assert root == 3 and exact is True

        root, exact = MathUtils.integer_nth_root(26, 3)
        assert root == 2 and exact is False

        root, exact = MathUtils.integer_nth_root(16, 4)
        assert root == 2 and exact is True

    def test_chinese_remainder_theorem(self):
        """Test Chinese Remainder Theorem."""
        # x ≡ 2 (mod 3), x ≡ 3 (mod 5), x ≡ 2 (mod 7)
        # Solution: x = 23
        result = MathUtils.chinese_remainder_theorem([(2, 3), (3, 5), (2, 7)])
        assert result == 23

        # x ≡ 1 (mod 2), x ≡ 2 (mod 3)
        # Solution: x = 5
        result = MathUtils.chinese_remainder_theorem([(1, 2), (2, 3)])
        assert result == 5

    def test_continued_fraction(self):
        """Test continued fraction expansion."""
        # sqrt(2) = [1; 2, 2, 2, ...]
        coeffs = MathUtils.continued_fraction(2**0.5, 10)
        assert coeffs[0] == 1
        assert all(c == 2 for c in coeffs[1:])

    def test_convergents(self):
        """Test convergent computation."""
        # For golden ratio (1+sqrt(5))/2 = [1; 1, 1, 1, ...]
        coeffs = [1, 1, 1, 1, 1]
        convergents = MathUtils.convergents(coeffs)
        assert len(convergents) == 5
        assert convergents[0] == 1  # 1/1
        assert convergents[1] == 2  # 2/1
        assert convergents[2] == 3/2  # 3/2

    def test_lcm(self):
        """Test least common multiple."""
        assert MathUtils.lcm(4, 6) == 12
        assert MathUtils.lcm(5, 7) == 35
        assert MathUtils.lcm(12, 18) == 36

    def test_euler_totient(self):
        """Test Euler's totient function."""
        assert MathUtils.euler_totient(1) == 1
        assert MathUtils.euler_totient(7) == 6  # 7 is prime
        assert MathUtils.euler_totient(12) == 4  # φ(12) = 4
        assert MathUtils.euler_totient(13) == 12  # 13 is prime

    def test_carmichael_function(self):
        """Test Carmichael function."""
        assert MathUtils.carmichael_function(1) == 1
        assert MathUtils.carmichael_function(7) == 6  # Prime
        assert MathUtils.carmichael_function(8) == 2  # 2^3
