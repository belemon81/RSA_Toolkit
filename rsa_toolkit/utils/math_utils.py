"""
Mathematical utilities for RSA attacks.

This module provides core mathematical functions used in various RSA attack scenarios.
"""

import math
from typing import Tuple, Optional, List, Union
from fractions import Fraction
import gmpy2


class MathUtils:
    """Utility class for mathematical operations in RSA attacks."""

    @staticmethod
    def gcd(a: int, b: int) -> int:
        """
        Compute the greatest common divisor of two integers.

        Args:
            a: First integer
            b: Second integer

        Returns:
            GCD of a and b
        """
        return math.gcd(a, b)

    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """
        Extended Euclidean algorithm.

        Args:
            a: First integer
            b: Second integer

        Returns:
            Tuple (g, x, y) where g = gcd(a, b) and ax + by = g
        """
        # Iterative form: the recursive version can exceed Python's
        # recursion limit (~1000 frames) for operands of a few hundred
        # bits, since the Euclidean algorithm needs ~1.44 * bit_length
        # division steps.
        old_r, r = a, b
        old_s, s = 1, 0
        old_t, t = 0, 1

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t

        return old_r, old_s, old_t

    @staticmethod
    def mod_inverse(a: int, m: int) -> Optional[int]:
        """
        Compute modular inverse of a modulo m.

        Args:
            a: Integer to find inverse for
            m: Modulus

        Returns:
            Modular inverse if it exists, None otherwise
        """
        g, x, _ = MathUtils.extended_gcd(a, m)
        if g != 1:
            return None
        return x % m

    @staticmethod
    def is_prime(n: int) -> bool:
        """
        Check if a number is prime using Miller-Rabin test.

        Args:
            n: Number to check

        Returns:
            True if n is prime, False otherwise
        """
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False

        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # Miller-Rabin test with multiple bases
        for a in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
            if a >= n:
                continue
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False

        return True

    @staticmethod
    def is_perfect_square(n: int) -> Tuple[bool, Optional[int]]:
        """
        Check if n is a perfect square.

        Args:
            n: Number to check

        Returns:
            Tuple (is_square, sqrt) where sqrt is the square root if is_square is True
        """
        if n < 0:
            return False, None

        sqrt_n = int(math.isqrt(n))
        if sqrt_n * sqrt_n == n:
            return True, sqrt_n
        return False, None

    @staticmethod
    def integer_nth_root(n: int, k: int) -> Tuple[int, bool]:
        """
        Compute the integer k-th root of n.

        Args:
            n: Number to find root of
            k: Root degree

        Returns:
            Tuple (root, is_exact) where is_exact is True if root^k == n
        """
        if k < 1:
            raise ValueError(f"k must be >= 1, got {k}")

        if n < 0 and k % 2 == 0:
            return 0, False

        # Use gmpy2.iroot for accurate calculation
        try:
            root, exact = gmpy2.iroot(n, k)
            return int(root), bool(exact)
        except Exception:
            # Fallback to binary search for very large numbers
            if n == 0:
                return 0, True
            if n == 1:
                return 1, True

            # Binary search
            low, high = 0, 1
            while pow(high, k) <= n:
                high *= 2

            while low < high:
                mid = (low + high + 1) // 2
                if pow(mid, k) <= n:
                    low = mid
                else:
                    high = mid - 1

            root = low
            is_exact = pow(root, k) == n
            return root, is_exact

    @staticmethod
    def chinese_remainder_theorem(congruences: List[Tuple[int, int]]) -> Optional[int]:
        """
        Solve system of congruences using Chinese Remainder Theorem.

        Args:
            congruences: List of (remainder, modulus) tuples

        Returns:
            Solution x satisfying all congruences, or None if no solution exists
        """
        if not congruences:
            return None

        result, mod_product = congruences[0]

        for remainder, modulus in congruences[1:]:
            # Solve: result + mod_product * k ≡ remainder (mod modulus)
            # => mod_product * k ≡ remainder - result (mod modulus)
            diff = remainder - result
            g = MathUtils.gcd(mod_product, modulus)

            if diff % g != 0:
                return None  # No solution

            # Simplify
            mod_product_simplified = mod_product // g
            modulus_simplified = modulus // g
            diff_simplified = diff // g

            # Find k using modular inverse
            k = MathUtils.mod_inverse(mod_product_simplified, modulus_simplified)
            if k is None:
                return None

            k = (k * diff_simplified) % modulus_simplified

            result = result + mod_product * k
            mod_product = mod_product * modulus_simplified

        return result % mod_product

    @staticmethod
    def continued_fraction(x: Union[float, Fraction], max_iterations: int = 1000) -> List[int]:
        """
        Compute continued fraction expansion of x.

        Args:
            x: Number to expand
            max_iterations: Maximum number of iterations

        Returns:
            List of continued fraction coefficients
        """
        result = []
        for _ in range(max_iterations):
            a = int(math.floor(x))
            result.append(a)
            x = x - a
            # Exact termination for rational input (e.g. Fraction); the
            # epsilon check is only a safeguard for inexact float input.
            if x == 0 or (isinstance(x, float) and abs(x) < 1e-10):
                break
            x = 1 / x
        return result

    @staticmethod
    def convergents(fraction_coeffs: List[int]) -> List[Fraction]:
        """
        Compute convergents from continued fraction coefficients.

        Args:
            fraction_coeffs: List of continued fraction coefficients

        Returns:
            List of convergent fractions
        """
        convergents = []
        for i in range(len(fraction_coeffs)):
            convergents.append(MathUtils._convergent_at(fraction_coeffs, i))
        return convergents

    @staticmethod
    def _convergent_at(coeffs: List[int], index: int) -> Fraction:
        """
        Compute convergent at specific index.

        Args:
            coeffs: Continued fraction coefficients
            index: Index of convergent to compute

        Returns:
            Convergent as Fraction
        """
        if index == 0:
            return Fraction(coeffs[0], 1)
        if index == 1:
            return Fraction(coeffs[0] * coeffs[1] + 1, coeffs[1])

        # Recursively compute using the recurrence relation
        h_prev2, h_prev1 = coeffs[0], coeffs[0] * coeffs[1] + 1
        k_prev2, k_prev1 = 1, coeffs[1]

        for i in range(2, index + 1):
            h = coeffs[i] * h_prev1 + h_prev2
            k = coeffs[i] * k_prev1 + k_prev2
            h_prev2, h_prev1 = h_prev1, h
            k_prev2, k_prev1 = k_prev1, k

        return Fraction(h_prev1, k_prev1)

    @staticmethod
    def lcm(a: int, b: int) -> int:
        """
        Compute least common multiple of two integers.

        Args:
            a: First integer
            b: Second integer

        Returns:
            LCM of a and b
        """
        if a == 0 or b == 0:
            return 0
        return abs(a * b) // MathUtils.gcd(a, b)
