"""
Wiener's attack for small private exponent d.

This module implements Wiener's attack, which can recover the private key
when the private exponent d is too small (d < N^(1/4) / 3).
"""

from typing import Optional
from dataclasses import dataclass
from fractions import Fraction

from rsa_toolkit.utils.math_utils import MathUtils


@dataclass
class WienerResult:
    """Result of Wiener's attack."""
    success: bool
    d: Optional[int] = None
    p: Optional[int] = None
    q: Optional[int] = None
    iterations: int = 0
    time_elapsed: float = 0.0
    method: str = ""


class WienerAttack:
    """
    Wiener's attack using continued fractions.

    Exploits the fact that when d is small, e/φ(N) has a convergent
    equal to k/d where k is the small integer from ed ≡ 1 (mod φ(N)).
    """

    def __init__(self, max_convergents: int = 1000):
        """
        Initialize Wiener's attack.

        Args:
            max_convergents: Maximum number of convergents to check
        """
        self.max_convergents = max_convergents

    def attack(self, n: int, e: int) -> WienerResult:
        """
        Recover private key using Wiener's attack.

        Args:
            n: Modulus
            e: Public exponent

        Returns:
            WienerResult with recovered private key if successful
        """
        import time
        start_time = time.perf_counter()

        # Compute continued fraction expansion of e/N
        frac = e / n
        cf_coeffs = MathUtils.continued_fraction(frac, self.max_convergents)

        # Get convergents
        convergents = MathUtils.convergents(cf_coeffs)

        iterations = 0

        for i, conv in enumerate(convergents):
            iterations += 1

            # Convergent k/d
            k = conv.numerator
            d = conv.denominator

            # Check if this convergent gives valid p and q
            # From: ed - kφ(N) = 1
            # => φ(N) = (ed - 1) / k

            if k == 0:
                continue

            # Compute φ(N) candidate
            phi_candidate = (e * d - 1) // k

            # Check if (ed - 1) is divisible by k
            if (e * d - 1) % k != 0:
                continue

            # Solve for p and q from:
            # N = pq
            # φ(N) = (p-1)(q-1) = N - p - q + 1
            # => p + q = N - φ(N) + 1
            # => p - q = sqrt((p+q)^2 - 4N)

            sum_pq = n - phi_candidate + 1
            discriminant = sum_pq * sum_pq - 4 * n

            # Check if discriminant is a perfect square
            is_square, diff_pq = MathUtils.is_perfect_square(discriminant)

            if not is_square:
                continue

            # Compute p and q
            p = (sum_pq + diff_pq) // 2
            q = (sum_pq - diff_pq) // 2

            # Verify p and q are integers and multiply to N
            if p * q != n:
                continue

            # Verify p and q are primes
            if not (MathUtils.is_prime(p) and MathUtils.is_prime(q)):
                continue

            # Verify ed ≡ 1 (mod φ(N))
            phi = (p - 1) * (q - 1)
            if (e * d) % phi != 1:
                continue

            return WienerResult(
                success=True,
                d=d,
                p=p,
                q=q,
                iterations=iterations,
                time_elapsed=time.perf_counter() - start_time,
                method="Wiener's Attack"
            )

        return WienerResult(
            success=False,
            iterations=iterations,
            time_elapsed=time.perf_counter() - start_time,
            method="Wiener's Attack"
        )


def is_vulnerable_to_wiener(n: int, d: int) -> bool:
    """
    Check if a key is vulnerable to Wiener's attack.

    Args:
        n: Modulus
        d: Private exponent

    Returns:
        True if vulnerable (d < N^(1/4) / 3)
    """
    import gmpy2
    n_pow_quarter = gmpy2.iroot(n, 4)[0]
    return d < n_pow_quarter // 3
