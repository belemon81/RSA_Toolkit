"""
Factorization attacks on RSA modulus.

This module implements various factorization methods to break RSA when
the modulus N is small or has special properties.
"""

import math
import random
from typing import Optional, Tuple
from dataclasses import dataclass

from rsa_toolkit.utils.math_utils import MathUtils


@dataclass
class FactorizationResult:
    """Result of factorization attack."""
    success: bool
    p: Optional[int] = None
    q: Optional[int] = None
    iterations: int = 0
    time_elapsed: float = 0.0
    method: str = ""


class BruteForceFactorization:
    """
    Brute force factorization for small modulus.

    Suitable for N < 64 bits. Uses trial division with wheel factorization
    to skip multiples of 2, 3, and 5.
    """

    def __init__(self, max_iterations: int = 1000000):
        """
        Initialize brute force factorization.

        Args:
            max_iterations: Maximum number of iterations to attempt
        """
        self.max_iterations = max_iterations

    def factorize(self, n: int) -> FactorizationResult:
        """
        Factorize N using brute force trial division.

        Args:
            n: Modulus to factorize

        Returns:
            FactorizationResult with factors p and q if successful
        """
        import time
        start_time = time.perf_counter()

        # Check if n is even
        if n % 2 == 0:
            p = 2
            q = n // 2
            return FactorizationResult(
                success=True,
                p=p,
                q=q,
                iterations=1,
                time_elapsed=time.perf_counter() - start_time,
                method="Brute Force (even)"
            )

        # Trial division with wheel factorization (skip multiples of 2, 3, 5)
        # Residues coprime to 30: 1, 7, 11, 13, 17, 19, 23, 29 (mod 30)
        # wheel_deltas are the GAPS between consecutive residues, starting
        # from residue 7: 7->11->13->17->19->23->29->31(=1)->37(=7)...
        wheel_deltas = [4, 2, 4, 2, 4, 6, 2, 6]
        iterations = 0

        # Check divisibility by 3 and 5 first
        if n % 3 == 0:
            p = 3
            q = n // 3
            return FactorizationResult(
                success=True,
                p=p,
                q=q,
                iterations=1,
                time_elapsed=time.perf_counter() - start_time,
                method="Brute Force (divisible by 3)"
            )

        if n % 5 == 0:
            p = 5
            q = n // 5
            return FactorizationResult(
                success=True,
                p=p,
                q=q,
                iterations=1,
                time_elapsed=time.perf_counter() - start_time,
                method="Brute Force (divisible by 5)"
            )

        # Trial division
        limit = int(math.isqrt(n)) + 1
        divisor = 7
        wheel_index = 0

        while divisor <= limit and iterations < self.max_iterations:
            iterations += 1

            if n % divisor == 0:
                p = divisor
                q = n // divisor
                return FactorizationResult(
                    success=True,
                    p=p,
                    q=q,
                    iterations=iterations,
                    time_elapsed=time.perf_counter() - start_time,
                    method="Brute Force"
                )

            # Next divisor using wheel deltas
            divisor += wheel_deltas[wheel_index]
            wheel_index = (wheel_index + 1) % 8

        return FactorizationResult(
            success=False,
            iterations=iterations,
            time_elapsed=time.perf_counter() - start_time,
            method="Brute Force"
        )


class FermatFactorization:
    """
    Fermat's factorization method.

    Effective when p and q are very close together.
    Uses the identity: N = a^2 - b^2 = (a-b)(a+b)
    """

    def __init__(self, max_iterations: int = 100000):
        """
        Initialize Fermat factorization.

        Args:
            max_iterations: Maximum number of iterations to attempt
        """
        self.max_iterations = max_iterations

    def factorize(self, n: int) -> FactorizationResult:
        """
        Factorize N using Fermat's method.

        Args:
            n: Modulus to factorize

        Returns:
            FactorizationResult with factors p and q if successful
        """
        import time
        start_time = time.perf_counter()

        if n % 2 == 0:
            return FactorizationResult(
                success=False,
                method="Fermat (N is even)"
            )

        a = math.isqrt(n)
        iterations = 0

        while iterations < self.max_iterations:
            iterations += 1
            b_squared = a * a - n

            # Check if b_squared is a perfect square
            is_square, b = MathUtils.is_perfect_square(b_squared)

            if is_square:
                p = a - b
                q = a + b
                return FactorizationResult(
                    success=True,
                    p=p,
                    q=q,
                    iterations=iterations,
                    time_elapsed=time.perf_counter() - start_time,
                    method="Fermat"
                )

            a += 1

        return FactorizationResult(
            success=False,
            iterations=iterations,
            time_elapsed=time.perf_counter() - start_time,
            method="Fermat"
        )


class PollardsRho:
    """
    Pollard's rho algorithm for factorization.

    Effective when N has a small prime factor.
    Uses Floyd's cycle detection and the function f(x) = x^2 + c (mod N).
    """

    def __init__(self, max_iterations: int = 10000):
        """
        Initialize Pollard's rho.

        Args:
            max_iterations: Maximum number of iterations to attempt
        """
        self.max_iterations = max_iterations

    def factorize(self, n: int) -> FactorizationResult:
        """
        Factorize N using Pollard's rho algorithm.

        Args:
            n: Modulus to factorize

        Returns:
            FactorizationResult with factors p and q if successful
        """
        import time
        start_time = time.perf_counter()

        if n % 2 == 0:
            p = 2
            q = n // 2
            return FactorizationResult(
                success=True,
                p=p,
                q=q,
                iterations=1,
                time_elapsed=time.perf_counter() - start_time,
                method="Pollard's Rho (even)"
            )

        # Check if n is prime
        if MathUtils.is_prime(n):
            return FactorizationResult(
                success=False,
                method="Pollard's Rho (N is prime)"
            )

        iterations = 0

        for _ in range(10):  # Try with different random starting points
            x = random.randint(2, n - 1)
            y = x
            c = random.randint(1, n - 1)
            d = 1

            while d == 1 and iterations < self.max_iterations:
                iterations += 1

                # Tortoise: x = f(x)
                x = (x * x + c) % n

                # Hare: y = f(f(y))
                y = (y * y + c) % n
                y = (y * y + c) % n

                d = MathUtils.gcd(abs(x - y), n)

                if d == n:
                    # Failed with this c, try again
                    break

            if d > 1 and d < n:
                p = d
                q = n // d
                return FactorizationResult(
                    success=True,
                    p=p,
                    q=q,
                    iterations=iterations,
                    time_elapsed=time.perf_counter() - start_time,
                    method="Pollard's Rho"
                )

        return FactorizationResult(
            success=False,
            iterations=iterations,
            time_elapsed=time.perf_counter() - start_time,
            method="Pollard's Rho"
        )


class PollardsP1:
    """
    Pollard's p-1 algorithm for factorization.

    Effective when p-1 has only small prime factors (B-smooth).
    Uses the fact that if p-1 is B-smooth, then a^(p-1) ≡ 1 (mod p).
    """

    def __init__(self, max_iterations: int = 10000, B: int = 100):
        """
        Initialize Pollard's p-1.

        Args:
            max_iterations: Maximum number of iterations to attempt
            B: Smoothness bound (search for factors where p-1 is B-smooth)
        """
        self.max_iterations = max_iterations
        self.B = B

    def factorize(self, n: int) -> FactorizationResult:
        """
        Factorize N using Pollard's p-1 algorithm.

        Args:
            n: Modulus to factorize

        Returns:
            FactorizationResult with factors p and q if successful
        """
        import time
        start_time = time.perf_counter()

        if n % 2 == 0:
            p = 2
            q = n // 2
            return FactorizationResult(
                success=True,
                p=p,
                q=q,
                iterations=1,
                time_elapsed=time.perf_counter() - start_time,
                method="Pollard's p-1 (even)"
            )

        # Check if n is prime
        if MathUtils.is_prime(n):
            return FactorizationResult(
                success=False,
                method="Pollard's p-1 (N is prime)"
            )

        iterations = 0

        # Try with different B values
        for B_multiplier in [1, 2, 5, 10]:
            B = self.B * B_multiplier
            iterations += 1

            # Generate primes up to B
            primes = [p for p in range(2, B + 1) if MathUtils.is_prime(p)]

            # Compute M = product of prime powers
            # M = ∏_{q≤B} q^{⌊log_q B⌋}
            # M must stay a true multiple of p-1, so it must NOT be
            # reduced modulo n-1 (that would break divisibility).
            M = 1
            for prime in primes:
                # Raise to highest power of prime <= B
                power = prime
                while power * prime <= B:
                    power *= prime
                M *= power

            # Try multiple bases
            for _ in range(10):  # Try up to 10 different bases
                a = random.randint(2, n - 2)
                a_pow = pow(a, M, n)
                g = MathUtils.gcd(a_pow - 1, n)

                if 1 < g < n:
                    p = g
                    q = n // g
                    return FactorizationResult(
                        success=True,
                        p=p,
                        q=q,
                        iterations=iterations,
                        time_elapsed=time.perf_counter() - start_time,
                        method="Pollard's p-1"
                    )

        return FactorizationResult(
            success=False,
            iterations=iterations,
            time_elapsed=time.perf_counter() - start_time,
            method="Pollard's p-1"
        )


def factorize_auto(n: int) -> FactorizationResult:
    """
    Automatically select and run the best factorization method.

    Args:
        n: Modulus to factorize

    Returns:
        FactorizationResult with factors p and q if successful
    """
    # Check bit length
    bit_length = n.bit_length()

    # For very small N, use brute force
    if bit_length <= 40:
        result = BruteForceFactorization().factorize(n)
        if result.success:
            return result

    # Try Fermat (effective for close primes)
    result = FermatFactorization().factorize(n)
    if result.success:
        return result

    # Try Pollard's rho (effective for small factors)
    result = PollardsRho().factorize(n)
    if result.success:
        return result

    # Try Pollard's p-1 (effective when p-1 is B-smooth)
    result = PollardsP1().factorize(n)
    if result.success:
        return result

    # Try brute force as last resort for small N
    if bit_length <= 64:
        result = BruteForceFactorization().factorize(n)
        if result.success:
            return result

    return FactorizationResult(
        success=False,
        method="Auto (all methods failed)"
    )
