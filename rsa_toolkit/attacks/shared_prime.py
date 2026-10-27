"""
Shared prime (GCD) attack.

This module implements the attack when two moduli share a common prime factor
due to poor random number generation.
"""

from typing import Optional, List, Tuple
from dataclasses import dataclass

from rsa_toolkit.utils.math_utils import MathUtils


@dataclass
class SharedPrimeResult:
    """Result of shared prime attack."""
    success: bool
    shared_prime: Optional[int] = None
    vulnerabilities: Optional[List[Tuple[int, int]]] = None
    iterations: int = 0
    time_elapsed: float = 0.0
    method: str = ""


class SharedPrimeAttack:
    """
    Attack when moduli share a common prime factor.

    If two moduli N1 and N2 share a prime factor p, then gcd(N1, N2) = p.
    This allows immediate factorization of both moduli.
    """

    def __init__(self):
        """Initialize shared prime attack."""
        pass

    def attack_pair(self, n1: int, n2: int) -> SharedPrimeResult:
        """
        Check if two moduli share a prime factor.

        Args:
            n1: First modulus
            n2: Second modulus

        Returns:
            SharedPrimeResult with shared prime if found
        """
        import time
        start_time = time.perf_counter()

        # Compute GCD
        g = MathUtils.gcd(n1, n2)

        if g > 1 and g < n1 and g < n2:
            # Found shared prime
            return SharedPrimeResult(
                success=True,
                shared_prime=g,
                iterations=1,
                time_elapsed=time.perf_counter() - start_time,
                method="Shared Prime (GCD)"
            )

        return SharedPrimeResult(
            success=False,
            iterations=1,
            time_elapsed=time.perf_counter() - start_time,
            method="Shared Prime (GCD)"
        )

    def scan_multiple(self, moduli: List[int]) -> SharedPrimeResult:
        """
        Scan multiple moduli for shared prime factors.

        Args:
            moduli: List of moduli to check

        Returns:
            SharedPrimeResult with list of vulnerable pairs
        """
        import time
        start_time = time.perf_counter()

        vulnerabilities = []
        iterations = 0

        for i in range(len(moduli)):
            for j in range(i + 1, len(moduli)):
                iterations += 1
                g = MathUtils.gcd(moduli[i], moduli[j])

                if g > 1 and g < moduli[i] and g < moduli[j]:
                    vulnerabilities.append((i, j, g))

        if vulnerabilities:
            return SharedPrimeResult(
                success=True,
                shared_prime=vulnerabilities[0][2],
                vulnerabilities=vulnerabilities,
                iterations=iterations,
                time_elapsed=time.perf_counter() - start_time,
                method="Shared Prime (Batch Scan)"
            )

        return SharedPrimeResult(
            success=False,
            iterations=iterations,
            time_elapsed=time.perf_counter() - start_time,
            method="Shared Prime (Batch Scan)"
        )

    def factorize_with_shared_prime(
        self,
        n: int,
        shared_prime: int
    ) -> Tuple[int, int]:
        """
        Factorize a modulus given a shared prime factor.

        Args:
            n: Modulus to factorize
            shared_prime: Known shared prime factor

        Returns:
            Tuple (p, q) where p is the shared prime
        """
        p = shared_prime
        q = n // p
        return p, q
