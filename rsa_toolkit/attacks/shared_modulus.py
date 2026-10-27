"""
Shared modulus attacks.

This module implements attacks when the same modulus N is used by multiple users.
"""

from typing import Optional
from dataclasses import dataclass

from rsa_toolkit.utils.math_utils import MathUtils


@dataclass
class SharedModulusResult:
    """Result of shared modulus attack."""
    success: bool
    d: Optional[int] = None
    iterations: int = 0
    time_elapsed: float = 0.0
    method: str = ""


class SharedModulusAttack:
    """
    Attack when modulus N is shared between users.

    If an internal attacker knows their own private key and the modulus
    is shared, they can compute other users' private keys.
    """

    @staticmethod
    def internal_attack(
        n: int,
        e1: int,
        d1: int,
        e2: int
    ) -> SharedModulusResult:
        """
        Internal attacker: recover d2 from known d1 on shared modulus.

        Args:
            n: Shared modulus
            e1: Attacker's public exponent
            d1: Attacker's private exponent (known)
            e2: Victim's public exponent

        Returns:
            SharedModulusResult with recovered private key if successful
        """
        import time
        start_time = time.perf_counter()

        # From: e1*d1 ≡ 1 (mod φ(N))
        # => e1*d1 - 1 = k*φ(N)
        # => φ(N) = (e1*d1 - 1) / k

        # Try small values of k
        for k in range(1, 100):
            phi_candidate = (e1 * d1 - 1) // k

            # Check if (e1*d1 - 1) is divisible by k
            if (e1 * d1 - 1) % k != 0:
                continue

            # Compute d2 from φ(N)
            d2 = MathUtils.mod_inverse(e2, phi_candidate)

            if d2 is None:
                continue

            # Verify the result
            if (e2 * d2) % phi_candidate == 1:
                return SharedModulusResult(
                    success=True,
                    d=d2,
                    iterations=k,
                    time_elapsed=time.perf_counter() - start_time,
                    method="Shared Modulus (Internal)"
                )

        return SharedModulusResult(
            success=False,
            iterations=100,
            time_elapsed=time.perf_counter() - start_time,
            method="Shared Modulus (Internal)"
        )

    @staticmethod
    def external_attack(
        c1: int,
        c2: int,
        n: int,
        e1: int,
        e2: int
    ) -> SharedModulusResult:
        """
        External attacker: recover message from two ciphertexts on shared modulus.

        When the same message is encrypted with different e values on the same N,
        we can use the extended Euclidean algorithm to recover the message.

        Args:
            c1: First ciphertext
            c2: Second ciphertext
            n: Shared modulus
            e1: First public exponent
            e2: Second public exponent

        Returns:
            SharedModulusResult with recovered message if successful
        """
        import time
        start_time = time.perf_counter()

        # Find a and b such that: a*e1 + b*e2 = 1
        g, a, b = MathUtils.extended_gcd(e1, e2)

        if g != 1:
            return SharedModulusResult(
                success=False,
                method="Shared Modulus (External) - e1 and e2 not coprime"
            )

        # Compute message: m = c1^a * c2^b (mod N)
        # Note: one of a or b will be negative
        if a < 0:
            c1_inv = MathUtils.mod_inverse(c1, n)
            if c1_inv is None:
                return SharedModulusResult(
                    success=False,
                    method="Shared Modulus (External) - no inverse for c1"
                )
            message = (pow(c1_inv, -a, n) * pow(c2, b, n)) % n
        elif b < 0:
            c2_inv = MathUtils.mod_inverse(c2, n)
            if c2_inv is None:
                return SharedModulusResult(
                    success=False,
                    method="Shared Modulus (External) - no inverse for c2"
                )
            message = (pow(c1, a, n) * pow(c2_inv, -b, n)) % n
        else:
            message = (pow(c1, a, n) * pow(c2, b, n)) % n

        return SharedModulusResult(
            success=True,
            d=message,  # Store message in d field for result
            iterations=1,
            time_elapsed=time.perf_counter() - start_time,
            method="Shared Modulus (External)"
        )
