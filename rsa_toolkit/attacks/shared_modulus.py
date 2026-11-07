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
        e2: int,
        d2: int,
        e1: int
    ) -> SharedModulusResult:
        """
        Internal attacker: recover the victim's private exponent d_target
        on a shared modulus, given the attacker's OWN key pair (e2,
        d2) and the victim's public exponent e1.

        The attacker does NOT know the victim's private key — that is
        exactly what this attack recovers.

        Args:
            n: Shared modulus
            e2: Attacker's own public exponent
            d2: Attacker's own private exponent (known)
            e1: Victim's public exponent

        Returns:
            SharedModulusResult with the victim's private exponent
        """
        import time
        start_time = time.perf_counter()

        # t = e2*d2 - 1 is a multiple of φ(N). Any d_target
        # satisfying e1*d_target ≡ 1 (mod t) is also valid mod φ(N),
        # because t is a multiple of φ(N). If gcd(t, e1) > 1 we may
        # divide t by that gcd: since gcd(e1, φ(N)) = 1, all common
        # factors live in the cofactor of φ(N) inside t, so
        # t/gcd(t, e1) remains a multiple of φ(N). Repeat until
        # e1 is invertible modulo t.
        t = e2 * d2 - 1
        iterations = 0

        while t > 1:
            iterations += 1
            g = MathUtils.gcd(t, e1)
            if g == 1:
                d_target = MathUtils.mod_inverse(e1, t)
                if d_target is not None:
                    return SharedModulusResult(
                        success=True,
                        d=d_target % t,
                        iterations=iterations,
                        time_elapsed=time.perf_counter() - start_time,
                        method="Shared Modulus (Internal)"
                    )
                break
            t //= g

        return SharedModulusResult(
            success=False,
            iterations=iterations,
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
