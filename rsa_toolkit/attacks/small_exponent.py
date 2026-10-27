"""
Attacks on RSA with small public exponent e.

This module implements attacks that exploit small public exponents (e=3, e=17, etc.)
when messages are not properly padded.
"""

from typing import Optional, List, Tuple
from dataclasses import dataclass

from rsa_toolkit.utils.math_utils import MathUtils


@dataclass
class SmallExponentResult:
    """Result of small exponent attack."""
    success: bool
    message: Optional[int] = None
    iterations: int = 0
    time_elapsed: float = 0.0
    method: str = ""


class CubeRootAttack:
    """
    Cube root attack for e=3 without padding.

    When m^e < N, the modulo operation doesn't reduce the value,
    so we can recover m by taking the e-th root directly.
    """

    def __init__(self, e: int = 3):
        """
        Initialize cube root attack.

        Args:
            e: Public exponent (typically 3)
        """
        self.e = e

    def attack(self, ciphertext: int, n: int) -> SmallExponentResult:
        """
        Recover plaintext when m^e < N.

        Args:
            ciphertext: Ciphertext c = m^e mod N
            n: Modulus

        Returns:
            SmallExponentResult with recovered message if successful
        """
        import time
        start_time = time.perf_counter()

        # Check if ciphertext is small enough
        if ciphertext >= n:
            return SmallExponentResult(
                success=False,
                method="Cube Root (ciphertext >= N)"
            )

        # Compute e-th root
        message, is_exact = MathUtils.integer_nth_root(ciphertext, self.e)

        if is_exact:
            return SmallExponentResult(
                success=True,
                message=message,
                iterations=1,
                time_elapsed=time.perf_counter() - start_time,
                method="Cube Root"
            )

        return SmallExponentResult(
            success=False,
            message=message,
            iterations=1,
            time_elapsed=time.perf_counter() - start_time,
            method="Cube Root (not exact)"
        )


class HastadBroadcastAttack:
    """
    Hastad's broadcast attack for small e.

    When the same message is encrypted with the same small e
    for different moduli, we can recover m using CRT.
    """

    def __init__(self, e: int = 3):
        """
        Initialize Hastad's broadcast attack.

        Args:
            e: Public exponent (typically 3)
        """
        self.e = e

    def attack(
        self,
        ciphertexts: List[int],
        moduli: List[int]
    ) -> SmallExponentResult:
        """
        Recover message using Chinese Remainder Theorem.

        Args:
            ciphertexts: List of ciphertexts [c1, c2, c3, ...]
            moduli: List of corresponding moduli [n1, n2, n3, ...]

        Returns:
            SmallExponentResult with recovered message if successful
        """
        import time
        start_time = time.perf_counter()

        # Need at least e ciphertexts
        if len(ciphertexts) < self.e or len(moduli) < self.e:
            return SmallExponentResult(
                success=False,
                method=f"Hastad (need at least {self.e} ciphertexts)"
            )

        # Check that moduli are pairwise coprime
        for i in range(len(moduli)):
            for j in range(i + 1, len(moduli)):
                if MathUtils.gcd(moduli[i], moduli[j]) != 1:
                    return SmallExponentResult(
                        success=False,
                        method="Hastad (moduli not coprime)"
                    )

        # Use CRT to compute M^e
        congruences = [(c, n) for c, n in zip(ciphertexts, moduli)]
        m_pow_e = MathUtils.chinese_remainder_theorem(congruences)

        if m_pow_e is None:
            return SmallExponentResult(
                success=False,
                method="Hastad (CRT failed)"
            )

        # Compute e-th root
        message, is_exact = MathUtils.integer_nth_root(m_pow_e, self.e)

        if is_exact:
            return SmallExponentResult(
                success=True,
                message=message,
                iterations=len(ciphertexts),
                time_elapsed=time.perf_counter() - start_time,
                method="Hastad's Broadcast"
            )

        return SmallExponentResult(
            success=False,
            message=message,
            iterations=len(ciphertexts),
            time_elapsed=time.perf_counter() - start_time,
            method="Hastad's Broadcast (not exact)"
        )


class FranklinReiterAttack:
    """
    Franklin-Reiter related message attack.

    When two related messages m1 and m2 = f(m1) are encrypted
    with the same small e and modulus, we can recover them.
    """

    def __init__(self, e: int = 3):
        """
        Initialize Franklin-Reiter attack.

        Args:
            e: Public exponent
        """
        self.e = e

    def attack(
        self,
        c1: int,
        c2: int,
        n: int,
        relation_func
    ) -> SmallExponentResult:
        """
        Recover related messages.

        Args:
            c1: First ciphertext
            c2: Second ciphertext
            n: Modulus
            relation_func: Function relating m2 to m1 (e.g., m2 = m1 + k)

        Returns:
            SmallExponentResult with recovered message if successful
        """
        import time
        start_time = time.perf_counter()

        # This is a simplified version - full implementation requires
        # polynomial GCD over finite fields
        # For educational purposes, we implement a basic version

        # If relation is linear: m2 = m1 + k
        # Then c2 - c1 ≡ (m1 + k)^e - m1^e (mod n)
        # We can try small values of k

        # This is computationally expensive for large n
        # In practice, use sage or specialized libraries

        return SmallExponentResult(
            success=False,
            method="Franklin-Reiter (not fully implemented)"
        )
