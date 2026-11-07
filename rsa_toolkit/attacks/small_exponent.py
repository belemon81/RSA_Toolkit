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

        # The attack is valid iff m^e < N held before the mod reduction,
        # i.e. ciphertext == m^e exactly. That is verified directly by
        # checking whether the e-th root is exact — no separate guard
        # on ciphertext vs N is needed (c = m^e mod N is always < N).

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

        # Non-coprime moduli: if gcd(N_i, N_j) > 1, that shared factor
        # splits both moduli, so we can compute each private exponent
        # directly and decrypt the corresponding ciphertext.
        saw_non_coprime = False
        for i in range(len(moduli)):
            for j in range(i + 1, len(moduli)):
                g = MathUtils.gcd(moduli[i], moduli[j])
                if g <= 1:
                    continue
                saw_non_coprime = True
                for idx in (i, j):
                    n_i = moduli[idx]
                    if not (1 < g < n_i) or n_i % g != 0:
                        continue
                    p, q = g, n_i // g
                    phi = (p - 1) * (q - 1)
                    d = MathUtils.mod_inverse(self.e, phi)
                    if d is None:
                        continue
                    m = pow(ciphertexts[idx], d, n_i)
                    if pow(m, self.e, n_i) == ciphertexts[idx]:
                        return SmallExponentResult(
                            success=True,
                            message=m,
                            iterations=1,
                            time_elapsed=time.perf_counter() - start_time,
                            method="Hastad (non-coprime moduli)"
                        )

        if saw_non_coprime:
            return SmallExponentResult(
                success=False,
                method="Hastad (non-coprime moduli, decryption failed)"
            )

        # Check that moduli are pairwise coprime (required for CRT)
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
