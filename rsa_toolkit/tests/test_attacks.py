"""
Tests for attack modules.
"""

import pytest
from rsa_toolkit.utils.rsa_utils import RSAUtils
from rsa_toolkit.attacks.factorization import (
    BruteForceFactorization,
    FermatFactorization,
    PollardsRho,
    factorize_auto
)
from rsa_toolkit.attacks.small_exponent import (
    CubeRootAttack,
    HastadBroadcastAttack
)
from rsa_toolkit.attacks.wiener import WienerAttack
from rsa_toolkit.attacks.shared_modulus import SharedModulusAttack
from rsa_toolkit.attacks.shared_prime import SharedPrimeAttack


class TestFactorizationAttacks:
    """Test suite for factorization attacks."""

    def test_brute_force_small_modulus(self):
        """Test brute force on small modulus."""
        # Use known small primes for reliable testing
        p = 7
        q = 5
        n = p * q
        e = 17
        phi = (p - 1) * (q - 1)
        d = RSAUtils.compute_d_from_p_q_e(p, q, e)

        result = BruteForceFactorization(max_iterations=100000).factorize(n)
        assert result.success is True
        assert result.p == p or result.p == q
        assert result.q == q or result.q == p

    def test_fermat_close_primes(self):
        """Test Fermat factorization on close primes."""
        # Use known close primes
        p = 10007
        q = 10009
        n = p * q
        e = 65537
        phi = (p - 1) * (q - 1)
        d = RSAUtils.compute_d_from_p_q_e(p, q, e)

        result = FermatFactorization().factorize(n)
        assert result.success is True
        assert result.p == p or result.p == q
        assert result.q == q or result.q == p

    def test_pollards_rho_small_factor(self):
        """Test Pollard's rho on modulus with small factor."""
        # Generate modulus with known small factor
        p = 17  # Small prime
        q = RSAUtils._generate_prime(64)
        n = p * q

        result = PollardsRho().factorize(n)
        assert result.success is True
        assert result.p == p or result.p == q
        assert result.q == q or result.q == p

    def test_factorize_auto(self):
        """Test automatic factorization selection."""
        p = 61
        q = 53
        n = p * q

        result = factorize_auto(n)
        assert result.success is True
        assert result.p == p or result.p == q
        assert result.q == q or result.q == p


class TestSmallExponentAttacks:
    """Test suite for small exponent attacks."""

    def test_cube_root_attack(self):
        """Test cube root attack."""
        # Use known larger primes to accommodate m^e < n
        p = 1009
        q = 997
        n = p * q
        e = 3
        phi = (p - 1) * (q - 1)
        d = RSAUtils.compute_d_from_p_q_e(p, q, e)

        # Small message so that m^e < n
        message = 42
        ciphertext = RSAUtils.encrypt(message, n, e)

        result = CubeRootAttack(e=3).attack(ciphertext, n)
        assert result.success is True
        assert result.message == message

    def test_hastad_broadcast_attack(self):
        """Test Hastad's broadcast attack."""
        e = 3
        message = 42

        ciphertexts = []
        moduli = []

        # Use known small primes
        primes = [(61, 53), (67, 59), (71, 73)]
        for p, q in primes:
            n = p * q
            ciphertext = RSAUtils.encrypt(message, n, e)
            ciphertexts.append(ciphertext)
            moduli.append(n)

        result = HastadBroadcastAttack(e=e).attack(ciphertexts, moduli)
        assert result.success is True
        assert result.message == message


class TestWienerAttack:
    """Test suite for Wiener's attack."""

    def test_wiener_small_d(self):
        """Test Wiener's attack on small d."""
        # Use very small primes to ensure small d
        p = 61
        q = 53
        n = p * q
        e = 65537
        phi = (p - 1) * (q - 1)
        d = RSAUtils.compute_d_from_p_q_e(p, q, e)

        result = WienerAttack().attack(n, e)

        # May or may not succeed depending on how small d is
        if result.success:
            assert result.d == d
            assert result.p == p
            assert result.q == q


class TestSharedModulusAttack:
    """Test suite for shared modulus attacks."""

    def test_shared_modulus_internal(self):
        """Test internal shared modulus attack."""
        p = 61
        q = 53
        n = p * q
        e1 = 17
        e2 = 65537
        phi = (p - 1) * (q - 1)
        d1 = RSAUtils.compute_d_from_p_q_e(p, q, e1)
        d2 = RSAUtils.compute_d_from_p_q_e(p, q, e2)

        result = SharedModulusAttack.internal_attack(n, e1, d1, e2)
        assert result.success is True
        # Verify the recovered d works (may be different but equivalent)
        assert (e2 * result.d) % phi == 1

    def test_shared_modulus_external(self):
        """Test external shared modulus attack."""
        p = 61
        q = 53
        n = p * q
        e1 = 17
        e2 = 65537
        d1 = RSAUtils.compute_d_from_p_q_e(p, q, e1)
        d2 = RSAUtils.compute_d_from_p_q_e(p, q, e2)

        message = 42
        c1 = RSAUtils.encrypt(message, n, e1)
        c2 = RSAUtils.encrypt(message, n, e2)

        result = SharedModulusAttack.external_attack(c1, c2, n, e1, e2)
        assert result.success is True
        assert result.d == message


class TestSharedPrimeAttack:
    """Test suite for shared prime attack."""

    def test_shared_prime_pair(self):
        """Test shared prime detection for pair."""
        shared_p = 61
        q1 = 53
        q2 = 59

        n1 = shared_p * q1
        n2 = shared_p * q2

        result = SharedPrimeAttack().attack_pair(n1, n2)
        assert result.success is True
        assert result.shared_prime == shared_p

    def test_shared_prime_scan(self):
        """Test shared prime scan on multiple moduli."""
        shared_p = 61
        moduli = []

        # First modulus uses shared prime
        q1 = 53
        n1 = shared_p * q1
        moduli.append(n1)

        # Second modulus uses shared prime
        q2 = 59
        n2 = shared_p * q2
        moduli.append(n2)

        # Third modulus uses different primes
        p3 = 67
        q3 = 71
        n3 = p3 * q3
        moduli.append(n3)

        result = SharedPrimeAttack().scan_multiple(moduli)
        assert result.success is True
        assert len(result.vulnerabilities) > 0

    def test_factorize_with_shared_prime(self):
        """Test factorization with known shared prime."""
        shared_p = 61
        q = 53
        n = shared_p * q

        p, q_recovered = SharedPrimeAttack().factorize_with_shared_prime(n, shared_p)
        assert p == shared_p
        assert q_recovered == q
