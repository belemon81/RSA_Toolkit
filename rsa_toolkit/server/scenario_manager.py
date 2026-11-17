"""
Scenario Manager for Vulnerable RSA Server.

This module manages different attack scenarios with weak RSA configurations.
"""

import random
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from rsa_toolkit.utils.rsa_utils import RSAUtils
from rsa_toolkit.utils.math_utils import MathUtils


class ScenarioType(Enum):
    """Enumeration of attack scenarios."""
    SECURE = "S0"  # Secure configuration (baseline)
    SMALL_MODULUS = "S1"  # Small modulus (< 64 bits)
    CLOSE_PRIMES = "S2"  # p and q very close
    POLLARDS_RHO = "S3"  # N has small prime factor (Pollard's rho)
    POLLARDS_P1 = "S4"  # p-1 and q-1 have small factors (Pollard's p-1)
    SHARED_MODULUS_INTERNAL = "S5"  # Shared modulus (internal attacker)
    SHARED_MODULUS_EXTERNAL = "S6"  # Shared modulus (external attacker)
    SMALL_D = "S7"  # Small private exponent d
    SMALL_E_NO_PADDING = "S8"  # Small e, no padding
    SMALL_E_BROADCAST = "S9"  # Small e, broadcast attack
    SHARED_PRIME = "S10"  # Shared prime factor (GCD attack)


@dataclass
class RSAKey:
    """RSA key representation."""
    n: int
    e: int
    d: Optional[int] = None  # Private key (only on server)
    p: Optional[int] = None  # Prime factor (only on server)
    q: Optional[int] = None  # Prime factor (only on server)


@dataclass
class Scenario:
    """Attack scenario configuration."""
    scenario_id: str
    scenario_type: ScenarioType
    description: str
    keys: Dict[str, RSAKey]  # Multiple keys for some scenarios
    messages: Dict[str, int]  # Original messages
    ciphertexts: Dict[str, int]  # Encrypted messages
    seed: int


@dataclass
class BitConfig:
    """Bit length configuration for scenario generation."""
    # S0: Secure baseline (default 2048; lower values allowed for testing)
    s0_bits: int = 2048
    # S1: Small modulus
    s1_p_bits: int = 24  # Default: ~20 bits (~1 million)
    s1_q_bits: int = 32  # Default: ~28 bits (~268 million)
    # S2: Close primes
    s2_pq_bits: int = 128  # Default: ~64 bits
    s2_max_offset: int = 8000  # Default: offset < 10000
    # S3: Pollard's rho
    s3_p_bits: int = 24  # Default: ~18 bits (~262k)
    s3_q_bits: int = 64  # Default: ~46 bits (~70 trillion)
    # S4: Pollard's p-1 (p is constructed with B-smooth p-1, ~s4_p_bits)
    s4_p_bits: int = 82  # Default: ~24 bits
    s4_q_bits: int = 103  # Default: ~32 bits
    # S5, S6: Shared modulus
    s_shared_pq_bits: int = 128  # Default: ~20 bits
    # S7: Small d
    s7_pq_bits: int = 114  # Default: ~16 bits
    # S8, S9: Small e
    s_small_e_bits: int = 584  # Default: 128 bits
    # S10: Shared prime
    s10_p_bits: int = 256  # Default: ~20 bits
    s10_q_bits: int = 256  # Default: ~20 bits


class ScenarioManager:
    """
    Manager for creating and managing attack scenarios.

    Implements the scenarios described in the report:
    - S0: Secure configuration (2048-bit, e=65537, textbook RSA)
    - S1: Small modulus (< 64 bits)
    - S2: Close primes (Fermat factorization)
    - S3: N has small prime factor (Pollard's rho)
    - S4: p-1 and q-1 have small factors (Pollard's p-1)
    - S5: Shared modulus (internal attacker)
    - S6: Shared modulus (external attacker)
    - S7: Small d (Wiener attack)
    - S8: Small e, no padding (cube root attack)
    - S9: Small e, broadcast (Hastad attack)
    - S10: Shared prime (GCD attack)
    """

    def __init__(self):
        """Initialize scenario manager."""
        self.scenarios: Dict[str, Scenario] = {}
        self.current_seed: Optional[int] = None

    def set_seed(self, seed: int):
        """
        Set random seed for reproducible scenario generation.

        Args:
            seed: Random seed value
        """
        self.current_seed = seed
        random.seed(seed)

    def create_scenario(
        self,
        scenario_type: ScenarioType,
        seed: Optional[int] = None,
        bit_config: Optional[BitConfig] = None
    ) -> Scenario:
        """
        Create a specific attack scenario.

        Args:
            scenario_type: Type of scenario to create
            seed: Optional seed for reproducibility
            bit_config: Optional bit length configuration (uses defaults if not provided)

        Returns:
            Created Scenario object
        """
        if seed is not None:
            self.set_seed(seed)

        if bit_config is None:
            bit_config = BitConfig()

        scenario_id = f"{scenario_type.value}_{random.randint(1000, 9999)}"

        if scenario_type == ScenarioType.SECURE:
            return self._create_secure_scenario(scenario_id, bit_config)
        elif scenario_type == ScenarioType.SMALL_MODULUS:
            return self._create_small_modulus_scenario(scenario_id, bit_config)
        elif scenario_type == ScenarioType.CLOSE_PRIMES:
            return self._create_close_primes_scenario(scenario_id, bit_config)
        elif scenario_type == ScenarioType.POLLARDS_RHO:
            return self._create_pollards_rho_scenario(scenario_id, bit_config)
        elif scenario_type == ScenarioType.POLLARDS_P1:
            return self._create_pollards_p1_scenario(scenario_id, bit_config)
        elif scenario_type == ScenarioType.SHARED_MODULUS_INTERNAL:
            return self._create_shared_modulus_internal_scenario(scenario_id, bit_config)
        elif scenario_type == ScenarioType.SHARED_MODULUS_EXTERNAL:
            return self._create_shared_modulus_external_scenario(scenario_id, bit_config)
        elif scenario_type == ScenarioType.SMALL_D:
            return self._create_small_d_scenario(scenario_id, bit_config)
        elif scenario_type == ScenarioType.SMALL_E_NO_PADDING:
            return self._create_small_e_no_padding_scenario(scenario_id, bit_config)
        elif scenario_type == ScenarioType.SMALL_E_BROADCAST:
            return self._create_small_e_broadcast_scenario(scenario_id, bit_config)
        elif scenario_type == ScenarioType.SHARED_PRIME:
            return self._create_shared_prime_scenario(scenario_id, bit_config)
        else:
            raise ValueError(f"Unknown scenario type: {scenario_type}")

    def _create_secure_scenario(self, scenario_id: str, bit_config: BitConfig) -> Scenario:
        """Create S0: Secure configuration."""
        (n, e, d), (p, q) = RSAUtils.generate_keypair(bit_length=bit_config.s0_bits, e=65537)

        key = RSAKey(n=n, e=e, d=d, p=p, q=q)
        message = RSAUtils.message_to_int("This is a secure message")
        ciphertext = RSAUtils.encrypt(message, n, e)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SECURE,
            description=f"Secure RSA configuration ({bit_config.s0_bits}-bit, e=65537)",
            keys={"user1": key},
            messages={"user1": message},
            ciphertexts={"user1": ciphertext},
            seed=self.current_seed if self.current_seed is not None else random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_small_modulus_scenario(self, scenario_id: str, bit_config: BitConfig) -> Scenario:
        """Create S1: Small modulus (< 64 bits) with small prime factors."""
        # Generate modulus with one small prime factor for easier brute force
        # Ensure p is always the smaller one (small_p < q)
        p = RSAUtils._generate_prime(bit_config.s1_p_bits)
        q = RSAUtils._generate_prime(bit_config.s1_q_bits)

        # Ensure p < q (so p is always the small factor)
        if p > q:
            p, q = q, p

        n = p * q

        e = 65537
        phi = (p - 1) * (q - 1)

        # Ensure e and phi are coprime
        if MathUtils.gcd(e, phi) != 1:
            # Try different e values
            for e_candidate in [3, 5, 17, 257, 65537]:
                if MathUtils.gcd(e_candidate, phi) == 1:
                    e = e_candidate
                    break
            else:
                # Regenerate if no suitable e found
                return self._create_small_modulus_scenario(scenario_id, bit_config)

        d = MathUtils.mod_inverse(e, phi)

        key = RSAKey(n=n, e=e, d=d, p=p, q=q)
        message = RSAUtils.message_to_int("Hi")
        ciphertext = RSAUtils.encrypt(message, n, e)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SMALL_MODULUS,
            description=f"Small modulus ({n.bit_length()} bits) with small prime factor - vulnerable to brute force",
            keys={"user1": key},
            messages={"user1": message},
            ciphertexts={"user1": ciphertext},
            seed=self.current_seed if self.current_seed is not None else random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_close_primes_scenario(self, scenario_id: str, bit_config: BitConfig) -> Scenario:
        """Create S2: Close primes (Fermat factorization)."""
        # Generate p and q very close together for Fermat factorization
        # Start with a base prime, then generate q very close to p
        p = RSAUtils._generate_prime(bit_config.s2_pq_bits)
        # Generate q within a small range using bit_config.s2_max_offset
        # offset must be EVEN so that q = p + offset stays odd (p is odd);
        # an odd offset would make q even and the primality loop never ends.
        offset = random.randint(1, bit_config.s2_max_offset) * 2
        q = p + offset

        # Ensure q is prime
        while not MathUtils.is_prime(q):
            offset += 2
            q = p + offset

        # Ensure p < q
        if p > q:
            p, q = q, p

        n = p * q
        e = 65537
        phi = (p - 1) * (q - 1)

        # Ensure e and phi are coprime
        if MathUtils.gcd(e, phi) != 1:
            for e_candidate in [3, 5, 17, 257, 65537]:
                if MathUtils.gcd(e_candidate, phi) == 1:
                    e = e_candidate
                    break
            else:
                return self._create_close_primes_scenario(scenario_id, bit_config)

        d = MathUtils.mod_inverse(e, phi)

        key = RSAKey(n=n, e=e, d=d, p=p, q=q)
        message = RSAUtils.message_to_int("Close primes")
        ciphertext = RSAUtils.encrypt(message, n, e)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.CLOSE_PRIMES,
            description=f"Close primes (offset={offset}) - vulnerable to Fermat factorization",
            keys={"user1": key},
            messages={"user1": message},
            ciphertexts={"user1": ciphertext},
            seed=self.current_seed if self.current_seed is not None else random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_small_d_scenario(self, scenario_id: str, bit_config: BitConfig) -> Scenario:
        """Create S7: Small d (Wiener attack)."""
        # Wiener's attack condition: d < N^(1/4) / 3
        # Correct construction: choose a SMALL d first, then compute
        # e = d^{-1} mod phi(N). This makes e large while d stays small,
        # which is exactly the vulnerable configuration Wiener exploits.
        # (Choosing small e and deriving d = e^{-1} mod phi yields a LARGE d
        #  and is NOT vulnerable to Wiener.)

        import gmpy2

        # Use bit_config.s7_pq_bits for both primes. The attempt cap prevents
        # an infinite loop when s7_pq_bits is set absurdly small: then
        # bound <= 3, the d-range is empty, and no keypair can ever be built.
        for _attempt in range(1000):
            p = RSAUtils._generate_prime(bit_config.s7_pq_bits)
            q = RSAUtils._generate_prime(bit_config.s7_pq_bits)
            if p == q:
                continue
            if p > q:
                p, q = q, p

            n = p * q
            phi = (p - 1) * (q - 1)
            bound = gmpy2.iroot(n, 4)[0] // 3

            # Pick a small d coprime to phi
            for d in range(3, int(bound)):
                if MathUtils.gcd(d, phi) == 1:
                    e = MathUtils.mod_inverse(d, phi)
                    if e is None or e <= 1:
                        continue
                    # Ensure e is usable (odd preferred, coprime already holds)
                    key = RSAKey(n=n, e=e, d=d, p=p, q=q)
                    message = RSAUtils.message_to_int("Small d")
                    ciphertext = RSAUtils.encrypt(message, n, e)

                    scenario = Scenario(
                        scenario_id=scenario_id,
                        scenario_type=ScenarioType.SMALL_D,
                        description=f"Small private exponent d={d} - vulnerable to Wiener attack",
                        keys={"user1": key},
                        messages={"user1": message},
                        ciphertexts={"user1": ciphertext},
                        seed=self.current_seed if self.current_seed is not None else random.randint(0, 2**32)
                    )

                    self.scenarios[scenario_id] = scenario
                    return scenario

        raise RuntimeError(
            "Failed to generate small-d keypair: try larger s7_pq_bits"
        )

    def _create_shared_modulus_internal_scenario(self, scenario_id: str, bit_config: BitConfig) -> Scenario:
        """Create S5: Shared modulus (internal attacker)."""
        # Generate shared modulus with small primes for easier factorization
        # This allows the "attacker" to factorize and get their own d
        p = RSAUtils._generate_prime(bit_config.s_shared_pq_bits)
        q = RSAUtils._generate_prime(bit_config.s_shared_pq_bits)
        while q == p:
            q = RSAUtils._generate_prime(bit_config.s_shared_pq_bits)

        if p > q:
            p, q = q, p

        n = p * q
        phi = (p - 1) * (q - 1)

        # Use small e values to make k smaller for the attack
        # First key (attacker knows this)
        e1 = 3
        if MathUtils.gcd(e1, phi) != 1:
            e1 = 5
            while MathUtils.gcd(e1, phi) != 1:
                e1 += 2
        d1 = MathUtils.mod_inverse(e1, phi)

        # Second key (victim, different e)
        e2 = 17
        if MathUtils.gcd(e2, phi) != 1:
            e2 = 5
            # Unbounded: phi has finitely many prime factors, so an odd
            # e2 coprime to phi always exists. A bounded loop could exit
            # with gcd(e2, phi) != 1 and leave d2 = None.
            while MathUtils.gcd(e2, phi) != 1:
                e2 += 2
        d2 = MathUtils.mod_inverse(e2, phi)

        # Ensure e1 and e2 are coprime (required for external attack).
        # Without this, both e's can converge to the same small prime
        # when phi has small prime factors, making e1 == e2.
        while MathUtils.gcd(e1, e2) != 1:
            e2 += 2
            while MathUtils.gcd(e2, phi) != 1:
                e2 += 2
            d2 = MathUtils.mod_inverse(e2, phi)

        key1 = RSAKey(n=n, e=e1, d=d1, p=p, q=q)
        key2 = RSAKey(n=n, e=e2, d=d2, p=p, q=q)

        # Use a small integer message for this scenario
        message = 42
        c1 = RSAUtils.encrypt(message, n, e1)
        c2 = RSAUtils.encrypt(message, n, e2)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SHARED_MODULUS_INTERNAL,
            description=f"Shared modulus N ({n.bit_length()} bits) - internal attacker knows one private key",
            keys={"attacker": key1, "victim": key2},
            messages={"attacker": message, "victim": message},
            ciphertexts={"attacker": c1, "victim": c2},
            seed=self.current_seed if self.current_seed is not None else random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_shared_modulus_external_scenario(self, scenario_id: str, bit_config: BitConfig) -> Scenario:
        """Create S6: Shared modulus (external attacker)."""
        # Generate shared modulus with small primes
        p = RSAUtils._generate_prime(bit_config.s_shared_pq_bits)
        q = RSAUtils._generate_prime(bit_config.s_shared_pq_bits)
        while q == p:
            q = RSAUtils._generate_prime(bit_config.s_shared_pq_bits)

        if p > q:
            p, q = q, p

        n = p * q
        phi = (p - 1) * (q - 1)

        # Two keys with different e, both coprime to phi
        e1 = 17
        if MathUtils.gcd(e1, phi) != 1:
            e1 = 3
            while MathUtils.gcd(e1, phi) != 1:
                e1 += 2
        d1 = MathUtils.mod_inverse(e1, phi)

        e2 = 65537
        if MathUtils.gcd(e2, phi) != 1:
            e2 = 5
            while MathUtils.gcd(e2, phi) != 1:
                e2 += 2
        d2 = MathUtils.mod_inverse(e2, phi)

        # Ensure e1 and e2 are coprime (required for external attack)
        while MathUtils.gcd(e1, e2) != 1:
            e2 += 2
            while MathUtils.gcd(e2, phi) != 1:
                e2 += 2
            d2 = MathUtils.mod_inverse(e2, phi)

        key1 = RSAKey(n=n, e=e1, d=d1, p=p, q=q)
        key2 = RSAKey(n=n, e=e2, d=d2, p=p, q=q)

        # Use a small integer message for this scenario
        message = 42
        c1 = RSAUtils.encrypt(message, n, e1)
        c2 = RSAUtils.encrypt(message, n, e2)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SHARED_MODULUS_EXTERNAL,
            description=f"Shared modulus N ({n.bit_length()} bits), e1={e1}, e2={e2} - external attacker with two ciphertexts",
            keys={"user1": key1, "user2": key2},
            messages={"user1": message, "user2": message},
            ciphertexts={"user1": c1, "user2": c2},
            seed=self.current_seed if self.current_seed is not None else random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_small_e_no_padding_scenario(self, scenario_id: str, bit_config: BitConfig) -> Scenario:
        """Create S8: Small e, no padding (cube root attack)."""
        # Generate modulus large enough to encrypt small message
        # Condition: M^e < N for cube root attack to work
        # For e=3 and M=42, we need N > 42^3 = 74088
        # Use bit_config.s_small_e_bits
        (n, e, d), (p, q) = RSAUtils.generate_keypair(
            bit_length=bit_config.s_small_e_bits,
            e=3,
            weak_config='small_e'
        )

        key = RSAKey(n=n, e=e, d=d, p=p, q=q)
        # Small message so that m^e < n; shrink until the condition holds
        # (always terminates: 1^e = 1 < n for any RSA modulus)
        message = 42
        while pow(message, e) >= n and message > 1:
            message -= 1

        ciphertext = RSAUtils.encrypt(message, n, e)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SMALL_E_NO_PADDING,
            description=f"Small e=3, no padding, M={message} - vulnerable to cube root attack",
            keys={"user1": key},
            messages={"user1": message},
            ciphertexts={"user1": ciphertext},
            seed=self.current_seed if self.current_seed is not None else random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_small_e_broadcast_scenario(self, scenario_id: str, bit_config: BitConfig) -> Scenario:
        """Create S9: Small e, broadcast (Hastad attack)."""
        e = 3
        messages = {}
        ciphertexts = {}
        keys = {}
        moduli = []

        # Generate all keys first so the shared message can be chosen to
        # satisfy m^e < n for EVERY modulus (Hastad requires the same m
        # under all moduli). weak_config='small_e' keeps e=3 by
        # regenerating primes when gcd(3, phi) != 1; without it,
        # generate_keypair silently bumps e and the stored (e, d) pair
        # would not match.
        for i in range(3):
            (n, key_e, d), (p, q) = RSAUtils.generate_keypair(
                bit_length=bit_config.s_small_e_bits,
                e=e,
                weak_config='small_e'
            )

            key = RSAKey(n=n, e=key_e, d=d, p=p, q=q)
            user_id = f"user{i+1}"
            keys[user_id] = key
            moduli.append(n)

        # Same message for all users; shrink it until m^e < every n
        message = 42
        min_n = min(moduli)
        while pow(message, e) >= min_n and message > 1:
            message -= 1

        for user_id, key in keys.items():
            messages[user_id] = message
            ciphertexts[user_id] = RSAUtils.encrypt(message, key.n, key.e)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SMALL_E_BROADCAST,
            description=f"Small e=3, broadcast M={message} to 3 users - Hastad attack",
            keys=keys,
            messages=messages,
            ciphertexts=ciphertexts,
            seed=self.current_seed if self.current_seed is not None else random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_shared_prime_scenario(self, scenario_id: str, bit_config: BitConfig) -> Scenario:
        """Create S10: Shared prime (GCD attack)."""
        # Generate shared prime (smaller for faster testing)
        shared_p = RSAUtils._generate_prime(bit_config.s10_p_bits)

        # Generate different q values
        q1 = RSAUtils._generate_prime(bit_config.s10_q_bits)
        q2 = RSAUtils._generate_prime(bit_config.s10_q_bits)
        while q2 == q1:
            q2 = RSAUtils._generate_prime(bit_config.s10_q_bits)

        n1 = shared_p * q1
        n2 = shared_p * q2

        e = 65537
        phi1 = (shared_p - 1) * (q1 - 1)
        phi2 = (shared_p - 1) * (q2 - 1)

        # Ensure e is coprime to both phis
        if MathUtils.gcd(e, phi1) != 1 or MathUtils.gcd(e, phi2) != 1:
            e = 3
            while MathUtils.gcd(e, phi1) != 1 or MathUtils.gcd(e, phi2) != 1:
                e += 2

        d1 = MathUtils.mod_inverse(e, phi1)
        d2 = MathUtils.mod_inverse(e, phi2)

        key1 = RSAKey(n=n1, e=e, d=d1, p=shared_p, q=q1)
        key2 = RSAKey(n=n2, e=e, d=d2, p=shared_p, q=q2)

        message = RSAUtils.message_to_int("Shared prime")
        c1 = RSAUtils.encrypt(message, n1, e)
        c2 = RSAUtils.encrypt(message, n2, e)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SHARED_PRIME,
            description=f"Shared prime p={shared_p} - vulnerable to GCD attack",
            keys={"user1": key1, "user2": key2},
            messages={"user1": message, "user2": message},
            ciphertexts={"user1": c1, "user2": c2},
            seed=self.current_seed if self.current_seed is not None else random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_pollards_rho_scenario(self, scenario_id: str, bit_config: BitConfig) -> Scenario:
        """Create S3: N has small prime factor (Pollard's rho)."""
        # Generate N with a small prime factor for Pollard's rho
        # Use bit_config.s3_p_bits for small prime and bit_config.s3_q_bits for larger prime
        small_p = RSAUtils._generate_prime(bit_config.s3_p_bits)
        q = RSAUtils._generate_prime(bit_config.s3_q_bits)
        n = small_p * q

        e = 65537
        phi = (small_p - 1) * (q - 1)

        # Ensure e and phi are coprime
        if MathUtils.gcd(e, phi) != 1:
            for e_candidate in [3, 5, 17, 257, 65537]:
                if MathUtils.gcd(e_candidate, phi) == 1:
                    e = e_candidate
                    break
            else:
                return self._create_pollards_rho_scenario(scenario_id, bit_config)

        d = MathUtils.mod_inverse(e, phi)

        key = RSAKey(n=n, e=e, d=d, p=small_p, q=q)
        message = RSAUtils.message_to_int("Pollard's rho")
        ciphertext = RSAUtils.encrypt(message, n, e)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.POLLARDS_RHO,
            description=f"N has small prime factor p={small_p} - vulnerable to Pollard's rho",
            keys={"user1": key},
            messages={"user1": message},
            ciphertexts={"user1": ciphertext},
            seed=self.current_seed if self.current_seed is not None else random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_pollards_p1_scenario(self, scenario_id: str, bit_config: BitConfig) -> Scenario:
        """Create S4: p-1 is B-smooth (Pollard's p-1)."""
        # p-1 must be B-smooth for Pollard's p-1. Build a RANDOM smooth
        # base M = product of small prime powers (~s4_p_bits bits) so that
        # p = M + 1 is prime. Per-prime exponents are capped so every prime
        # power dividing p-1 stays <= 10000 — the attack's largest B bound
        # (PollardsP1.B * max multiplier). Without the cap, combined
        # exponents (e.g. 2^15 | p-1) could exceed B and the attack fails.
        smooth_primes = [2, 3, 5, 7, 11, 13, 17, 19]
        max_exp = {2: 13, 3: 8, 5: 5, 7: 4, 11: 3, 13: 3, 17: 3, 19: 3}
        p = None

        for _attempt in range(2000):
            need = bit_config.s4_p_bits
            M = 2  # factor 2 keeps p = M + 1 odd
            exponents = {r: 1 if r == 2 else 0 for r in smooth_primes}
            picks = 0

            while M.bit_length() < need and picks < 500:
                picks += 1
                r = random.choice(smooth_primes)
                e = random.randint(1, 3)
                if exponents[r] + e > max_exp[r]:
                    continue
                exponents[r] += e
                M *= r ** e

            # Reject M that undershot (exponent caps hit) or overshot
            # the target size, then test p = M + 1 for primality.
            if not (need <= M.bit_length() <= need + 4):
                continue

            if MathUtils.is_prime(M + 1):
                p = M + 1
                break

        if p is None:
            raise RuntimeError(
                "Failed to generate B-smooth p for S4; try larger s4_p_bits"
            )

        # Generate q normally (not B-smooth)
        q = RSAUtils._generate_prime(bit_config.s4_q_bits)
        while q == p:
            q = RSAUtils._generate_prime(bit_config.s4_q_bits)

        n = p * q
        e = 65537
        phi = (p - 1) * (q - 1)

        # Ensure e and phi are coprime
        if MathUtils.gcd(e, phi) != 1:
            for e_candidate in [3, 5, 17, 257, 65537]:
                if MathUtils.gcd(e_candidate, phi) == 1:
                    e = e_candidate
                    break
            else:
                return self._create_pollards_p1_scenario(scenario_id, bit_config)

        d = MathUtils.mod_inverse(e, phi)

        key = RSAKey(n=n, e=e, d=d, p=p, q=q)
        message = RSAUtils.message_to_int("Pollard's p-1")
        ciphertext = RSAUtils.encrypt(message, n, e)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.POLLARDS_P1,
            description=f"p-1 is B-smooth (p={p}, {p.bit_length()} bits) - vulnerable to Pollard's p-1",
            keys={"user1": key},
            messages={"user1": message},
            ciphertexts={"user1": ciphertext},
            seed=self.current_seed if self.current_seed is not None else random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def get_scenario(self, scenario_id: str) -> Optional[Scenario]:
        """
        Retrieve a scenario by ID.

        Args:
            scenario_id: Scenario identifier

        Returns:
            Scenario object if found, None otherwise
        """
        return self.scenarios.get(scenario_id)

    def list_scenarios(self) -> List[str]:
        """
        List all available scenario IDs.

        Returns:
            List of scenario IDs
        """
        return list(self.scenarios.keys())

    def verify_private_key(
        self,
        scenario_id: str,
        user_id: str,
        proposed_d: int
    ) -> bool:
        """
        Verify if a proposed private key is correct.

        Args:
            scenario_id: Scenario identifier
            user_id: User identifier
            proposed_d: Proposed private exponent

        Returns:
            True if the key is correct
        """
        scenario = self.get_scenario(scenario_id)
        if scenario is None:
            return False

        key = scenario.keys.get(user_id)
        if key is None or key.d is None:
            return False

        return key.d == proposed_d

    def verify_message(
        self,
        scenario_id: str,
        user_id: str,
        proposed_message: int
    ) -> bool:
        """
        Verify if a proposed message is correct.

        Args:
            scenario_id: Scenario identifier
            user_id: User identifier
            proposed_message: Proposed message

        Returns:
            True if the message is correct
        """
        scenario = self.get_scenario(scenario_id)
        if scenario is None:
            return False

        message = scenario.messages.get(user_id)
        if message is None:
            return False

        return message == proposed_message
