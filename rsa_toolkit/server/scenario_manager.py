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


class ScenarioManager:
    """
    Manager for creating and managing attack scenarios.

    Implements the scenarios described in the report:
    - S0: Secure configuration (2048-bit, e=65537, OAEP padding)
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
        seed: Optional[int] = None
    ) -> Scenario:
        """
        Create a specific attack scenario.

        Args:
            scenario_type: Type of scenario to create
            seed: Optional seed for reproducibility

        Returns:
            Created Scenario object
        """
        if seed is not None:
            self.set_seed(seed)

        scenario_id = f"{scenario_type.value}_{random.randint(1000, 9999)}"

        if scenario_type == ScenarioType.SECURE:
            return self._create_secure_scenario(scenario_id)
        elif scenario_type == ScenarioType.SMALL_MODULUS:
            return self._create_small_modulus_scenario(scenario_id)
        elif scenario_type == ScenarioType.CLOSE_PRIMES:
            return self._create_close_primes_scenario(scenario_id)
        elif scenario_type == ScenarioType.POLLARDS_RHO:
            return self._create_pollards_rho_scenario(scenario_id)
        elif scenario_type == ScenarioType.POLLARDS_P1:
            return self._create_pollards_p1_scenario(scenario_id)
        elif scenario_type == ScenarioType.SHARED_MODULUS_INTERNAL:
            return self._create_shared_modulus_internal_scenario(scenario_id)
        elif scenario_type == ScenarioType.SHARED_MODULUS_EXTERNAL:
            return self._create_shared_modulus_external_scenario(scenario_id)
        elif scenario_type == ScenarioType.SMALL_D:
            return self._create_small_d_scenario(scenario_id)
        elif scenario_type == ScenarioType.SMALL_E_NO_PADDING:
            return self._create_small_e_no_padding_scenario(scenario_id)
        elif scenario_type == ScenarioType.SMALL_E_BROADCAST:
            return self._create_small_e_broadcast_scenario(scenario_id)
        elif scenario_type == ScenarioType.SHARED_PRIME:
            return self._create_shared_prime_scenario(scenario_id)
        else:
            raise ValueError(f"Unknown scenario type: {scenario_type}")

    def _create_secure_scenario(self, scenario_id: str) -> Scenario:
        """Create S0: Secure configuration."""
        (n, e, d), (p, q) = RSAUtils.generate_keypair(bit_length=2048, e=65537)

        key = RSAKey(n=n, e=e, d=d, p=p, q=q)
        message = RSAUtils.message_to_int("This is a secure message")
        ciphertext = RSAUtils.encrypt(message, n, e)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SECURE,
            description="Secure RSA configuration (2048-bit, e=65537)",
            keys={"user1": key},
            messages={"user1": message},
            ciphertexts={"user1": ciphertext},
            seed=self.current_seed or random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_small_modulus_scenario(self, scenario_id: str) -> Scenario:
        """Create S1: Small modulus (< 64 bits) with small prime factors."""
        # Generate modulus with one small prime factor for easier brute force
        # Use a small prime p (e.g., around 20 bits) and a larger q
        small_p = RSAUtils._generate_prime(20)  # ~20 bits (~1 million)
        q = RSAUtils._generate_prime(28)  # ~28 bits (~268 million)
        n = small_p * q  # ~48 bits total

        e = 65537
        phi = (small_p - 1) * (q - 1)

        # Ensure e and phi are coprime
        if MathUtils.gcd(e, phi) != 1:
            # Try different e values
            for e_candidate in [3, 5, 17, 257, 65537]:
                if MathUtils.gcd(e_candidate, phi) == 1:
                    e = e_candidate
                    break
            else:
                # Regenerate if no suitable e found
                return self._create_small_modulus_scenario(scenario_id)

        d = MathUtils.mod_inverse(e, phi)

        key = RSAKey(n=n, e=e, d=d, p=small_p, q=q)
        message = RSAUtils.message_to_int("Hi")
        ciphertext = RSAUtils.encrypt(message, n, e)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SMALL_MODULUS,
            description=f"Small modulus ({n.bit_length()} bits) with small prime factor - vulnerable to brute force",
            keys={"user1": key},
            messages={"user1": message},
            ciphertexts={"user1": ciphertext},
            seed=self.current_seed or random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_close_primes_scenario(self, scenario_id: str) -> Scenario:
        """Create S2: Close primes (Fermat factorization)."""
        # Generate p and q very close together for Fermat factorization
        # Start with a base prime, then generate q very close to p
        p = RSAUtils._generate_prime(64)  # ~64 bits
        # Generate q within a small range (e.g., offset < 10000)
        # offset must be EVEN so that q = p + offset stays odd (p is odd);
        # an odd offset would make q even and the primality loop never ends.
        offset = random.randint(1, 5000) * 2
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
                return self._create_close_primes_scenario(scenario_id)

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
            seed=self.current_seed or random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_small_d_scenario(self, scenario_id: str) -> Scenario:
        """Create S7: Small d (Wiener attack)."""
        # Wiener's attack condition: d < N^(1/4) / 3
        # Correct construction: choose a SMALL d first, then compute
        # e = d^{-1} mod phi(N). This makes e large while d stays small,
        # which is exactly the vulnerable configuration Wiener exploits.
        # (Choosing small e and deriving d = e^{-1} mod phi yields a LARGE d
        #  and is NOT vulnerable to Wiener.)

        import gmpy2

        # Two 16-bit primes -> N ~ 32 bits -> N^(1/4)/3 ~ 85
        while True:
            p = RSAUtils._generate_prime(16)
            q = RSAUtils._generate_prime(16)
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
                        seed=self.current_seed or random.randint(0, 2**32)
                    )

                    self.scenarios[scenario_id] = scenario
                    return scenario

    def _create_shared_modulus_internal_scenario(self, scenario_id: str) -> Scenario:
        """Create S5: Shared modulus (internal attacker)."""
        # Generate shared modulus with small primes for easier factorization
        # This allows the "attacker" to factorize and get their own d
        p = RSAUtils._generate_prime(20)  # ~20 bits
        q = RSAUtils._generate_prime(20)  # ~20 bits
        while q == p:
            q = RSAUtils._generate_prime(20)

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
            while MathUtils.gcd(e2, phi) != 1 and e2 < 100:
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
            seed=self.current_seed or random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_shared_modulus_external_scenario(self, scenario_id: str) -> Scenario:
        """Create S6: Shared modulus (external attacker)."""
        # Generate shared modulus with small primes
        p = RSAUtils._generate_prime(20)  # ~20 bits
        q = RSAUtils._generate_prime(20)  # ~20 bits
        while q == p:
            q = RSAUtils._generate_prime(20)

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
            while MathUtils.gcd(e2, phi) != 1 and e2 < 100:
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
            seed=self.current_seed or random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_small_e_no_padding_scenario(self, scenario_id: str) -> Scenario:
        """Create S8: Small e, no padding (cube root attack)."""
        # Generate modulus large enough to encrypt small message
        # Condition: M^e < N for cube root attack to work
        # For e=3 and M=42, we need N > 42^3 = 74088
        # Use larger N to be safe, e.g., 128 bits
        (n, e, d), (p, q) = RSAUtils.generate_keypair(
            bit_length=128,
            e=3,
            weak_config='small_e'
        )

        key = RSAKey(n=n, e=e, d=d, p=p, q=q)
        # Small message so that m^e < n
        message = 42
        # Verify condition
        if pow(message, e) >= n:
            # If condition not met, try smaller message
            message = 2
            while pow(message, e) >= n and message < 100:
                message += 1

        ciphertext = RSAUtils.encrypt(message, n, e)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SMALL_E_NO_PADDING,
            description=f"Small e=3, no padding, M={message} - vulnerable to cube root attack",
            keys={"user1": key},
            messages={"user1": message},
            ciphertexts={"user1": ciphertext},
            seed=self.current_seed or random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_small_e_broadcast_scenario(self, scenario_id: str) -> Scenario:
        """Create S9: Small e, broadcast (Hastad attack)."""
        e = 3
        messages = {}
        ciphertexts = {}
        keys = {}

        # Use the same message for all users
        message = 42  # Small integer for Hastad's attack

        for i in range(3):
            # Generate modulus large enough so that M^e < each N_i
            # For e=3 and M=42, need N > 74088
            (n, _, d), (p, q) = RSAUtils.generate_keypair(bit_length=128, e=e)

            # Verify condition for Hastad's attack
            if pow(message, e) >= n:
                # If condition not met, try smaller message
                temp_message = 2
                while pow(temp_message, e) >= n and temp_message < 100:
                    temp_message += 1
                message = temp_message  # Update message for all users

            key = RSAKey(n=n, e=e, d=d, p=p, q=q)
            ciphertext = RSAUtils.encrypt(message, n, e)

            user_id = f"user{i+1}"
            keys[user_id] = key
            messages[user_id] = message
            ciphertexts[user_id] = ciphertext

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SMALL_E_BROADCAST,
            description=f"Small e=3, broadcast M={message} to 3 users - Hastad attack",
            keys=keys,
            messages=messages,
            ciphertexts=ciphertexts,
            seed=self.current_seed or random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_shared_prime_scenario(self, scenario_id: str) -> Scenario:
        """Create S10: Shared prime (GCD attack)."""
        # Generate shared prime (smaller for faster testing)
        shared_p = RSAUtils._generate_prime(20)  # ~20 bits

        # Generate different q values
        q1 = RSAUtils._generate_prime(20)  # ~20 bits
        q2 = RSAUtils._generate_prime(20)  # ~20 bits
        while q2 == q1:
            q2 = RSAUtils._generate_prime(20)

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
            seed=self.current_seed or random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_pollards_rho_scenario(self, scenario_id: str) -> Scenario:
        """Create S3: N has small prime factor (Pollard's rho)."""
        # Generate N with a small prime factor for Pollard's rho
        # Use a very small prime (e.g., 16-20 bits) and a larger prime
        small_p = RSAUtils._generate_prime(18)  # Small prime (~18 bits, ~262k)
        q = RSAUtils._generate_prime(46)  # Larger prime (~46 bits, ~70 trillion)
        n = small_p * q  # ~64 bits total

        e = 65537
        phi = (small_p - 1) * (q - 1)

        # Ensure e and phi are coprime
        if MathUtils.gcd(e, phi) != 1:
            for e_candidate in [3, 5, 17, 257, 65537]:
                if MathUtils.gcd(e_candidate, phi) == 1:
                    e = e_candidate
                    break
            else:
                return self._create_pollards_rho_scenario(scenario_id)

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
            seed=self.current_seed or random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_pollards_p1_scenario(self, scenario_id: str) -> Scenario:
        """Create S4: p-1 and q-1 have small factors (Pollard's p-1)."""
        # Generate p where p-1 is B-smooth (has only small prime factors)
        # Use a simpler approach: construct p-1 directly from small primes
        primes = [2, 3, 5, 7, 11, 13]
        p_minus_1 = 1
        for prime in primes:
            p_minus_1 *= prime  # p-1 = 2*3*5*7*11*13 = 30030

        # Find a prime p of the form k * product + 1
        k = 1
        max_attempts = 10000
        attempts = 0
        p = None
        while attempts < max_attempts:
            candidate = k * p_minus_1 + 1
            if MathUtils.is_prime(candidate):
                p = candidate
                break
            k += 1
            attempts += 1

        if p is None:
            # Fallback: use a different set of primes
            primes = [2, 3, 5, 7, 11]
            p_minus_1 = 1
            for prime in primes:
                p_minus_1 *= prime
            k = 1
            while attempts < max_attempts * 2:
                candidate = k * p_minus_1 + 1
                if MathUtils.is_prime(candidate):
                    p = candidate
                    break
                k += 1
                attempts += 1

        if p is None:
            # Last fallback: generate normal primes
            p = RSAUtils._generate_prime(32)
            q = RSAUtils._generate_prime(32)
            while q == p:
                q = RSAUtils._generate_prime(32)
        else:
            # Generate q normally (not B-smooth)
            q = RSAUtils._generate_prime(32)
            while q == p:
                q = RSAUtils._generate_prime(32)

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
                return self._create_pollards_p1_scenario(scenario_id)

        d = MathUtils.mod_inverse(e, phi)

        key = RSAKey(n=n, e=e, d=d, p=p, q=q)
        message = RSAUtils.message_to_int("Pollard's p-1")
        ciphertext = RSAUtils.encrypt(message, n, e)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.POLLARDS_P1,
            description=f"p-1 constructed from small primes - vulnerable to Pollard's p-1",
            keys={"user1": key},
            messages={"user1": message},
            ciphertexts={"user1": ciphertext},
            seed=self.current_seed or random.randint(0, 2**32)
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
