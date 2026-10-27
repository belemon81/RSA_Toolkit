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
    SMALL_D = "S3"  # Small private exponent d
    SHARED_MODULUS_INTERNAL = "S4"  # Shared modulus (internal attacker)
    SHARED_MODULUS_EXTERNAL = "S5"  # Shared modulus (external attacker)
    SMALL_E_NO_PADDING = "S6"  # Small e, no padding
    SMALL_E_BROADCAST = "S7"  # Small e, broadcast attack
    SHARED_PRIME = "S8"  # Shared prime factor (GCD attack)
    SMALL_D_EXTENDED = "S9"  # Very small d for Wiener


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
    - S3: Small d (Wiener attack)
    - S4: Shared modulus (internal attacker)
    - S5: Shared modulus (external attacker)
    - S6: Small e, no padding (cube root attack)
    - S7: Small e, broadcast (Hastad attack)
    - S8: Shared prime (GCD attack)
    - S9: Very small d (extended Wiener)
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
        elif scenario_type == ScenarioType.SMALL_D:
            return self._create_small_d_scenario(scenario_id)
        elif scenario_type == ScenarioType.SHARED_MODULUS_INTERNAL:
            return self._create_shared_modulus_internal_scenario(scenario_id)
        elif scenario_type == ScenarioType.SHARED_MODULUS_EXTERNAL:
            return self._create_shared_modulus_external_scenario(scenario_id)
        elif scenario_type == ScenarioType.SMALL_E_NO_PADDING:
            return self._create_small_e_no_padding_scenario(scenario_id)
        elif scenario_type == ScenarioType.SMALL_E_BROADCAST:
            return self._create_small_e_broadcast_scenario(scenario_id)
        elif scenario_type == ScenarioType.SHARED_PRIME:
            return self._create_shared_prime_scenario(scenario_id)
        elif scenario_type == ScenarioType.SMALL_D_EXTENDED:
            return self._create_small_d_extended_scenario(scenario_id)
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
        """Create S1: Small modulus (< 64 bits)."""
        (n, e, d), (p, q) = RSAUtils.generate_keypair(
            bit_length=48,
            e=65537,
            weak_config='small_modulus'
        )

        key = RSAKey(n=n, e=e, d=d, p=p, q=q)
        message = RSAUtils.message_to_int("Hi")
        ciphertext = RSAUtils.encrypt(message, n, e)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SMALL_MODULUS,
            description="Small modulus (48 bits) - vulnerable to brute force",
            keys={"user1": key},
            messages={"user1": message},
            ciphertexts={"user1": ciphertext},
            seed=self.current_seed or random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_close_primes_scenario(self, scenario_id: str) -> Scenario:
        """Create S2: Close primes (Fermat factorization)."""
        (n, e, d), (p, q) = RSAUtils.generate_keypair(
            bit_length=128,
            e=65537,
            weak_config='close_primes'
        )

        key = RSAKey(n=n, e=e, d=d, p=p, q=q)
        message = RSAUtils.message_to_int("Close primes")
        ciphertext = RSAUtils.encrypt(message, n, e)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.CLOSE_PRIMES,
            description="Close primes - vulnerable to Fermat factorization",
            keys={"user1": key},
            messages={"user1": message},
            ciphertexts={"user1": ciphertext},
            seed=self.current_seed or random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_small_d_scenario(self, scenario_id: str) -> Scenario:
        """Create S3: Small d (Wiener attack)."""
        (n, e, d), (p, q) = RSAUtils.generate_keypair(
            bit_length=128,
            e=65537,
            weak_config='small_d'
        )

        key = RSAKey(n=n, e=e, d=d, p=p, q=q)
        message = RSAUtils.message_to_int("Small d")
        ciphertext = RSAUtils.encrypt(message, n, e)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SMALL_D,
            description="Small private exponent d - vulnerable to Wiener attack",
            keys={"user1": key},
            messages={"user1": message},
            ciphertexts={"user1": ciphertext},
            seed=self.current_seed or random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_shared_modulus_internal_scenario(self, scenario_id: str) -> Scenario:
        """Create S4: Shared modulus (internal attacker)."""
        # Generate shared modulus
        (n, e1, d1), (p, q) = RSAUtils.generate_keypair(bit_length=128, e=65537)

        # Compute second private key with different e
        e2 = 17
        phi = (p - 1) * (q - 1)
        d2 = MathUtils.mod_inverse(e2, phi)

        key1 = RSAKey(n=n, e=e1, d=d1, p=p, q=q)
        key2 = RSAKey(n=n, e=e2, d=d2, p=p, q=q)

        message = RSAUtils.message_to_int("Shared modulus internal")
        c1 = RSAUtils.encrypt(message, n, e1)
        c2 = RSAUtils.encrypt(message, n, e2)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SHARED_MODULUS_INTERNAL,
            description="Shared modulus - internal attacker knows one private key",
            keys={"attacker": key1, "victim": key2},
            messages={"attacker": message, "victim": message},
            ciphertexts={"attacker": c1, "victim": c2},
            seed=self.current_seed or random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_shared_modulus_external_scenario(self, scenario_id: str) -> Scenario:
        """Create S5: Shared modulus (external attacker)."""
        (n, e1, d1), (p, q) = RSAUtils.generate_keypair(bit_length=128, e=17)
        e2 = 65537
        phi = (p - 1) * (q - 1)
        d2 = MathUtils.mod_inverse(e2, phi)

        key1 = RSAKey(n=n, e=e1, d=d1, p=p, q=q)
        key2 = RSAKey(n=n, e=e2, d=d2, p=p, q=q)

        message = RSAUtils.message_to_int("Shared modulus external")
        c1 = RSAUtils.encrypt(message, n, e1)
        c2 = RSAUtils.encrypt(message, n, e2)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SHARED_MODULUS_EXTERNAL,
            description="Shared modulus - external attacker with two ciphertexts",
            keys={"user1": key1, "user2": key2},
            messages={"user1": message, "user2": message},
            ciphertexts={"user1": c1, "user2": c2},
            seed=self.current_seed or random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_small_e_no_padding_scenario(self, scenario_id: str) -> Scenario:
        """Create S6: Small e, no padding (cube root attack)."""
        (n, e, d), (p, q) = RSAUtils.generate_keypair(
            bit_length=128,
            e=3,
            weak_config='small_e'
        )

        key = RSAKey(n=n, e=e, d=d, p=p, q=q)
        # Small message so that m^e < n
        message = 42
        ciphertext = RSAUtils.encrypt(message, n, e)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SMALL_E_NO_PADDING,
            description="Small e=3, no padding - vulnerable to cube root attack",
            keys={"user1": key},
            messages={"user1": message},
            ciphertexts={"user1": ciphertext},
            seed=self.current_seed or random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_small_e_broadcast_scenario(self, scenario_id: str) -> Scenario:
        """Create S7: Small e, broadcast (Hastad attack)."""
        e = 3
        messages = {}
        ciphertexts = {}
        keys = {}

        for i in range(3):
            (n, _, d), (p, q) = RSAUtils.generate_keypair(bit_length=128, e=e)
            key = RSAKey(n=n, e=e, d=d, p=p, q=q)
            message = RSAUtils.message_to_int("Broadcast")
            ciphertext = RSAUtils.encrypt(message, n, e)

            user_id = f"user{i+1}"
            keys[user_id] = key
            messages[user_id] = message
            ciphertexts[user_id] = ciphertext

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SMALL_E_BROADCAST,
            description="Small e=3, broadcast to 3 users - Hastad attack",
            keys=keys,
            messages=messages,
            ciphertexts=ciphertexts,
            seed=self.current_seed or random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_shared_prime_scenario(self, scenario_id: str) -> Scenario:
        """Create S8: Shared prime (GCD attack)."""
        # Generate shared prime
        shared_p = RSAUtils._generate_prime(32)

        # Generate different q values
        q1 = RSAUtils._generate_prime(32)
        q2 = RSAUtils._generate_prime(32)

        n1 = shared_p * q1
        n2 = shared_p * q2

        e = 65537
        phi1 = (shared_p - 1) * (q1 - 1)
        phi2 = (shared_p - 1) * (q2 - 1)

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
            description="Shared prime factor - vulnerable to GCD attack",
            keys={"user1": key1, "user2": key2},
            messages={"user1": message, "user2": message},
            ciphertexts={"user1": c1, "user2": c2},
            seed=self.current_seed or random.randint(0, 2**32)
        )

        self.scenarios[scenario_id] = scenario
        return scenario

    def _create_small_d_extended_scenario(self, scenario_id: str) -> Scenario:
        """Create S9: Very small d (extended Wiener)."""
        (n, e, d), (p, q) = RSAUtils.generate_keypair(
            bit_length=256,
            e=65537,
            weak_config='small_d'
        )

        key = RSAKey(n=n, e=e, d=d, p=p, q=q)
        message = RSAUtils.message_to_int("Very small d")
        ciphertext = RSAUtils.encrypt(message, n, e)

        scenario = Scenario(
            scenario_id=scenario_id,
            scenario_type=ScenarioType.SMALL_D_EXTENDED,
            description="Very small d - extended Wiener attack",
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
