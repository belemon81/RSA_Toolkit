"""
Tests for scenario manager.
"""

import pytest
from rsa_toolkit.server.scenario_manager import ScenarioManager, ScenarioType


class TestScenarioManager:
    """Test suite for ScenarioManager class."""

    def test_create_secure_scenario(self):
        """Test creating secure scenario."""
        manager = ScenarioManager()
        scenario = manager.create_scenario(ScenarioType.SECURE)

        assert scenario.scenario_type == ScenarioType.SECURE
        assert "user1" in scenario.keys
        assert len(scenario.keys) == 1
        assert scenario.keys["user1"].n.bit_length() == 2048
        assert scenario.keys["user1"].e == 65537

    def test_create_small_modulus_scenario(self):
        """Test creating small modulus scenario."""
        manager = ScenarioManager()
        scenario = manager.create_scenario(ScenarioType.SMALL_MODULUS)

        assert scenario.scenario_type == ScenarioType.SMALL_MODULUS
        assert scenario.keys["user1"].n.bit_length() <= 64

    def test_create_close_primes_scenario(self):
        """Test creating close primes scenario."""
        manager = ScenarioManager()
        scenario = manager.create_scenario(ScenarioType.CLOSE_PRIMES)

        assert scenario.scenario_type == ScenarioType.CLOSE_PRIMES
        p = scenario.keys["user1"].p
        q = scenario.keys["user1"].q
        assert abs(p - q) < 10000

    def test_create_pollards_rho_scenario(self):
        """Test creating Pollard's rho scenario."""
        manager = ScenarioManager()
        scenario = manager.create_scenario(ScenarioType.POLLARDS_RHO)

        assert scenario.scenario_type == ScenarioType.POLLARDS_RHO
        n = scenario.keys["user1"].n
        # Check that N has a small factor (vulnerable to Pollard's rho)
        p = scenario.keys["user1"].p
        q = scenario.keys["user1"].q
        assert p.bit_length() <= 20  # Small prime

    def test_create_pollards_p1_scenario(self):
        """Test creating Pollard's p-1 scenario."""
        manager = ScenarioManager()
        scenario = manager.create_scenario(ScenarioType.POLLARDS_P1)

        assert scenario.scenario_type == ScenarioType.POLLARDS_P1
        p = scenario.keys["user1"].p
        # Check that p-1 has small factors (is B-smooth)
        p_minus_1 = p - 1
        assert p_minus_1 % 2 == 0  # Even
        # Should be divisible by at least some small primes
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
        has_small_factor = any(p_minus_1 % prime == 0 for prime in small_primes)
        assert has_small_factor

    def test_create_shared_modulus_internal_scenario(self):
        """Test creating shared modulus internal scenario."""
        manager = ScenarioManager()
        scenario = manager.create_scenario(ScenarioType.SHARED_MODULUS_INTERNAL)

        assert scenario.scenario_type == ScenarioType.SHARED_MODULUS_INTERNAL
        assert "attacker" in scenario.keys
        assert "victim" in scenario.keys

        # Check that modulus is shared
        n_attacker = scenario.keys["attacker"].n
        n_victim = scenario.keys["victim"].n
        assert n_attacker == n_victim

    def test_create_shared_modulus_external_scenario(self):
        """Test creating shared modulus external scenario."""
        manager = ScenarioManager()
        scenario = manager.create_scenario(ScenarioType.SHARED_MODULUS_EXTERNAL)

        assert scenario.scenario_type == ScenarioType.SHARED_MODULUS_EXTERNAL
        assert "user1" in scenario.keys
        assert "user2" in scenario.keys

        # Check that modulus is shared
        n1 = scenario.keys["user1"].n
        n2 = scenario.keys["user2"].n
        assert n1 == n2

    def test_create_small_d_scenario(self):
        """Test creating small d scenario."""
        manager = ScenarioManager()
        scenario = manager.create_scenario(ScenarioType.SMALL_D)

        assert scenario.scenario_type == ScenarioType.SMALL_D
        d = scenario.keys["user1"].d
        assert d is not None

    def test_create_small_e_no_padding_scenario(self):
        """Test creating small e no padding scenario."""
        manager = ScenarioManager()
        scenario = manager.create_scenario(ScenarioType.SMALL_E_NO_PADDING)

        assert scenario.scenario_type == ScenarioType.SMALL_E_NO_PADDING
        # e should be small (3, 5, or 17 if 3 is not coprime with phi)
        assert scenario.keys["user1"].e in [3, 5, 17]

    def test_create_small_e_broadcast_scenario(self):
        """Test creating small e broadcast scenario."""
        manager = ScenarioManager()
        scenario = manager.create_scenario(ScenarioType.SMALL_E_BROADCAST)

        assert scenario.scenario_type == ScenarioType.SMALL_E_BROADCAST
        assert len(scenario.keys) >= 3

        # All should have e=3
        for key in scenario.keys.values():
            assert key.e == 3

    def test_create_shared_prime_scenario(self):
        """Test creating shared prime scenario."""
        manager = ScenarioManager()
        scenario = manager.create_scenario(ScenarioType.SHARED_PRIME)

        assert scenario.scenario_type == ScenarioType.SHARED_PRIME
        assert "user1" in scenario.keys
        assert "user2" in scenario.keys

        # Check that they share a prime
        from rsa_toolkit.utils.math_utils import MathUtils
        n1 = scenario.keys["user1"].n
        n2 = scenario.keys["user2"].n
        g = MathUtils.gcd(n1, n2)
        assert g > 1 and g < n1

    def test_get_scenario(self):
        """Test retrieving a scenario."""
        manager = ScenarioManager()
        created = manager.create_scenario(ScenarioType.SECURE)

        retrieved = manager.get_scenario(created.scenario_id)
        assert retrieved is not None
        assert retrieved.scenario_id == created.scenario_id

    def test_list_scenarios(self):
        """Test listing scenarios."""
        manager = ScenarioManager()
        manager.create_scenario(ScenarioType.SECURE)
        manager.create_scenario(ScenarioType.SMALL_MODULUS)

        scenarios = manager.list_scenarios()
        assert len(scenarios) == 2

    def test_verify_private_key(self):
        """Test private key verification."""
        manager = ScenarioManager()
        scenario = manager.create_scenario(ScenarioType.SECURE)

        user_id = "user1"
        correct_d = scenario.keys[user_id].d

        # Correct key
        assert manager.verify_private_key(scenario.scenario_id, user_id, correct_d) is True

        # Incorrect key
        assert manager.verify_private_key(scenario.scenario_id, user_id, correct_d + 1) is False

    def test_verify_message(self):
        """Test message verification."""
        manager = ScenarioManager()
        scenario = manager.create_scenario(ScenarioType.SECURE)

        user_id = "user1"
        correct_message = scenario.messages[user_id]

        # Correct message
        assert manager.verify_message(scenario.scenario_id, user_id, correct_message) is True

        # Incorrect message
        assert manager.verify_message(scenario.scenario_id, user_id, correct_message + 1) is False

    def test_reproducible_with_seed(self):
        """Test that scenarios are reproducible with seed."""
        manager1 = ScenarioManager()
        manager1.set_seed(12345)
        scenario1 = manager1.create_scenario(ScenarioType.SECURE)

        manager2 = ScenarioManager()
        manager2.set_seed(12345)
        scenario2 = manager2.create_scenario(ScenarioType.SECURE)

        # Should produce same keys
        assert scenario1.keys["user1"].n == scenario2.keys["user1"].n
        assert scenario1.keys["user1"].e == scenario2.keys["user1"].e
