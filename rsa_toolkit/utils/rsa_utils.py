"""
RSA utility functions for key generation, encryption, and decryption.
"""

import random
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import gmpy2

from rsa_toolkit.utils.math_utils import MathUtils


class RSAUtils:
    """Utility class for RSA operations."""

    @staticmethod
    def generate_keypair(
        bit_length: int = 2048,
        e: int = 65537,
        weak_config: Optional[str] = None
    ) -> Tuple[Tuple[int, int, int], Tuple[int, int]]:
        """
        Generate RSA keypair with optional weak configurations for testing.

        Args:
            bit_length: Bit length of modulus N
            e: Public exponent
            weak_config: Type of weak configuration:
                - 'small_modulus': Generate small modulus (< 64 bits)
                - 'close_primes': Generate p and q very close together
                - 'small_d': Generate small private exponent d
                - 'shared_prime': Share a prime factor (requires context)
                - 'small_e': Use small public exponent (e=3)
                - None: Generate secure keypair

        Returns:
            Tuple of ((n, e, d), (p, q)) where (n, e, d) is public/private key,
            and (p, q) are the prime factors
        """
        if weak_config == 'small_modulus':
            # Generate small modulus for brute force testing
            bit_length = min(bit_length, 64)
        elif weak_config == 'small_e':
            e = 3

        # Generate primes
        if weak_config == 'close_primes':
            # Generate p and q very close together
            p = RSAUtils._generate_prime(bit_length // 2)
            # Generate q close to p
            offset = random.randint(1, 10000)
            q = p + offset
            while not MathUtils.is_prime(q):
                q += 2
        elif weak_config == 'small_d':
            # Generate small d by using small p and q
            p = RSAUtils._generate_prime(20)
            q = RSAUtils._generate_prime(20)
            while q == p:
                q = RSAUtils._generate_prime(20)
        else:
            # Normal secure generation
            p = RSAUtils._generate_prime(bit_length // 2)
            q = RSAUtils._generate_prime(bit_length // 2)
            while q == p:
                q = RSAUtils._generate_prime(bit_length // 2)

        # Ensure p < q
        if p > q:
            p, q = q, p

        n = p * q
        phi = (p - 1) * (q - 1)

        # Ensure e and phi are coprime
        if MathUtils.gcd(e, phi) != 1:
            # Try different e values
            for e_candidate in [3, 5, 17, 257, 65537]:
                if MathUtils.gcd(e_candidate, phi) == 1:
                    e = e_candidate
                    break
            else:
                # Regenerate primes if no suitable e found
                return RSAUtils.generate_keypair(bit_length, e, weak_config)

        d = MathUtils.mod_inverse(e, phi)

        return ((n, e, d), (p, q))

    @staticmethod
    def _generate_prime(bit_length: int) -> int:
        """
        Generate a prime number of specified bit length.

        Args:
            bit_length: Desired bit length

        Returns:
            Prime number
        """
        while True:
            # Generate random odd number
            candidate = random.getrandbits(bit_length)
            candidate |= (1 << (bit_length - 1)) | 1  # Ensure MSB is set and number is odd

            if MathUtils.is_prime(candidate):
                return candidate

    @staticmethod
    def encrypt(message: int, n: int, e: int) -> int:
        """
        Encrypt a message using RSA.

        Args:
            message: Plaintext message as integer
            n: Modulus
            e: Public exponent

        Returns:
            Ciphertext as integer
        """
        return pow(message, e, n)

    @staticmethod
    def decrypt(ciphertext: int, n: int, d: int) -> int:
        """
        Decrypt a ciphertext using RSA.

        Args:
            ciphertext: Ciphertext as integer
            n: Modulus
            d: Private exponent

        Returns:
            Plaintext message as integer
        """
        return pow(ciphertext, d, n)

    @staticmethod
    def encrypt_with_oaep(message: bytes, public_key) -> bytes:
        """
        Encrypt message using RSA-OAEP padding (secure).

        Args:
            message: Plaintext message as bytes
            public_key: RSA public key object

        Returns:
            Ciphertext as bytes
        """
        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    @staticmethod
    def decrypt_with_oaep(ciphertext: bytes, private_key) -> bytes:
        """
        Decrypt message using RSA-OAEP padding (secure).

        Args:
            ciphertext: Ciphertext as bytes
            private_key: RSA private key object

        Returns:
            Plaintext message as bytes
        """
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    @staticmethod
    def message_to_int(message: str, encoding: str = 'utf-8') -> int:
        """
        Convert string message to integer.

        Args:
            message: String message
            encoding: Character encoding

        Returns:
            Integer representation
        """
        return int.from_bytes(message.encode(encoding), 'big')

    @staticmethod
    def int_to_message(message_int: int, encoding: str = 'utf-8') -> str:
        """
        Convert integer to string message.

        Args:
            message_int: Integer representation
            encoding: Character encoding

        Returns:
            String message
        """
        # Calculate number of bytes needed
        byte_length = (message_int.bit_length() + 7) // 8
        message_bytes = message_int.to_bytes(byte_length, 'big')
        return message_bytes.decode(encoding)

    @staticmethod
    def validate_keypair(n: int, e: int, d: int) -> bool:
        """
        Validate RSA keypair by testing encryption/decryption.

        Args:
            n: Modulus
            e: Public exponent
            d: Private exponent

        Returns:
            True if keypair is valid
        """
        test_message = 42
        encrypted = RSAUtils.encrypt(test_message, n, e)
        decrypted = RSAUtils.decrypt(encrypted, n, d)
        return decrypted == test_message

    @staticmethod
    def compute_d_from_p_q_e(p: int, q: int, e: int) -> int:
        """
        Compute private exponent d from p, q, and e.

        Args:
            p: First prime factor
            q: Second prime factor
            e: Public exponent

        Returns:
            Private exponent d
        """
        n = p * q
        phi = (p - 1) * (q - 1)
        return MathUtils.mod_inverse(e, phi)

    @staticmethod
    def is_weak_modulus(n: int, threshold_bits: int = 64) -> bool:
        """
        Check if modulus is too small (weak).

        Args:
            n: Modulus
            threshold_bits: Bit length threshold

        Returns:
            True if modulus is weak (too small)
        """
        return n.bit_length() < threshold_bits

    @staticmethod
    def is_weak_d(n: int, d: int) -> bool:
        """
        Check if private exponent d is too small (Wiener's attack condition).

        Args:
            n: Modulus
            d: Private exponent

        Returns:
            True if d is vulnerable to Wiener's attack
        """
        # Wiener's attack condition: d < N^(1/4) / 3
        n_pow_quarter = gmpy2.iroot(n, 4)[0]
        return d < n_pow_quarter // 3

    @staticmethod
    def get_key_fingerprint(n: int, e: int) -> str:
        """
        Generate a fingerprint for a public key.

        Args:
            n: Modulus
            e: Public exponent

        Returns:
            Fingerprint string
        """
        import hashlib
        key_data = f"{n}:{e}".encode()
        return hashlib.sha256(key_data).hexdigest()[:16]
