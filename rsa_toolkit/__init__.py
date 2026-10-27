"""
RSA Attack Toolkit - A comprehensive security testing tool for RSA cryptographic vulnerabilities.

This toolkit implements various attack scenarios against weak RSA configurations including:
- Small modulus factorization (brute force, Fermat, Pollard's rho)
- Wiener's attack for small private exponent d
- Small public exponent e attacks (cube root, Hastad's broadcast)
- Shared modulus attacks
- Shared prime (GCD) attacks

Author: Group 3 - Cybersecurity Cryptography Course
"""

__version__ = "1.0.0"
__author__ = "Group 3"

from rsa_toolkit.utils.math_utils import *
from rsa_toolkit.utils.rsa_utils import *
