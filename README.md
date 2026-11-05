# RSA Attack Toolkit

A comprehensive security testing tool for RSA cryptographic vulnerabilities, implementing various attack scenarios based on weak RSA configurations.

## Overview

This toolkit is designed for educational and research purposes to demonstrate and test RSA vulnerabilities arising from:
- Small modulus sizes
- Close prime factors
- Small private exponents (Wiener's attack)
- Small public exponents without proper padding
- Shared modulus across users
- Shared prime factors (poor RNG)

**⚠️ Warning**: This toolkit is for educational and authorized security testing only. Do not use against systems without proper authorization.

## Features

### Attack Modules

1. **Factorization Attacks**
   - Brute Force (for small modulus < 64 bits)
   - Fermat's Method (for close primes)
   - Pollard's Rho (for small prime factors)

2. **Small Exponent Attacks**
   - Cube Root Attack (e=3, no padding)
   - Hastad's Broadcast Attack (e=3, multiple recipients)

3. **Wiener's Attack**
   - Small private exponent d recovery

4. **Shared Modulus Attacks**
   - Internal attacker (knows one private key)
   - External attacker (has two ciphertexts)

5. **Shared Prime Attack**
   - GCD-based detection of common prime factors

### Architecture

The toolkit follows a client-server architecture:

- **Vulnerable RSA Server**: FastAPI-based server that generates weak RSA configurations and provides REST API endpoints
- **Attacker Client**: CLI-based client that performs reconnaissance, plans attacks, executes exploits, and reports results

## Installation

### Prerequisites

- Python 3.10 or higher
- pip package manager

### Setup

1. Clone the repository:
```bash
cd RSA_Toolkit
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Starting the Server

Run the vulnerable RSA server:

```bash
python main.py server
```

Or with custom host/port:

```bash
python main.py server --host 0.0.0.0 --port 8080
```

The server will start at `http://127.0.0.1:8000` by default.

### Using the Client

#### List Available Scenarios

```bash
python main.py client list-scenarios
```

#### Create a Scenario

```bash
python main.py client create-scenario S1
```

Available scenario types:
- `S0`: Secure configuration (baseline)
- `S1`: Small modulus (< 64 bits)
- `S2`: Close primes (Fermat factorization)
- `S3`: Small d (Wiener attack)
- `S4`: Shared modulus (internal attacker)
- `S5`: Shared modulus (external attacker)
- `S6`: Small e, no padding (cube root attack)
- `S7`: Small e, broadcast (Hastad attack)
- `S8`: Shared prime (GCD attack)
- `S9`: Very small d (extended Wiener)

#### Get Scenario Information

```bash
python main.py client scenario-info <scenario_id>
```

#### Attack a Scenario

```bash
python main.py client attack <scenario_id>
```

For verbose output:

```bash
python main.py client attack <scenario_id> --verbose
```

#### Custom Server URL

If the server is running on a different host/port:

```bash
python main.py client attack <scenario_id> --server http://192.168.1.100:8000
```

## Project Structure

```
RSA_Toolkit/
├── rsa_toolkit/
│   ├── __init__.py
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── math_utils.py      # Mathematical utilities
│   │   └── rsa_utils.py       # RSA operations
│   ├── attacks/
│   │   ├── __init__.py
│   │   ├── factorization.py   # Factorization attacks
│   │   ├── small_exponent.py  # Small e attacks
│   │   ├── wiener.py          # Wiener's attack
│   │   ├── shared_modulus.py  # Shared modulus attacks
│   │   └── shared_prime.py    # Shared prime attack
│   ├── server/
│   │   ├── __init__.py
│   │   ├── app.py             # FastAPI server
│   │   └── scenario_manager.py # Scenario management
│   ├── client/
│   │   ├── __init__.py
│   │   ├── attacker.py        # Attack client logic
│   │   └── cli.py             # CLI interface
│   └── tests/
│       ├── __init__.py
│       ├── test_math_utils.py
│       ├── test_rsa_utils.py
│       ├── test_attacks.py
│       └── test_scenarios.py
├── main.py                    # Entry point
├── requirements.txt           # Dependencies
└── README.md                 # This file
```

## Running Tests

Run the complete test suite:

```bash
pytest rsa_toolkit/tests/
```

Run specific test file:

```bash
pytest rsa_toolkit/tests/test_attacks.py
```

Run with verbose output:

```bash
pytest rsa_toolkit/tests/ -v
```

## API Documentation

When the server is running, you can access the interactive API documentation at:

- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

### API Endpoints

- `GET /` - Server information
- `GET /scenarios` - List all scenarios
- `POST /scenarios/create` - Create a new scenario
- `GET /scenarios/{scenario_id}` - Get scenario details
- `GET /scenarios/{scenario_id}/users` - List users in scenario
- `GET /scenarios/{scenario_id}/users/{user_id}/public_key` - Get public key
- `GET /scenarios/{scenario_id}/users/{user_id}/ciphertext` - Get ciphertext
- `POST /scenarios/{scenario_id}/users/{user_id}/verify_d` - Verify private key
- `POST /scenarios/{scenario_id}/users/{user_id}/verify_message` - Verify message

## Security Recommendations

Based on the analysis performed by this toolkit, here are the recommended security configurations:

1. **Key Size**: Use minimum 2048-bit keys (3072-bit or 4096-bit for long-term security)
2. **Random Number Generation**: Use cryptographically secure RNG (CSPRNG)
3. **Public Exponent**: Use e = 65537 (standard, secure choice)
4. **Padding**: Always use OAEP padding (never raw RSA)
5. **Modulus Sharing**: Never share modulus N between users
6. **Key Generation**: Ensure primes are not too close and don't share factors

## Mathematical Background

### RSA Basics

RSA is based on the difficulty of factoring large integers:

- Choose two large primes p and q
- Compute n = p × q
- Compute φ(n) = (p-1)(q-1)
- Choose public exponent e (coprime to φ(n))
- Compute private exponent d = e^(-1) mod φ(n)

### Vulnerabilities

1. **Small Modulus**: Can be factorized by brute force
2. **Close Primes**: Vulnerable to Fermat's factorization
3. **Small d**: Wiener's attack using continued fractions
4. **Small e without Padding**: Cube root or Hastad's broadcast attack
5. **Shared Modulus**: Allows key recovery from another user's key
6. **Shared Prime**: GCD reveals the common factor immediately

## Development

### Code Style

The codebase follows these conventions:
- PEP 8 for Python code
- Type hints for function signatures
- Docstrings for all public functions
- Dataclasses for structured data

### Adding New Attacks

To add a new attack module:

1. Create a new file in `rsa_toolkit/attacks/`
2. Implement the attack class with:
   - `__init__` method for configuration
   - `attack` method that takes inputs and returns a result
   - Result dataclass with success flag and details
3. Add the attack to `rsa_toolkit/attacks/__init__.py`
4. Add the attack to the client's attack planning in `attacker.py`
5. Write tests in `rsa_toolkit/tests/test_attacks.py`

## License

This project is for educational purposes. Use responsibly and only with proper authorization.

## Authors

Group 3 - Cybersecurity Cryptography Course
- Đặng Quỳnh Trang
- Lưu Quý Nhân
- Trần Hoàng Anh
- Bùi Hoàng Hải

## Acknowledgments

- Course instructor: Đỗ Xuân Chợ
- Based on the report: "Các lỗ hổng toán học trong hệ mật RSA và phát triển bộ công cụ kiểm thử an toàn"
