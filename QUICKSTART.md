# Quick Start Guide

This guide will help you get started with the RSA Attack Toolkit quickly.

## Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

## Step 2: Start the Server

Open a terminal and run:

```bash
python main.py server
```

You should see:
```
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000
```

## Step 3: Create a Scenario (in another terminal)

Open a new terminal and create a test scenario:

```bash
python main.py client create-scenario S1
```

This will create a scenario with a small modulus (vulnerable to brute force).

## Step 4: Attack the Scenario

```bash
python main.py client attack <scenario_id>
```

Replace `<scenario_id>` with the ID returned from step 3.

You should see output showing:
- Reconnaissance results
- Attack planning
- Attack execution
- Final results

## Example Session

```bash
# Terminal 1: Start server
python main.py server

# Terminal 2: Create and attack
python main.py client create-scenario S1
# Output: Scenario created successfully! Scenario ID: S1_1234

python main.py client attack S1_1234
# Output: Attack Successful! Method: brute_force
```

## Try Different Scenarios

```bash
# Small modulus (brute force)
python main.py client create-scenario S1

# Close primes (Fermat)
python main.py client create-scenario S2

# Small d (Wiener)
python main.py client create-scenario S3

# Small e, no padding (cube root)
python main.py client create-scenario S6

# Shared prime (GCD)
python main.py client create-scenario S8
```

## Running Tests

```bash
pytest rsa_toolkit/tests/ -v
```

## API Documentation

With the server running, visit:
- http://127.0.0.1:8000/docs (Swagger UI)
- http://127.0.0.1:8000/redoc (ReDoc)

## Troubleshooting

### Port already in use
If port 8000 is in use, use a different port:
```bash
python main.py server --port 8080
python main.py client attack <id> --server http://127.0.0.1:8080
```

### Import errors
Make sure you're in the RSA_Toolkit directory:
```bash
cd "D:\Study Process\PTIT\BSKT\Mật mã học cơ sở\RSA_Toolkit"
```

### Slow attacks
Some attacks (like Pollard's rho) can be slow on larger moduli. Start with S1 (small modulus) for quick results.
