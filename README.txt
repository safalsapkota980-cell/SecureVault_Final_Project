# SecureVault

A Python desktop application I developed to explore secure file management, authentication, encryption and security monitoring.

The project brings together a graphical interface, file protection tools, automated tests and educational cryptography demonstrations.

## Features

- **Two-factor authentication:** Login using a password and a time-based one-time code.
- **Role-based access control:** Restrict application actions according to user roles.
- **File encryption and decryption:** Protect file contents and recover them through the application.
- **Integrity verification:** Check whether protected data has been modified.
- **File deletion:** Demonstrate overwriting a file before deleting it.
- **Security logging:** Record application security events for review.
- **Log monitoring:** Display recent security events.
- **Cryptography demonstrations:** Explore homomorphic encryption, zero-knowledge proofs and differential privacy.

## Technologies

- Python
- Tkinter
- Argon2 password hashing
- PyOTP
- Pytest
- Python logging
- Git and GitHub

Additional dependencies are listed in `requirements.txt`.

## Project structure

| File | Purpose |
|------|---------|
| `securevault_app.py` | Main desktop application |
| `auth.py` | Authentication and access control |
| `tk_login.py` | Login interface |
| `create_user.py` | User creation utility |
| `crypto_engine.py` | File encryption and decryption functions |
| `crypto_demo.py` | Cryptography demonstration |
| `integrity.py` | Integrity verification |
| `secure_delete.py` | File overwriting and deletion |
| `security_logger.py` | Centralised security logging |
| `monitor_logs.py` | Recent security event viewer |
| `homomorphic_demo.py` | Homomorphic encryption demonstration |
| `zkp_demo.py` | Zero-knowledge proof demonstration |
| `differential_privacy_demo.py` | Differential privacy demonstration |
| `test_auth.py` | Authentication tests |
| `test_crypto_engine.py` | Cryptography tests |
| `requirements.txt` | Python dependencies |

## Getting started

### 1. Prepare the environment

Install Python with Tkinter support.

Open a terminal in the project folder and create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

On macOS or Linux:

```bash
source .venv/bin/activate
```

### 2. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 3. Set up a local account

User records and two-factor authentication enrolment must be configured locally.

Review `create_user.py` for its required arguments and account creation process. Complete the two-factor authentication setup before attempting to log in.

The repository intentionally excludes local user records and authentication QR codes.

### 4. Start the application

```bash
python securevault_app.py
```

## Running tests

Run the automated tests from the project folder:

```bash
python -m pytest
```

The test files cover authentication and cryptography functionality. Results depend on the local environment and configuration.

## Security logging

The logging configuration writes events to:

```text
logs/security.log
```

Logs rotate at 1 MB, with up to five backup files.

To display recent security events:

```bash
python monitor_logs.py
```

Authentication events sent to the `securevault.auth` logger are captured by the configured parent `securevault` logger.

Passwords, authentication secrets and live one-time codes should never be included in logs.

## Educational demonstrations

The following scripts explore security and privacy concepts:

```bash
python homomorphic_demo.py
python zkp_demo.py
python differential_privacy_demo.py
```

These demonstrations are intended for learning. They are not production implementations of cryptographic protocols.

## Local files and sensitive data

The `.gitignore` configuration excludes local data and generated files, including:

- `users.json`
- `demo_user_2fa.png`
- `vault_files/`
- `logs/`
- Environment configuration files
- Virtual environments
- Python and test caches

Do not commit passwords, encryption keys, authentication secrets or personal documents.

Adding a file to `.gitignore` does not remove it from an existing Git history.

## Limitations

SecureVault is an educational prototype.

- File overwriting cannot guarantee permanent erasure on SSDs, backups, snapshots or storage using wear levelling.
- Authentication secret storage and encryption key management require further review before use with sensitive information.
- Automated testing and static analysis do not prove that an application is secure.
- The advanced cryptography scripts demonstrate concepts and should not be used to protect real-world sensitive data.

Use sample files and demonstration accounts when exploring the application.

## Future improvements

- Strengthen protection of stored authentication secrets.
- Review encryption key management.
- Expand automated tests and error handling.
- Improve account setup instructions.
- Add interface screenshots and a short demonstration video.
- Review the application before considering production use.

## Author

**Safal Sapkota**

[GitHub profile](https://github.com/safalsapkota980-cell)

Any reused third-party code remains subject to its original licence and attribution requirements.