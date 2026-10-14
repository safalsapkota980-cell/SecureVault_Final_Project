# SecureVault

A Python desktop project exploring secure file management,
authentication, encryption and security monitoring.

The application combines a graphical interface, file protection
tools, automated tests and educational security demonstrations.

## Features

- Password login with TOTP two-factor authentication.
- Role-based access control for users, administrators and auditors.
- File encryption and decryption.
- HMAC-SHA256 file integrity verification.
- Best-effort file overwriting and deletion.
- Centralised security logging with rotating log files.
- Recent security event monitoring.
- Educational arithmetic, hash-based verification and
  differential privacy demonstrations.

## Technologies

Python · Tkinter · Cryptography · Argon2 · PyOTP · Pytest · Git

## Project structure

| File | Purpose |
|------|---------|
| `securevault_app.py` | Main desktop application |
| `auth.py` | Authentication, sessions and access control |
| `tk_login.py` | Login interface |
| `create_user.py` | Local account creation and 2FA enrolment |
| `crypto_engine.py` | File encryption and decryption |
| `crypto_demo.py` | Encryption demonstration |
| `integrity.py` | HMAC integrity verification |
| `secure_delete.py` | File overwriting and deletion |
| `security_logger.py` | Security logging configuration |
| `monitor_logs.py` | Recent security event viewer |
| `homomorphic_demo.py` | Arithmetic transformation simulation |
| `zkp_demo.py` | Hash-based commitment and secret verification |
| `differential_privacy_demo.py` | Laplace noise count demonstration |
| `test_auth.py` | Authentication and access control tests |
| `test_crypto_engine.py` | Cryptography tests |
| `requirements.txt` | Python dependencies |

## Installation

### 1. Prepare Python

Install Python with Tkinter support.

Open a terminal in the project folder and create a virtual
environment:

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

### 3. Create a demonstration account

Run:

```bash
python create_user.py demo_user user
```

Enter and confirm a password when prompted. Use a unique
demonstration password, not a password used for another account.

Scan the generated QR code using an authenticator application.
Delete the generated QR image after completing enrolment,
because it contains the account's authentication secret.

Other supported roles are `admin` and `auditor`.

User records are stored locally in `users.json` and are
excluded from Git.

### 4. Start the application

From the project folder, run:

```bash
python securevault_app.py
```

Log in using the account password and the current code from
your authenticator application.

## Using the application

1. Sign in with a locally configured account.
2. Choose an action permitted by your role.
3. Select a sample file to encrypt.
4. Enter a separate encryption password of at least
   12 characters.
5. Use the decryption and integrity verification functions
   to explore file protection.
6. Review security events using an authorised account.

Use disposable sample files when testing file deletion.

## Testing

Run the automated tests:

```bash
python -m pytest -q
```

Local verification on 14 October 2026:

- Python 3.14 on Windows.
- 28 tests passed.

The tests cover authentication, access control and
cryptography behaviour. Passing tests does not establish
that the application is free of security vulnerabilities.

## Security monitoring

Security events are written to:

```text
logs/security.log
```

The logger uses a rotating file handler configured for
1,000,000 bytes per file and up to five backup files.

Display recent security events:

```bash
python monitor_logs.py
```

Passwords, authentication secrets and live one-time codes
should never be included in logs.

## Educational demonstrations

Run the examples:

```bash
python homomorphic_demo.py
python zkp_demo.py
python differential_privacy_demo.py
```

### Arithmetic transformation

`homomorphic_demo.py` illustrates calculations on values
transformed by adding a fixed number.

This is a toy arithmetic simulation. It does not provide
secure homomorphic encryption.

### Hash-based secret verification

`zkp_demo.py` creates a SHA-256 commitment using a secret
and a random nonce, then checks a supplied secret against it.

The verifier receives the secret. This is a hash-based
verification demonstration, not a zero-knowledge proof.

### Differential privacy

`differential_privacy_demo.py` adds Laplace noise to a count
with an assumed sensitivity of one.

It illustrates how epsilon affects the noise distribution.
It does not implement privacy-budget tracking across
repeated queries.

These examples are intended for learning, not production use.

## Sensitive data and Git

The `.gitignore` configuration excludes:

- Local user records: `users.json`
- Generated authentication QR images: `*_2fa.png`
- Stored files: `vault_files/`
- Runtime logs: `logs/`
- Local environment configuration
- Virtual environments
- Python and test caches

Do not commit passwords, encryption keys, authentication
secrets or personal documents.

Adding a file to `.gitignore` does not remove it from
previous Git commits.

## Limitations

SecureVault is an educational prototype.

- TOTP secrets are stored unencrypted in the local user
  database. File access permissions are not a substitute
  for encrypting those secrets.
- Application roles do not replace operating-system
  permissions. Someone with access to the project files
  may bypass application controls.
- File overwriting cannot guarantee permanent erasure on
  SSDs, snapshots, backups or storage using wear levelling.
- Deleting an encrypted file does not delete its original
  file, decrypted copies or backups.
- Encryption and decryption load file contents into memory.
- Cryptography demonstrations have the limitations
  described above.
- Further security review is required before using this
  application with sensitive information.

## Planned improvements

- Encrypt stored authentication secrets.
- Review key management and local file permissions.
- Improve account setup and error handling.
- Expand automated testing.
- Add interface screenshots and a demonstration video.
- Replace toy examples with carefully reviewed educational
  implementations where appropriate.

## Portfolio contact

**Safal Sapkota**

[GitHub profile](https://github.com/safalsapkota980-cell)

## Attribution

Preserve the original authorship and licence notices for
any reused code. Module-level contribution notes remain
in the source files.