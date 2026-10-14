# ICT306 - SecureVault Core Cryptography Engine
# Authenticated file encryption with password-based key derivation
#
# Algorithms:
#   Key derivation : Argon2id (primary), PBKDF2-HMAC-SHA256 (fallback)
#   Key separation : HKDF-SHA256 (encryption key + HMAC key)
#   Encryption     : AES-256-GCM (default) or ChaCha20-Poly1305
#
# All primitives come from the "cryptography" and "argon2-cffi"
# libraries. No cryptographic algorithm is implemented by hand.

import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


# ---------------------------------------
# File format constants
# ---------------------------------------
#
# Header layout (36 bytes, every field is authenticated as AAD):
#
#   magic      4 bytes   b"SVLT"
#   version    1 byte    format version (1)
#   cipher_id  1 byte    1 = AES-256-GCM, 2 = ChaCha20-Poly1305
#   kdf_id     1 byte    1 = Argon2id, 2 = PBKDF2-HMAC-SHA256
#   reserved   1 byte    0
#   salt      16 bytes   random, unique per file
#   nonce     12 bytes   random, unique per encryption
#   (followed by ciphertext + 16-byte authentication tag)

MAGIC = b"SVLT"
VERSION = 1

CIPHER_AES_GCM = 1
CIPHER_CHACHA20 = 2

KDF_ARGON2ID = 1
KDF_PBKDF2 = 2

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16

HEADER_FORMAT = ">4sBBBB16s12s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)   # 36 bytes

# Argon2id cost settings (OWASP Password Storage Cheat Sheet range)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536      # in KiB, so 64 MiB
ARGON2_PARALLELISM = 4

# PBKDF2 iteration count (OWASP 2023 guidance for SHA-256)
PBKDF2_ITERATIONS = 600000

MIN_PASSWORD_LENGTH = 12
MAX_FILE_SIZE = 512 * 1024 * 1024   # 512 MB, whole file held in memory


class DecryptionError(Exception):
    """
    Raised for every decryption failure.

    The message is the same whether the password is wrong,
    the file was modified, or the header is damaged, so an
    attacker learns nothing from the error itself.
    """
    pass


# ---------------------------------------
# Key derivation
# ---------------------------------------

def check_password_strength(password):
    """Reject passwords that are too short to resist guessing."""

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            "Password must be at least "
            + str(MIN_PASSWORD_LENGTH) + " characters."
        )


def derive_master_key(password, salt, kdf_id):
    """
    Stretch the user's password into a 256-bit master key.

    Argon2id is memory-hard, which makes GPU and ASIC
    guessing attacks far more expensive than plain hashing.
    """

    password_bytes = password.encode("utf-8")

    if kdf_id == KDF_ARGON2ID:
        if not ARGON2_AVAILABLE:
            raise RuntimeError("argon2-cffi is not installed.")

        return hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=KEY_SIZE,
            type=Type.ID,
        )

    if kdf_id == KDF_PBKDF2:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(password_bytes)

    raise ValueError("Unknown key derivation function.")


def split_keys(master_key, salt):
    """
    Use HKDF to derive two independent keys from the master key.

    One key is used for encryption and the other is handed to
    the integrity module (HMAC). Using the same key for two
    different jobs is bad practice, so they are separated here.
    """

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE * 2,
        salt=salt,
        info=b"SecureVault v1 enc+mac",
    )
    output = hkdf.derive(master_key)

    encryption_key = output[:KEY_SIZE]
    hmac_key = output[KEY_SIZE:]

    return encryption_key, hmac_key


def _get_cipher(cipher_id, key):
    """Return the AEAD object for the selected algorithm."""

    if cipher_id == CIPHER_AES_GCM:
        return AESGCM(key)
    if cipher_id == CIPHER_CHACHA20:
        return ChaCha20Poly1305(key)

    raise ValueError("Unknown cipher.")


# ---------------------------------------
# Encryption and decryption (bytes)
# ---------------------------------------

def encrypt_bytes(plaintext, password,
                  cipher_id=CIPHER_AES_GCM,
                  kdf_id=KDF_ARGON2ID):
    """
    Encrypt data and return (container_bytes, hmac_key).

    A fresh salt and nonce are generated with os.urandom
    every time, so encrypting the same file twice gives
    completely different output.
    """

    check_password_strength(password)

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    header = struct.pack(
        HEADER_FORMAT,
        MAGIC, VERSION, cipher_id, kdf_id, 0, salt, nonce
    )

    master_key = derive_master_key(password, salt, kdf_id)
    encryption_key, hmac_key = split_keys(master_key, salt)

    cipher = _get_cipher(cipher_id, encryption_key)

    # The header is passed as associated data, so changing
    # any header byte (e.g. the algorithm id) breaks the tag.
    ciphertext = cipher.encrypt(nonce, plaintext, header)

    return header + ciphertext, hmac_key


def parse_header(container):
    """Read and validate the header. Fails closed on anything odd."""

    if len(container) < HEADER_SIZE + TAG_SIZE:
        raise DecryptionError("Decryption failed.")

    magic, version, cipher_id, kdf_id, _reserved, salt, nonce = struct.unpack(
        HEADER_FORMAT, container[:HEADER_SIZE]
    )

    if magic != MAGIC or version != VERSION:
        raise DecryptionError("Decryption failed.")
    if cipher_id not in (CIPHER_AES_GCM, CIPHER_CHACHA20):
        raise DecryptionError("Decryption failed.")
    if kdf_id not in (KDF_ARGON2ID, KDF_PBKDF2):
        raise DecryptionError("Decryption failed.")

    return cipher_id, kdf_id, salt, nonce


def decrypt_bytes(container, password):
    """
    Decrypt a SecureVault container and return
    (plaintext, hmac_key).

    If the tag does not verify, nothing is returned. GCM and
    Poly1305 check the tag before releasing any plaintext.
    """

    cipher_id, kdf_id, salt, nonce = parse_header(container)

    header = container[:HEADER_SIZE]
    ciphertext = container[HEADER_SIZE:]

    master_key = derive_master_key(password, salt, kdf_id)
    encryption_key, hmac_key = split_keys(master_key, salt)

    cipher = _get_cipher(cipher_id, encryption_key)

    try:
        plaintext = cipher.decrypt(nonce, ciphertext, header)
    except InvalidTag:
        # Same message for wrong password and tampering
        raise DecryptionError("Decryption failed.") from None

    return plaintext, hmac_key


# ---------------------------------------
# File helpers
# ---------------------------------------

def _atomic_write(path, data):
    """
    Write to a temporary file first, then rename it.

    If anything goes wrong half way, the user never ends
    up with a partly written output file.
    """

    temp_path = path + ".tmp"

    try:
        with open(temp_path, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_path, path)

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def encrypt_file(input_path, output_path, password,
                 cipher_id=CIPHER_AES_GCM,
                 kdf_id=KDF_ARGON2ID):
    """Encrypt a file on disk. Returns the HMAC key for integrity.py."""

    if os.path.getsize(input_path) > MAX_FILE_SIZE:
        raise ValueError("File is larger than the 512 MB limit.")

    with open(input_path, "rb") as file:
        plaintext = file.read()

    container, hmac_key = encrypt_bytes(
        plaintext, password, cipher_id, kdf_id
    )

    _atomic_write(output_path, container)

    return hmac_key


def decrypt_file(input_path, output_path, password):
    """
    Decrypt a file on disk. Returns the HMAC key for integrity.py.

    The output file is only created after the tag has been
    verified. A failed decrypt leaves no output behind.
    """

    with open(input_path, "rb") as file:
        container = file.read()

    plaintext, hmac_key = decrypt_bytes(container, password)

    _atomic_write(output_path, plaintext)

    return hmac_key
