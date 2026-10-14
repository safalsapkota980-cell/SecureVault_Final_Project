# ICT306 - SecureVault Crypto Engine Demonstration

import os
import time

import crypto_engine as ce


password = "Correct-Horse-Battery-42"
original_file = "confidential.txt"
encrypted_file = "confidential.txt.svlt"
restored_file = "confidential_restored.txt"

with open(original_file, "w") as file:
    file.write("Client tax file number: 123 456 789\nICT306 confidential test data.")


# ---------------------------------------
# 1. Encrypt the file
# ---------------------------------------

print("1. Encrypting", original_file, "with AES-256-GCM + Argon2id...")

start = time.perf_counter()
ce.encrypt_file(original_file, encrypted_file, password)
elapsed = time.perf_counter() - start

with open(encrypted_file, "rb") as file:
    container = file.read()

cipher_id, kdf_id, salt, nonce = ce.parse_header(container)

print("   Done in", round(elapsed, 2), "seconds")
print("   Salt  :", salt.hex())
print("   Nonce :", nonce.hex())
print("   Tag   :", container[-16:].hex())
print("   Size  :", os.path.getsize(original_file), "->", len(container), "bytes")


# ---------------------------------------
# 2. Decrypt with the correct password
# ---------------------------------------

print("\n2. Decrypting with the correct password...")

ce.decrypt_file(encrypted_file, restored_file, password)

with open(original_file, "rb") as a, open(restored_file, "rb") as b:
    if a.read() == b.read():
        print("   PASSED - restored file matches the original")


# ---------------------------------------
# 3. Decrypt with the wrong password
# ---------------------------------------

print("\n3. Decrypting with a wrong password...")

try:
    ce.decrypt_file(encrypted_file, "should_not_exist.txt", "Wrong-Password-123")
except ce.DecryptionError as error:
    print("   BLOCKED -", error)
    print("   Output file created?", os.path.exists("should_not_exist.txt"))


# ---------------------------------------
# 4. Tamper with one byte of ciphertext
# ---------------------------------------

print("\n4. Flipping one bit in the ciphertext...")

tampered = bytearray(container)
tampered[ce.HEADER_SIZE + 5] ^= 0x01

with open(encrypted_file, "wb") as file:
    file.write(tampered)

try:
    ce.decrypt_file(encrypted_file, "should_not_exist.txt", password)
except ce.DecryptionError as error:
    print("   BLOCKED -", error)
    print("   Output file created?", os.path.exists("should_not_exist.txt"))


# ---------------------------------------
# 5. Same file, same password, twice
# ---------------------------------------

print("\n5. Encrypting the same data twice...")

box1, _ = ce.encrypt_bytes(b"same data", password)
box2, _ = ce.encrypt_bytes(b"same data", password)

print("   Ciphertext 1:", box1[36:52].hex())
print("   Ciphertext 2:", box2[36:52].hex())
print("   Identical?   ", box1 == box2)


# Clean up demo files
for name in (original_file, encrypted_file, restored_file):
    if os.path.exists(name):
        os.remove(name)
