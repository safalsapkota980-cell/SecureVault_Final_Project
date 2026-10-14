# ICT306 - Security tests for crypto_engine.py
# Run with:  python -m unittest -v test_crypto_engine

import os
import tempfile
import unittest

import crypto_engine as ce

PASSWORD = "Correct-Horse-Battery-42"
DATA = b"Patient record #1182: confidential ICT306 test data."


class TestCryptoEngine(unittest.TestCase):

    def test_01_aes_gcm_round_trip(self):
        """AES-256-GCM: decrypt(encrypt(x)) == x"""
        box, _ = ce.encrypt_bytes(DATA, PASSWORD)
        plain, _ = ce.decrypt_bytes(box, PASSWORD)
        self.assertEqual(plain, DATA)

    def test_02_chacha20_round_trip(self):
        """ChaCha20-Poly1305: decrypt(encrypt(x)) == x"""
        box, _ = ce.encrypt_bytes(DATA, PASSWORD, cipher_id=ce.CIPHER_CHACHA20)
        plain, _ = ce.decrypt_bytes(box, PASSWORD)
        self.assertEqual(plain, DATA)

    def test_03_pbkdf2_fallback_round_trip(self):
        """PBKDF2 fallback KDF works end to end"""
        box, _ = ce.encrypt_bytes(DATA, PASSWORD, kdf_id=ce.KDF_PBKDF2)
        plain, _ = ce.decrypt_bytes(box, PASSWORD)
        self.assertEqual(plain, DATA)

    def test_04_wrong_password_rejected(self):
        """Wrong password raises DecryptionError, no plaintext"""
        box, _ = ce.encrypt_bytes(DATA, PASSWORD)
        with self.assertRaises(ce.DecryptionError):
            ce.decrypt_bytes(box, "Wrong-Password-123")

    def test_05_ciphertext_bit_flip_detected(self):
        """Flipping one ciphertext bit breaks the tag"""
        box, _ = ce.encrypt_bytes(DATA, PASSWORD)
        tampered = bytearray(box)
        tampered[ce.HEADER_SIZE + 3] ^= 0x01
        with self.assertRaises(ce.DecryptionError):
            ce.decrypt_bytes(bytes(tampered), PASSWORD)

    def test_06_header_tamper_detected(self):
        """Changing the salt in the header (AAD) is detected"""
        box, _ = ce.encrypt_bytes(DATA, PASSWORD)
        tampered = bytearray(box)
        tampered[10] ^= 0x01            # inside the salt field
        with self.assertRaises(ce.DecryptionError):
            ce.decrypt_bytes(bytes(tampered), PASSWORD)

    def test_07_algorithm_swap_detected(self):
        """Changing cipher id from AES-GCM to ChaCha20 is rejected"""
        box, _ = ce.encrypt_bytes(DATA, PASSWORD)
        tampered = bytearray(box)
        tampered[5] = ce.CIPHER_CHACHA20
        with self.assertRaises(ce.DecryptionError):
            ce.decrypt_bytes(bytes(tampered), PASSWORD)

    def test_08_truncated_file_rejected(self):
        """Truncated container fails closed"""
        box, _ = ce.encrypt_bytes(DATA, PASSWORD)
        with self.assertRaises(ce.DecryptionError):
            ce.decrypt_bytes(box[:-1], PASSWORD)
        with self.assertRaises(ce.DecryptionError):
            ce.decrypt_bytes(box[:20], PASSWORD)

    def test_09_same_error_message(self):
        """Wrong password and tampering give identical messages"""
        box, _ = ce.encrypt_bytes(DATA, PASSWORD)
        tampered = bytearray(box)
        tampered[-1] ^= 0x01
        try:
            ce.decrypt_bytes(box, "Wrong-Password-123")
        except ce.DecryptionError as e1:
            msg1 = str(e1)
        try:
            ce.decrypt_bytes(bytes(tampered), PASSWORD)
        except ce.DecryptionError as e2:
            msg2 = str(e2)
        self.assertEqual(msg1, msg2)

    def test_10_fresh_salt_and_nonce(self):
        """Same file + same password gives different ciphertext"""
        box1, _ = ce.encrypt_bytes(DATA, PASSWORD)
        box2, _ = ce.encrypt_bytes(DATA, PASSWORD)
        self.assertNotEqual(box1, box2)
        self.assertNotEqual(box1[8:24], box2[8:24])      # salt
        self.assertNotEqual(box1[24:36], box2[24:36])    # nonce

    def test_11_kdf_deterministic(self):
        """Same password + salt always gives the same key"""
        salt = os.urandom(16)
        k1 = ce.derive_master_key(PASSWORD, salt, ce.KDF_ARGON2ID)
        k2 = ce.derive_master_key(PASSWORD, salt, ce.KDF_ARGON2ID)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 32)

    def test_12_key_separation(self):
        """Encryption key and HMAC key are different"""
        salt = os.urandom(16)
        master = ce.derive_master_key(PASSWORD, salt, ce.KDF_ARGON2ID)
        enc_key, mac_key = ce.split_keys(master, salt)
        self.assertNotEqual(enc_key, mac_key)

    def test_13_weak_password_rejected(self):
        """Passwords under 12 characters are refused"""
        with self.assertRaises(ValueError):
            ce.encrypt_bytes(DATA, "short")

    def test_14_empty_file(self):
        """An empty file still encrypts and decrypts"""
        box, _ = ce.encrypt_bytes(b"", PASSWORD)
        self.assertEqual(len(box), ce.HEADER_SIZE + ce.TAG_SIZE)
        plain, _ = ce.decrypt_bytes(box, PASSWORD)
        self.assertEqual(plain, b"")

    def test_15_failed_decrypt_writes_nothing(self):
        """No output file is created when decryption fails"""
        with tempfile.TemporaryDirectory() as folder:
            src = os.path.join(folder, "report.pdf")
            enc = os.path.join(folder, "report.pdf.svlt")
            out = os.path.join(folder, "report_restored.pdf")
            with open(src, "wb") as f:
                f.write(DATA)
            ce.encrypt_file(src, enc, PASSWORD)
            with self.assertRaises(ce.DecryptionError):
                ce.decrypt_file(enc, out, "Wrong-Password-123")
            self.assertFalse(os.path.exists(out))
            self.assertFalse(os.path.exists(out + ".tmp"))

    def test_16_file_round_trip_and_hmac_key(self):
        """File round trip, and the same HMAC key comes back"""
        with tempfile.TemporaryDirectory() as folder:
            src = os.path.join(folder, "data.bin")
            enc = os.path.join(folder, "data.bin.svlt")
            out = os.path.join(folder, "data_restored.bin")
            original = os.urandom(1024 * 1024)
            with open(src, "wb") as f:
                f.write(original)
            key_a = ce.encrypt_file(src, enc, PASSWORD)
            key_b = ce.decrypt_file(enc, out, PASSWORD)
            with open(out, "rb") as f:
                self.assertEqual(f.read(), original)
            self.assertEqual(key_a, key_b)


if __name__ == "__main__":
    unittest.main(verbosity=2)
