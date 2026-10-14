
import hmac
import hashlib
import os


def generate_hmac(file_path, hmac_key):
    """Generate HMAC-SHA256 for a file using the supplied key."""
    with open(file_path, "rb") as file:
        file_data = file.read()

    return hmac.new(
        hmac_key,
        file_data,
        hashlib.sha256
    ).hexdigest()


def verify_hmac(file_path, original_hmac, hmac_key):
    """Verify integrity using a constant-time comparison."""
    new_hmac = generate_hmac(file_path, hmac_key)

    return hmac.compare_digest(
        new_hmac,
        original_hmac
    )


if __name__ == "__main__":
    # Standalone demonstration using a disposable test file.
    file_name = "test_file.txt"
    demo_key = os.urandom(32)

    with open(file_name, "w", encoding="utf-8") as file:
        file.write("SecureVault integrity demonstration")

    original_hmac = generate_hmac(file_name, demo_key)

    print("Original HMAC:", original_hmac)
    print(
        "Original file:",
        "PASSED" if verify_hmac(file_name, original_hmac, demo_key)
        else "FAILED"
    )

    with open(file_name, "a", encoding="utf-8") as file:
        file.write("\nUnauthorized modification!")

    print(
        "Modified file:",
        "PASSED - tampering detected"
        if not verify_hmac(file_name, original_hmac, demo_key)
        else "FAILED - tampering not detected"
    )
