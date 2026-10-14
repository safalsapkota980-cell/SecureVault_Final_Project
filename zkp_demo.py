
# ICT306 - Zero-Knowledge Proof (ZKP) Simulation
# Educational demonstration only

import hashlib
import secrets
import getpass


def create_commitment(secret, nonce):
    """
    Create a SHA-256 commitment using
    a secret and a random nonce.
    """
    data = secret + nonce

    return hashlib.sha256(
        data.encode()
    ).hexdigest()


def verify_proof(stored_commitment, provided_secret, nonce):
    """
    Verify the supplied secret by recreating
    the commitment and comparing the hashes.
    """
    new_commitment = create_commitment(
        provided_secret,
        nonce
    )

    return secrets.compare_digest(
        stored_commitment,
        new_commitment
    )


def run_demo():
    print("=== ZERO-KNOWLEDGE PROOF SIMULATION ===")

    # Create a secret at runtime
    secret_value = getpass.getpass(
        "\nCreate a secret: "
    )

    # Generate a secure random nonce
    nonce = secrets.token_hex(16)

    # Generate commitment
    commitment = create_commitment(
        secret_value,
        nonce
    )

    print("\nCommitment created:")
    print(commitment)

    print(
        "\nThe secret is not stored directly "
        "in the source code or displayed."
    )

    print("\n--- Knowledge Verification ---")

    verification_attempt = getpass.getpass(
        "Enter the secret again: "
    )

    if verify_proof(
        commitment,
        verification_attempt,
        nonce
    ):
        print(
            "PASSED - Knowledge of the secret "
            "was verified."
        )
    else:
        print(
            "FAILED - Incorrect secret was rejected."
        )

    print("\nZKP simulation completed.")


if __name__ == "__main__":
    run_demo()
