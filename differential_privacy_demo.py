
# ICT306 - Differential Privacy (DP) Simulation
# Educational demonstration only

import secrets
import math


def laplace_noise(scale):
    """
    Generate Laplace-distributed noise using
    a cryptographically secure random generator.
    """
    secure_random = secrets.SystemRandom()

    u = secure_random.random() - 0.5

    return -scale * math.copysign(
        math.log(1 - 2 * abs(u)),
        u
    )


def private_count(true_count, epsilon):
    """
    Add Laplace noise to a count.

    Smaller epsilon = stronger privacy, more noise.
    Larger epsilon = weaker privacy, less noise.
    """
    if epsilon <= 0:
        raise ValueError("Epsilon must be greater than zero.")

    sensitivity = 1
    scale = sensitivity / epsilon

    noise = laplace_noise(scale)

    return true_count + noise


def run_demo():
    # Example dataset
    student_records = [
        "Student 1",
        "Student 2",
        "Student 3",
        "Student 4",
        "Student 5",
        "Student 6",
        "Student 7",
        "Student 8",
        "Student 9",
        "Student 10"
    ]

    true_count = len(student_records)

    print("=== DIFFERENTIAL PRIVACY SIMULATION ===")

    print("\nActual number of records:")
    print(true_count)

    # Test 1: Stronger privacy
    epsilon_1 = 0.5

    private_result_1 = private_count(
        true_count,
        epsilon_1
    )

    print("\n--- Test 1: Epsilon =", epsilon_1, "---")
    print("Actual count:", true_count)
    print(
        "Privacy-protected count:",
        round(private_result_1, 2)
    )

    # Test 2: Weaker privacy
    epsilon_2 = 5.0

    private_result_2 = private_count(
        true_count,
        epsilon_2
    )

    print("\n--- Test 2: Epsilon =", epsilon_2, "---")
    print("Actual count:", true_count)
    print(
        "Privacy-protected count:",
        round(private_result_2, 2)
    )

    print("\n=== PRIVACY / ACCURACY TRADE-OFF ===")

    print(
        "Smaller epsilon provides stronger privacy "
        "but usually introduces more noise."
    )

    print(
        "Larger epsilon provides weaker privacy "
        "but usually gives a result closer to "
        "the original value."
    )

    print("\nDifferential Privacy simulation completed.")


if __name__ == "__main__":
    run_demo()
