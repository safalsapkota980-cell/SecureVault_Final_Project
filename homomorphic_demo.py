
# ICT306 - Homomorphic Encryption Simulation
# Educational demonstration only


class SimpleHomomorphicDemo:

    def __init__(self, secret_key):
        self.secret_key = secret_key

    def encrypt(self, value):
        # Simple transformation for educational purposes
        return value + self.secret_key

    def decrypt(self, encrypted_value):
        return encrypted_value - self.secret_key

    def add_encrypted_values(self, encrypted_a, encrypted_b):
        # Calculate using transformed values
        return encrypted_a + encrypted_b - self.secret_key


def run_demo():
    demo = SimpleHomomorphicDemo(secret_key=1000)

    value_a = 25
    value_b = 15

    print("Original values:")
    print("Value A:", value_a)
    print("Value B:", value_b)

    encrypted_a = demo.encrypt(value_a)
    encrypted_b = demo.encrypt(value_b)

    print("\nEncrypted values:")
    print("Encrypted A:", encrypted_a)
    print("Encrypted B:", encrypted_b)

    encrypted_result = demo.add_encrypted_values(
        encrypted_a,
        encrypted_b
    )

    print("\nCalculation performed on encrypted values.")
    print("Encrypted result:", encrypted_result)

    decrypted_result = demo.decrypt(encrypted_result)

    print("\nDecrypted result:")
    print(decrypted_result)

    expected_result = value_a + value_b

    print("\nExpected plaintext result:")
    print(expected_result)

    if decrypted_result == expected_result:
        print("\nPASSED - Homomorphic encryption concept demonstrated.")
    else:
        print("\nFAILED - Results do not match.")


if __name__ == "__main__":
    run_demo()
