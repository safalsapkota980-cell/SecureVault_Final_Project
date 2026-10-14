
import os


def secure_delete(file_path):
    """
    Demonstration of best-effort secure file deletion.
    Overwrites a file with random data before removing it.
    """

    if not os.path.isfile(file_path):
        print("ERROR - File does not exist.")
        return False

    try:
        file_size = os.path.getsize(file_path)

        print("File found:", file_path)
        print("File size:", file_size, "bytes")

        with open(file_path, "r+b") as file:
            print("\nOverwriting file with random data...")

            random_data = os.urandom(file_size)

            file.seek(0)
            file.write(random_data)
            file.flush()
            os.fsync(file.fileno())

        print("File overwrite completed.")

        os.remove(file_path)
        print("File deleted successfully.")

        return True

    except Exception as error:
        print("Secure deletion FAILED.")
        print("Error:", error)
        return False


# Run this demonstration only when the file
# is executed directly, not when imported.
if __name__ == "__main__":

    test_file = "delete_test.txt"

    with open(test_file, "w", encoding="utf-8") as file:
        file.write(
            "This is confidential information for the ICT306 project."
        )

    print("Test file created successfully.")
    print("\nStarting secure deletion...\n")

    result = secure_delete(test_file)

    print("\nChecking whether the file still exists...")

    if result and not os.path.exists(test_file):
        print("PASSED - File no longer exists.")
    else:
        print("FAILED - Secure deletion was not completed.")
