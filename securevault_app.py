
# ICT306 - SECUREVAULT
# Integrated Group Demonstration Application

import os
import json
import hmac
import logging
import secrets
import tkinter as tk

from pathlib import Path
from uuid import uuid4
from tkinter import ttk, filedialog, messagebox, simpledialog

from auth import AuthManager, check_permission, PermissionDenied
from tk_login import show_login

from crypto_engine import (
    encrypt_file,
    decrypt_file,
    decrypt_bytes,
    DecryptionError
)

from integrity import generate_hmac
from secure_delete import secure_delete
from homomorphic_demo import SimpleHomomorphicDemo
from zkp_demo import create_commitment, verify_proof
from differential_privacy_demo import private_count
from security_logger import configure_security_logging


# ---------------------------------------
# Application configuration
# ---------------------------------------

BASE_DIR = Path(__file__).resolve().parent
VAULT_DIR = BASE_DIR / "vault_files"
LOG_FILE = BASE_DIR / "logs" / "security.log"

configure_security_logging()
log = logging.getLogger("securevault.app")


# ---------------------------------------
# File helpers
# ---------------------------------------

def get_user_vault(username):
    return VAULT_DIR / username


def is_managed_file(path, directory, extension=".svlt"):
    """
    Check that a selected file is a regular file
    directly inside the permitted directory.
    """
    path = Path(path)
    directory = Path(directory)

    try:
        return (
            path.is_file()
            and not path.is_symlink()
            and path.suffix.lower() == extension
            and path.parent.resolve() == directory.resolve()
        )
    except OSError:
        return False


def hmac_metadata_path(encrypted_path):
    return Path(str(encrypted_path) + ".hmac")


def save_hmac_metadata(encrypted_path, hmac_key):
    """
    Save the expected HMAC for the encrypted file.
    The secret HMAC key is never written to this file.
    """
    encrypted_path = Path(encrypted_path)

    digest = generate_hmac(str(encrypted_path), hmac_key)

    metadata = {
        "algorithm": "HMAC-SHA256",
        "digest": digest
    }

    metadata_path = hmac_metadata_path(encrypted_path)

    # Use exclusive creation; never overwrite existing metadata.
    with open(metadata_path, "x", encoding="utf-8") as file:
        json.dump(metadata, file, indent=2)


def verify_encrypted_hmac(encrypted_path, password):
    """
    Verify HMAC for an encrypted file.

    Returns:
      True  - HMAC matches
      False - HMAC mismatch
      None  - No HMAC metadata exists

    AES-GCM authentication is checked before the
    derived HMAC key is returned by decrypt_bytes().
    """
    encrypted_path = Path(encrypted_path)
    metadata_path = hmac_metadata_path(encrypted_path)

    if not metadata_path.is_file():
        return None

    with open(metadata_path, "r", encoding="utf-8") as file:
        metadata = json.load(file)

    if metadata.get("algorithm") != "HMAC-SHA256":
        raise ValueError("Unsupported HMAC metadata.")

    expected_digest = metadata.get("digest", "")

    if (
        not isinstance(expected_digest, str)
        or len(expected_digest) != 64
    ):
        raise ValueError("Invalid HMAC metadata.")

    with open(encrypted_path, "rb") as file:
        encrypted_data = file.read()

    # This also authenticates the AES-GCM container.
    # A wrong password or damaged container is rejected.
    plaintext, hmac_key = decrypt_bytes(
        encrypted_data,
        password
    )

    actual_digest = generate_hmac(
        str(encrypted_path),
        hmac_key
    )

    return hmac.compare_digest(
        actual_digest,
        expected_digest
    )


# ---------------------------------------
# Main application
# ---------------------------------------

def main():

    # Authentication and 2FA
    auth = AuthManager()
    session = show_login(auth)

    if session is None:
        print("Login cancelled.")
        return

    root = tk.Tk()
    root.title("SecureVault - Secure File Encryption Tool")
    root.geometry("850x780")
    root.minsize(740, 660)

    frame = ttk.Frame(root, padding=20)
    frame.pack(fill="both", expand=True)

    ttk.Label(
        frame,
        text="SECUREVAULT",
        font=("Arial", 24, "bold")
    ).pack(pady=(5, 8))

    ttk.Label(
        frame,
        text="Secure File Encryption and Cybersecurity Tool",
        font=("Arial", 12)
    ).pack(pady=4)

    ttk.Label(
        frame,
        text=f"Signed in: {session.username} ({session.role})",
        font=("Arial", 11, "bold")
    ).pack(pady=10)

    status = tk.StringVar(value="Ready.")

    user_vault = get_user_vault(session.username)

    # ---------------------------------------
    # Session and permission checks
    # ---------------------------------------

    def allowed(permission, owner=None):

        if not session.is_active():
            messagebox.showerror(
                "Session expired",
                "Your session has expired. Please log in again."
            )
            logout()
            return False

        try:
            check_permission(
                session,
                permission,
                owner=owner
            )
            return True

        except PermissionDenied:
            messagebox.showerror(
                "Access denied",
                "You do not have permission for this action."
            )
            return False

    def select_own_encrypted_file():

        if not user_vault.is_dir():
            messagebox.showerror(
                "No files",
                "Your vault does not contain encrypted files yet."
            )
            return None

        source = filedialog.askopenfilename(
            parent=root,
            title="Select your encrypted SecureVault file",
            initialdir=str(user_vault),
            filetypes=[
                ("SecureVault encrypted files", "*.svlt")
            ]
        )

        if not source:
            return None

        if not is_managed_file(source, user_vault):
            messagebox.showerror(
                "Access denied",
                "Please select an encrypted file inside your vault."
            )
            return None

        return Path(source)

    # ---------------------------------------
    # Encrypt File
    # ---------------------------------------

    def encrypt_selected_file():

        if not allowed("encrypt"):
            return

        source = filedialog.askopenfilename(
            parent=root,
            title="Choose a file to encrypt"
        )

        if not source:
            return

        password = simpledialog.askstring(
            "Encryption password",
            "Enter an encryption password (minimum 12 characters):",
            show="*",
            parent=root
        )

        if password is None:
            return

        if len(password) < 12:
            messagebox.showerror(
                "Invalid password",
                "The encryption password must contain at least 12 characters."
            )
            return

        try:
            user_vault.mkdir(parents=True, exist_ok=True)

            # Use a new unpredictable filename.
            output = user_vault / (
                Path(source).name
                + "."
                + uuid4().hex
                + ".svlt"
            )

            if output.exists():
                raise FileExistsError("Encrypted file already exists.")

            hmac_key = encrypt_file(
                source,
                str(output),
                password
            )

            try:
                save_hmac_metadata(output, hmac_key)
            except Exception:
                # Avoid leaving a new vault entry without its
                # associated HMAC metadata.
                output.unlink(missing_ok=True)
                raise

            log.info(
                "FILE ENCRYPTED user=%s",
                session.username
            )

            status.set(
                "Encryption successful:\n" + str(output)
            )

            messagebox.showinfo(
                "Encryption successful",
                "Your file was encrypted successfully.\n\n"
                "Location:\n" + str(output)
            )

        except Exception:
            log.exception(
                "ENCRYPTION FAILED user=%s",
                session.username
            )
            messagebox.showerror(
                "Encryption failed",
                "The selected file could not be encrypted."
            )

    # ---------------------------------------
    # Decrypt File
    # ---------------------------------------

    def decrypt_selected_file():

        if not allowed("decrypt", owner=session.username):
            return

        source = select_own_encrypted_file()

        if source is None:
            return

        password = simpledialog.askstring(
            "Decryption password",
            "Enter the password used to encrypt this file:",
            show="*",
            parent=root
        )

        if password is None:
            return

        try:
            integrity_result = verify_encrypted_hmac(
                source,
                password
            )

            if integrity_result is False:
                log.warning(
                    "HMAC CHECK FAILED user=%s",
                    session.username
                )
                messagebox.showerror(
                    "Integrity error",
                    "File integrity verification failed."
                )
                return

            output_dir = user_vault / "decrypted"
            output_dir.mkdir(parents=True, exist_ok=True)

            # Original naming format:
            # filename.txt.uuid.svlt
            parts = source.name.rsplit(".", 2)

            if len(parts) == 3 and parts[-1] == "svlt":
                original_name = parts[0]
            else:
                original_name = source.stem

            output = output_dir / (
                uuid4().hex
                + "_"
                + Path(original_name).name
            )

            if output.exists():
                raise FileExistsError("Output file already exists.")

            decrypt_file(
                str(source),
                str(output),
                password
            )

            log.info(
                "FILE DECRYPTED user=%s",
                session.username
            )

            status.set(
                "Decryption successful:\n" + str(output)
            )

            messagebox.showinfo(
                "Decryption successful",
                "File decrypted successfully.\n\n"
                "Restored file:\n" + str(output)
            )

        except (DecryptionError, ValueError):
            log.warning(
                "FILE DECRYPTION REJECTED user=%s",
                session.username
            )
            messagebox.showerror(
                "Decryption failed",
                "Wrong password, corrupted file or invalid metadata."
            )

        except Exception:
            log.exception(
                "DECRYPTION FAILED user=%s",
                session.username
            )
            messagebox.showerror(
                "Decryption failed",
                "The file could not be decrypted."
            )

    # ---------------------------------------
    # HMAC Integrity Verification
    # ---------------------------------------

    def verify_integrity():

        if not allowed("decrypt", owner=session.username):
            return

        source = select_own_encrypted_file()

        if source is None:
            return

        password = simpledialog.askstring(
            "HMAC verification",
            "Enter the file's encryption password:",
            show="*",
            parent=root
        )

        if password is None:
            return

        try:
            result = verify_encrypted_hmac(
                source,
                password
            )

            if result is None:
                messagebox.showwarning(
                    "HMAC unavailable",
                    "This file has no saved HMAC metadata.\n\n"
                    "Encrypt a new file with this version "
                    "to demonstrate HMAC verification."
                )
                return

            if result:
                log.info(
                    "HMAC VERIFIED user=%s",
                    session.username
                )
                messagebox.showinfo(
                    "Integrity verified",
                    "PASSED - HMAC-SHA256 integrity verification succeeded."
                )
                status.set("HMAC integrity verification PASSED.")

            else:
                log.warning(
                    "HMAC MISMATCH user=%s",
                    session.username
                )
                messagebox.showerror(
                    "File tampering detected",
                    "FAILED - File integrity verification did not match."
                )
                status.set("HMAC integrity verification FAILED.")

        except (DecryptionError, ValueError):
            log.warning(
                "INTEGRITY VERIFICATION REJECTED user=%s",
                session.username
            )
            messagebox.showerror(
                "Integrity verification failed",
                "Wrong password, corrupted file or invalid HMAC metadata."
            )

        except Exception:
            log.exception(
                "HMAC ERROR user=%s",
                session.username
            )
            messagebox.showerror(
                "Integrity error",
                "The integrity check could not be completed."
            )

    # ---------------------------------------
    # Secure File Deletion
    # ---------------------------------------

    def delete_selected_file():

        if not allowed("delete", owner=session.username):
            return

        source = select_own_encrypted_file()

        if source is None:
            return

        confirmed = messagebox.askyesno(
            "Confirm secure deletion",
            "Are you sure you want to overwrite and delete\n"
            "this encrypted file?\n\n"
            + source.name
            + "\n\nThis action cannot be undone.",
            parent=root
        )

        if not confirmed:
            return

        # Check authorization again immediately before deletion.
        if not allowed("delete", owner=session.username):
            return

        if not is_managed_file(source, user_vault):
            messagebox.showerror(
                "Deletion denied",
                "The selected file is no longer valid."
            )
            return

        try:
            result = secure_delete(str(source))

            if not result:
                raise OSError("Secure deletion did not complete.")

            # Remove the matching HMAC metadata.
            metadata_path = hmac_metadata_path(source)

            if metadata_path.is_file() and not metadata_path.is_symlink():
                metadata_path.unlink()

            log.warning(
                "FILE SECURELY DELETED user=%s",
                session.username
            )

            status.set("File deletion completed.")

            messagebox.showinfo(
                "Deletion completed",
                "The encrypted file was overwritten and removed.\n\n"
                "Note: overwriting is best effort and does not "
                "guarantee physical erasure on SSDs or backups."
            )

        except Exception:
            log.exception(
                "SECURE DELETION ERROR user=%s",
                session.username
            )
            messagebox.showerror(
                "Deletion error",
                "The operation could not be completed fully."
            )

    # ---------------------------------------
    # Homomorphic Encryption Simulation
    # ---------------------------------------

    def show_homomorphic_demo():

        if not allowed("encrypt"):
            return

        demo = SimpleHomomorphicDemo(secret_key=1000)

        a = 25
        b = 15

        encrypted_a = demo.encrypt(a)
        encrypted_b = demo.encrypt(b)

        encrypted_result = demo.add_encrypted_values(
            encrypted_a,
            encrypted_b
        )

        result = demo.decrypt(encrypted_result)

        messagebox.showinfo(
            "Homomorphic Encryption Simulation",
            f"Original values: {a} and {b}\n\n"
            f"Transformed A: {encrypted_a}\n"
            f"Transformed B: {encrypted_b}\n\n"
            f"Transformed result: {encrypted_result}\n"
            f"Recovered result: {result}\n\n"
            "Educational simulation only; "
            "not real homomorphic encryption."
        )

        log.info(
            "HE SIMULATION RUN user=%s",
            session.username
        )

    # ---------------------------------------
    # ZKP Simulation
    # ---------------------------------------

    def show_zkp_demo():

        if not allowed("encrypt"):
            return

        secret = simpledialog.askstring(
            "ZKP Simulation",
            "Create a temporary demonstration secret:",
            show="*",
            parent=root
        )

        if secret is None:
            return

        nonce = secrets.token_hex(16)

        commitment = create_commitment(
            secret,
            nonce
        )

        verification = simpledialog.askstring(
            "ZKP Verification",
            "Enter the same secret again:",
            show="*",
            parent=root
        )

        if verification is None:
            return

        result = verify_proof(
            commitment,
            verification,
            nonce
        )

        if result:
            messagebox.showinfo(
                "ZKP Simulation",
                "PASSED - The secret was verified.\n\n"
                "This is a simplified commitment demonstration, "
                "not a complete zero-knowledge proof."
            )
        else:
            messagebox.showerror(
                "ZKP Simulation",
                "FAILED - The entered secret was incorrect."
            )

        log.info(
            "ZKP SIMULATION RUN user=%s",
            session.username
        )

    # ---------------------------------------
    # Differential Privacy Simulation
    # ---------------------------------------

    def show_dp_demo():

        if not allowed("encrypt"):
            return

        true_count = 10

        epsilon_small = 0.5
        epsilon_large = 5.0

        result_small = private_count(
            true_count,
            epsilon_small
        )

        result_large = private_count(
            true_count,
            epsilon_large
        )

        messagebox.showinfo(
            "Differential Privacy Simulation",
            f"Actual record count: {true_count}\n\n"
            f"Epsilon 0.5: {result_small:.2f}\n"
            f"Epsilon 5.0: {result_large:.2f}\n\n"
            "Smaller epsilon generally adds more noise.\n"
            "Larger epsilon generally adds less noise.\n\n"
            "Individual random results may vary."
        )

        log.info(
            "DP SIMULATION RUN user=%s",
            session.username
        )

    # ---------------------------------------
    # Security Logs
    # ---------------------------------------

    def view_security_logs():

        if not allowed("view_logs"):
            return

        if not LOG_FILE.is_file():
            messagebox.showinfo(
                "Security logs",
                "No security log is available yet."
            )
            return

        try:
            with open(
                LOG_FILE,
                "r",
                encoding="utf-8",
                errors="replace"
            ) as file:
                recent_lines = file.readlines()[-60:]

            log_window = tk.Toplevel(root)
            log_window.title("SecureVault Security Logs")
            log_window.geometry("850x450")

            text_box = tk.Text(
                log_window,
                wrap="word"
            )

            text_box.pack(
                fill="both",
                expand=True,
                padx=10,
                pady=10
            )

            text_box.insert(
                "1.0",
                "".join(recent_lines)
            )

            text_box.configure(state="disabled")

        except Exception:
            log.exception("LOG VIEW ERROR")
            messagebox.showerror(
                "Log error",
                "Unable to read the security log."
            )

    # ---------------------------------------
    # GUI Buttons
    # ---------------------------------------

    ttk.Button(
        frame,
        text="Encrypt File",
        command=encrypt_selected_file,
        width=36
    ).pack(pady=5)

    ttk.Button(
        frame,
        text="Decrypt File",
        command=decrypt_selected_file,
        width=36
    ).pack(pady=5)

    ttk.Button(
        frame,
        text="Verify HMAC Integrity",
        command=verify_integrity,
        width=36
    ).pack(pady=5)

    ttk.Button(
        frame,
        text="Securely Delete Encrypted File",
        command=delete_selected_file,
        width=36
    ).pack(pady=5)

    ttk.Separator(
        frame,
        orient="horizontal"
    ).pack(fill="x", pady=10)

    ttk.Label(
        frame,
        text="Advanced Security Simulations",
        font=("Arial", 12, "bold")
    ).pack(pady=6)

    ttk.Button(
        frame,
        text="Homomorphic Encryption Simulation",
        command=show_homomorphic_demo,
        width=36
    ).pack(pady=4)

    ttk.Button(
        frame,
        text="Zero-Knowledge Proof Simulation",
        command=show_zkp_demo,
        width=36
    ).pack(pady=4)

    ttk.Button(
        frame,
        text="Differential Privacy Simulation",
        command=show_dp_demo,
        width=36
    ).pack(pady=4)

    ttk.Separator(
        frame,
        orient="horizontal"
    ).pack(fill="x", pady=10)

    if session.role in ("admin", "auditor"):
        ttk.Button(
            frame,
            text="View Security Logs",
            command=view_security_logs,
            width=36
        ).pack(pady=5)

    ttk.Label(
        frame,
        textvariable=status,
        wraplength=730,
        justify="center"
    ).pack(pady=10)

    # ---------------------------------------
    # Logout
    # ---------------------------------------

    def logout():
        try:
            auth.logout(session)
        finally:
            root.destroy()

    ttk.Button(
        frame,
        text="Log Out",
        command=logout,
        width=25
    ).pack(pady=8)

    root.protocol(
        "WM_DELETE_WINDOW",
        logout
    )

    root.mainloop()


if __name__ == "__main__":
    main()
