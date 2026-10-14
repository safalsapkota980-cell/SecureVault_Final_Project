"""
create_user.py - Register a user and display the 2FA QR code.
Run before the demo:   python create_user.py alice user
                       python create_user.py admin1 admin
Scan the QR with Google/Microsoft Authenticator.
"""
import getpass
import sys

import qrcode

from auth import AuthManager, ROLE_PERMISSIONS


def main():
    if len(sys.argv) != 3 or sys.argv[2] not in ROLE_PERMISSIONS:
        print(f"Usage: python create_user.py <username> <{'|'.join(ROLE_PERMISSIONS)}>")
        sys.exit(1)
    username, role = sys.argv[1], sys.argv[2]

    password = getpass.getpass("Password: ")
    if password != getpass.getpass("Confirm password: "):
        print("Passwords do not match.")
        sys.exit(1)

    auth = AuthManager()
    try:
        uri = auth.create_user(username, password, role)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    qr = qrcode.QRCode(border=1)
    qr.add_data(uri)
    qr.print_ascii(invert=True)                 # scan from the terminal
    png = f"{username.lower()}_2fa.png"
    qrcode.make(uri).save(png)
    print(f"\nUser '{username}' created with role '{role}'.")
    print(f"QR also saved to {png} - scan it, then DELETE the file (it contains the secret).")


if __name__ == "__main__":
    main()
