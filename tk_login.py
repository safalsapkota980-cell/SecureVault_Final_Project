"""
tk_login.py - Tkinter login dialog (password -> 2FA code).

Integration with the main GUI:
    from auth import AuthManager
    from tk_login import show_login

    auth = AuthManager()
    session = show_login(auth)          # or show_login(auth, master=root)
    if session is None:
        sys.exit()                      # fail-secure: no session, no app
    # pass `session` to every encrypt/decrypt/delete call

Run this file directly for a standalone demo of login + role permissions.
"""
import tkinter as tk
from tkinter import ttk

from auth import AuthError, AuthManager, ROLE_PERMISSIONS, GENERIC_ERROR


class LoginDialog(tk.Toplevel):
    def __init__(self, master, auth: AuthManager):
        super().__init__(master)
        self.auth = auth
        self.session = None
        self.title("SecureVault - Sign in")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        self.status = tk.StringVar()
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.code = tk.StringVar()

        self.body = ttk.Frame(self, padding=20)
        self.body.pack(fill="both", expand=True)
        ttk.Label(self, textvariable=self.status, foreground="#b00020",
                  padding=(20, 0, 20, 12)).pack()

        self._show_password_step()
        self.grab_set()                        # modal
        self.lift()
        self.focus_force()

    def _clear(self):
        for w in self.body.winfo_children():
            w.destroy()

    # ---------- step 1
    def _show_password_step(self):
        self._clear()
        self.password.set("")
        ttk.Label(self.body, text="Sign in", font=("", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 12))
        ttk.Label(self.body, text="Username").grid(row=1, column=0, sticky="w")
        user_entry = ttk.Entry(self.body, textvariable=self.username, width=28)
        user_entry.grid(row=1, column=1, pady=4)
        ttk.Label(self.body, text="Password").grid(row=2, column=0, sticky="w")
        pw_entry = ttk.Entry(self.body, textvariable=self.password, show="•", width=28)
        pw_entry.grid(row=2, column=1, pady=4)
        ttk.Button(self.body, text="Next", command=self._submit_password).grid(row=3, column=0, columnspan=2, pady=(12, 0), sticky="ew")
        self.bind("<Return>", lambda e: self._submit_password())
        (pw_entry if self.username.get() else user_entry).focus_set()

    def _submit_password(self):
        ok = self.auth.verify_password(self.username.get(), self.password.get())
        self.password.set("")                  # don't keep the password in memory longer than needed
        if ok:
            self.status.set("")
            self._show_code_step()
        else:
            self.status.set(GENERIC_ERROR)

    # ---------- step 2
    def _show_code_step(self):
        self._clear()
        self.code.set("")
        ttk.Label(self.body, text="Two-factor authentication", font=("", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 8))
        ttk.Label(self.body, text="Enter the 6-digit code from your authenticator app.").grid(row=1, column=0, columnspan=2, pady=(0, 8))
        entry = ttk.Entry(self.body, textvariable=self.code, width=12, justify="center", font=("", 16))
        entry.grid(row=2, column=0, columnspan=2, pady=4)
        ttk.Button(self.body, text="Verify", command=self._submit_code).grid(row=3, column=0, columnspan=2, pady=(12, 0), sticky="ew")
        ttk.Button(self.body, text="Back", command=self._show_password_step).grid(row=4, column=0, columnspan=2, pady=(4, 0), sticky="ew")
        self.bind("<Return>", lambda e: self._submit_code())
        entry.focus_set()

    def _submit_code(self):
        try:
            self.session = self.auth.verify_2fa(self.username.get(), self.code.get())
        except AuthError:
            # fail-secure: wrong code cancels the attempt, password needed again
            self.status.set(GENERIC_ERROR + " Please sign in again.")
            self._show_password_step()
            return
        self.destroy()


def show_login(auth: AuthManager, master: tk.Misc | None = None):
    """Block until the user signs in or closes the window. Returns Session or None."""
    own_root = master is None
    if own_root:
        master = tk.Tk()
        master.withdraw()
    dialog = LoginDialog(master, auth)
    master.wait_window(dialog)
    session = dialog.session
    if own_root:
        master.destroy()
    return session


# ---------------------------------------------------------------- demo
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    auth = AuthManager()
    session = show_login(auth)
    if session is None:
        raise SystemExit("No session - exiting.")

    root = tk.Tk()
    root.title("SecureVault")
    frame = ttk.Frame(root, padding=20)
    frame.pack()
    ttk.Label(frame, text=f"Signed in as {session.username} ({session.role})",
              font=("", 13, "bold")).pack(pady=(0, 10))
    for perm in sorted({p for perms in ROLE_PERMISSIONS.values() for p in perms}):
        allowed = session.can(perm, owner=session.username)
        ttk.Label(frame, text=f"{'✓' if allowed else '✗'}  {perm}",
                  foreground="#1b5e20" if allowed else "#b00020").pack(anchor="w")
    ttk.Button(frame, text="Log out", command=lambda: (auth.logout(session), root.destroy())).pack(pady=(12, 0))
    root.mainloop()
