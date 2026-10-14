"""Person 5: display recent SecureVault security events."""
from pathlib import Path

LOG_FILE = Path("logs/security.log")

def show_recent_events(limit=20):
    if not LOG_FILE.exists():
        print("No security log has been generated yet.")
        return
    lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    print("Showing the last {} security events:".format(min(limit, len(lines))))
    print("-" * 80)
    for line in lines[-limit:]:
        print(line)

if __name__ == "__main__":
    show_recent_events()
