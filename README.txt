SecureVault - Person 5 Code
===========================
Files in this ZIP are the Person 5 deployment/monitoring contribution.

security_logger.py
- Configures centralized SecureVault logging.
- Writes to logs/security.log.
- Uses RotatingFileHandler (1 MB, 5 backups).

monitor_logs.py
- Displays the most recent security events.

Integration:
1. Place both files in the main SecureVault project folder.
2. At application startup:
       from security_logger import configure_security_logging
       configure_security_logging()
3. Authentication code using logging.getLogger("securevault.auth") will be
   captured by the parent securevault logger.
4. Run:
       python3 monitor_logs.py

Important:
- Do not include passwords, TOTP secrets, QR codes or live one-time codes in reports.
- The full authentication/backend code belongs to the integrated group project;
  this ZIP intentionally contains only Person 5's own code.
