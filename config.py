import os
from pathlib import Path
from dotenv import load_dotenv

# Load file .env jika ada
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

# Telegram
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

# Path Log
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "/var/log/nginx/access.log").strip()

# GeoIP
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "/usr/share/GeoIP/GeoLite2-City.mmdb").strip()

# Rate limit & Brute-force detector
RATE_LIMIT_THRESHOLD = int(os.getenv("RATE_LIMIT_THRESHOLD", "20"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

# Report schedule
REPORT_INTERVAL_SECONDS = int(os.getenv("REPORT_INTERVAL_SECONDS", "3600"))

# Alert cooldown (dalam detik, agar tidak spamming alert untuk IP yang sama)
ALERT_COOLDOWN_SECONDS = int(os.getenv("ALERT_COOLDOWN_SECONDS", "600"))

# Sensitive endpoints
raw_sensitive = os.getenv(
    "SENSITIVE_PATHS",
    "/wp-login.php,/xmlrpc.php,/admin,/login,/api/v1/auth,/.env,/config,/phpmyadmin"
)
SENSITIVE_PATHS = [p.strip().lower() for p in raw_sensitive.split(",") if p.strip()]
