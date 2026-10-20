import time
import os
from datetime import datetime

# Path file log target (bisa disesuaikan ke test_access.log atau /var/log/nginx/access.log)
TARGET_LOG = "test_access.log"

SAMPLE_IPS = [
    ("103.28.12.5", "GET / HTTP/1.1", 200, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
    ("1.1.1.1", "GET /blog/artikel-1 HTTP/1.1", 200, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"),
    ("8.8.8.8", "GET /about-us HTTP/1.1", 200, "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X)"),
]

ATTACKER_IP = "185.220.101.5" # IP attacker simulasi (Tor exit node / scan bot)
SENSITIVE_TARGET = "POST /wp-login.php HTTP/1.1"

def append_log(ip: str, request: str, status: int, ua: str):
    now_str = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0700")
    line = f'{ip} - - [{now_str}] "{request}" {status} 1234 "-" "{ua}"\n'
    with open(TARGET_LOG, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
    print(f"Log written: {ip} -> {request} [{status}]")

def main():
    print(f"Mulai simulasi log ke {TARGET_LOG}...")
    
    # 1. Tulis beberapa log normal
    for ip, req, status, ua in SAMPLE_IPS:
        append_log(ip, req, status, ua)
        time.sleep(0.5)

    print("\n--- Memulai Simulasi Brute-Force Attack (> 15 hit berturut-turut ke endpoint sensitif) ---")
    for i in range(1, 15):
        append_log(
            ATTACKER_IP,
            SENSITIVE_TARGET,
            401,
            "python-requests/2.28.1 (BruteForceTool)"
        )
        time.sleep(0.1)

    print("\nSimulasi selesai! Periksa notifikasi Telegram Alert Anda.")

if __name__ == "__main__":
    main()
