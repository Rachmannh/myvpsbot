# 🛡️ VPS Nginx / Apache Log Monitor & Telegram Security Bot

Sistem backend monitoring log akses web server (Nginx / Apache) secara real-time yang dirancang khusus untuk VPS (4 vCPU, 4 GB RAM, 60 GB SSD). Terintegrasi langsung dengan Telegram Bot untuk **Security Alerts (deteksi brute-force/spam)**, **Laporan Berkala**, dan **Perintah Interaktif** (`/status`, `/top_ips`, `/stats`).

---

## 🌟 Fitur Utama

1. **Pemrosesan Log Real-Time (Combined Log Format):**
   - IP Pengunjung & Resolusi Negara Asal (MaxMind GeoLite2 Lokal + Fallback Web API).
   - Timestamp & Metode/Endpoint (`GET /login`, `POST /api/v1/auth`, dsb).
   - HTTP Status Code & User-Agent.
   - Deteksi rotasi log otomatis (*Logrotate friendly*).

2. **Deteksi Ancaman Keamanan (Instant Alert):**
   - *Sliding-window algorithm* untuk mendeteksi flooding/spam (>20 request dalam 60 detik).
   - Deteksi serangan ke *sensitive endpoints* (`/wp-login.php`, `/.env`, `/admin`, `/login`, `/xmlrpc.php`, dll).
   - Fitur *Notification Cooldown* untuk mencegah flooding pesan Telegram saat serangan masif berlangsung.

3. **Laporan Ringkasan Berkala (Scheduled Report):**
   - Rekap total requests, unique visitors, top 5 IP pengunjung, dan negara asal secara berkala (default per jam).

4. **Perintah Interaktif (Telegram Commands):**
   - `/status` : Status beban server (CPU %, RAM, Disk, Uptime via `psutil`) & status monitor log.
   - `/top_ips` : Daftar 10 IP pengunjung teratas beserta negara asal.
   - `/stats` : Distribusi status code HTTP (200, 404, 500, dll) dan statistik negara.
   - `/help` : Daftar bantuan perintah.

---

## 📋 Struktur Direktori Proyek

```text
/opt/vps-bot/
├── .env.example            # Template konfigurasi environment
├── .env                    # Konfigurasi aktif (Token, Chat ID, Path Log)
├── requirements.txt        # Dependensi Python
├── config.py               # Pemuat variabel lingkungan
├── geoip_helper.py         # Modul GeoIP (MaxMind MMDB + Fallback API)
├── log_parser.py           # Parser Nginx & Apache Combined Log
├── detector.py             # Algoritma deteksi brute-force & spam
├── bot.py                  # Interaksi API Telegram & Perintah Bot
├── main.py                 # Service orchestrator & Log tailer
├── simulate_traffic.py     # Script pengujian traffic & simulasi serangan
└── vps-logbot.service      # Unit file systemd untuk background service
```

---

## 🚀 Panduan Instalasi di VPS (Ubuntu / Debian)

### 1. Update Server & Instalasi Dependensi Sistem

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv git curl
```

### 2. Instalasi Database GeoIP (MaxMind GeoLite2)

Bot ini memiliki **built-in fallback** ke `ip-api.com` sehingga bisa langsung bekerja tanpa file lokal. Namun untuk performa tercepat tanpa batasan request, disarankan memasang GeoLite2 lokal:

```bash
# Buat direktori GeoIP
sudo mkdir -p /usr/share/GeoIP

# Opsi Cepat (Download database mmdb langsung):
cd /usr/share/GeoIP
sudo curl -fsSL -o GeoLite2-City.mmdb "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
```

*(Catatan: Anda juga bisa mendaftar akun gratis di [maxmind.com](https://www.maxmind.com) dan memasang utilitas resmi `geoipupdate`)*.

---

### 3. Setup Token Telegram Bot & Chat ID

1. **Buat Bot Baru:**
   - Buka Telegram dan cari [@BotFather](https://t.me/botfather).
   - Kirim `/newbot`, ikuti langkah hingga mendapatkan **Bot Token** (contoh: `123456789:ABCdefGHIjklmnOPQRstuvwxyz`).

2. **Dapatkan Chat ID Anda:**
   - Cari bot [@userinfobot](https://t.me/userinfobot) di Telegram lalu ketik `/start`.
   - Salin angka **Id** Anda (contoh: `987654321`).

---

### 4. Deploy Skrip ke VPS

Letakkan kode program di `/opt/vps-bot`:

```bash
sudo mkdir -p /opt/vps-bot
# Salin semua file proyek ini ke /opt/vps-bot
cd /opt/vps-bot

# Buat virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependensi Python
pip install --upgrade pip
pip install -r requirements.txt

# Buat file konfigurasi .env
cp .env.example .env
nano .env
```

Sesuaikan isi `.env`:
```ini
TELEGRAM_BOT_TOKEN="123456789:ABCdefGHIjklmnOPQRstuvwxyz"
TELEGRAM_CHAT_ID="987654321"

# Sesuaikan dengan server Anda:
# Nginx: /var/log/nginx/access.log
# Apache: /var/log/apache2/access.log
LOG_FILE_PATH="/var/log/nginx/access.log"

GEOIP_DB_PATH="/usr/share/GeoIP/GeoLite2-City.mmdb"
RATE_LIMIT_THRESHOLD=20
RATE_LIMIT_WINDOW_SECONDS=60
REPORT_INTERVAL_SECONDS=3600
```

---

### 5. Konfigurasi Systemd (Jalankan sebagai Background Service 24/7)

Salin unit file service ke direktori systemd:

```bash
sudo cp /opt/vps-bot/vps-logbot.service /etc/systemd/system/

# Reload systemd daemon
sudo systemctl daemon-reload

# Aktifkan auto-start saat VPS booting dan langsung jalankan service
sudo systemctl enable --now vps-logbot
```

**Perintah Manajemen Service:**
```bash
# Cek status service
sudo systemctl status vps-logbot

# Melihat log running secara real-time
sudo journalctl -u vps-logbot -f

# Restart service
sudo systemctl restart vps-logbot

# Stop service
sudo systemctl stop vps-logbot
```

---

## 🧪 Pengujian & Simulasi Serangan

Untuk memastikan deteksi bekerja tanpa harus menunggu attacker asli:

1. Edit konfigurasi di `simulate_traffic.py` jika ingin mengarahkan ke log pengujian:
   ```bash
   python simulate_traffic.py
   ```
2. Skrip akan mengirimkan request cepat ke endpoint `/wp-login.php`.
3. Cek aplikasi Telegram Anda, bot akan langsung mengirimkan pesan **🚨 SECURITY ALERT** lengkap dengan alamat IP, lokasi negara, jumlah request, dan user-agent attacker.
"# myvpsbot" 
