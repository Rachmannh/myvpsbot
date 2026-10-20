import os
import sys
import time
import signal
import logging
import threading
from collections import Counter
from datetime import datetime
from typing import Dict, Any

from config import (
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    LOG_FILE_PATH,
    GEOIP_DB_PATH,
    RATE_LIMIT_THRESHOLD,
    RATE_LIMIT_WINDOW_SECONDS,
    REPORT_INTERVAL_SECONDS,
    ALERT_COOLDOWN_SECONDS,
    SENSITIVE_PATHS
)
from geoip_helper import GeoIPLookup
from log_parser import parse_log_line
from detector import ThreatDetector
from bot import TelegramNotifier, get_vps_status_metrics

# Konfigurasi Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("vps_bot.main")

class LogMonitorService:
    def __init__(self):
        self.running = True

        # Inisialisasi Komponen
        self.geoip = GeoIPLookup(GEOIP_DB_PATH)
        self.detector = ThreatDetector(
            threshold=RATE_LIMIT_THRESHOLD,
            window_seconds=RATE_LIMIT_WINDOW_SECONDS,
            cooldown_seconds=ALERT_COOLDOWN_SECONDS,
            sensitive_paths=SENSITIVE_PATHS
        )
        self.bot = TelegramNotifier(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID)

        # Statistik Sesi
        self.stats_lock = threading.Lock()
        self.session_start = datetime.now()
        self.total_hits = 0
        self.ip_counter: Counter = Counter()
        self.country_counter: Counter = Counter()
        self.status_counter: Counter = Counter()
        self.last_hit_info: Dict[str, Any] = {}

        # Registrasi Handler Perintah Telegram
        self._setup_bot_commands()

    def _setup_bot_commands(self):
        self.bot.register_command("/status", self._cmd_status)
        self.bot.register_command("/top_ips", self._cmd_top_ips)
        self.bot.register_command("/stats", self._cmd_stats)

    def _cmd_status(self) -> str:
        vps = get_vps_status_metrics()
        with self.stats_lock:
            hits = self.total_hits
            unique_ips = len(self.ip_counter)
            last_hit = self.last_hit_info

        last_str = "-"
        if last_hit:
            last_str = f"{last_hit.get('ip')} ({last_hit.get('method')} {last_hit.get('endpoint')}) @ {last_hit.get('time')}"

        return (
            "🖥 <b>STATUS KESEHATAN VPS & MONITOR</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"⚡ <b>CPU:</b> {vps['cpu_percent']}% ({vps['cpu_count']} Cores)\n"
            f"🧠 <b>RAM:</b> {vps['ram_used_gb']:.2f} GB / {vps['ram_total_gb']:.2f} GB ({vps['ram_percent']}%)\n"
            f"💾 <b>Disk:</b> {vps['disk_used_gb']:.1f} GB / {vps['disk_total_gb']:.1f} GB ({vps['disk_percent']}%)\n"
            f"⏱ <b>Uptime VPS:</b> {vps['uptime']}\n\n"
            "📊 <b>Statistik Log Sesi Ini:</b>\n"
            f"• Total Hits Diproses: <b>{hits:,}</b>\n"
            f"• Unique IPs: <b>{unique_ips:,}</b>\n"
            f"• Akses Terakhir: <code>{last_str}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🕒 <i>Waktu Server: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
        )

    def _cmd_top_ips(self) -> str:
        with self.stats_lock:
            top = self.ip_counter.most_common(10)

        if not top:
            return "ℹ️ Belum ada data kunjungan IP yang tercatat sejak service dimulai."

        lines = ["🏆 <b>TOP 10 IP PENGUNJUNG TERBANYAK:</b>", "━━━━━━━━━━━━━━━━━━━━━━"]
        for idx, (ip, count) in enumerate(top, 1):
            geo = self.geoip.lookup(ip)
            country = geo.get("country", "Unknown")
            code = geo.get("country_code", "??")
            lines.append(f"{idx}. <code>{ip}</code> ({country} - {code}) — <b>{count}</b> hits")

        lines.append("━━━━━━━━━━━━━━━━━━━━━━")
        return "\n".join(lines)

    def _cmd_stats(self) -> str:
        with self.stats_lock:
            status_items = sorted(self.status_counter.items())
            total = self.total_hits
            top_countries = self.country_counter.most_common(5)

        status_str = "\n".join([f"  • HTTP {code}: <b>{count}</b>" for code, count in status_items]) or "  - Belum ada data"
        country_str = "\n".join([f"  • {c}: <b>{cnt}</b> hits" for c, cnt in top_countries]) or "  - Belum ada data"

        return (
            "📈 <b>STATISTIK KUNJUNGAN & STATUS CODE</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"Total Akses: <b>{total:,}</b> requests\n\n"
            f"🏷 <b>Status Code HTTP:</b>\n{status_str}\n\n"
            f"🌍 <b>Top Negara:</b>\n{country_str}\n"
            "━━━━━━━━━━━━━━━━━━━━━━"
        )

    def _process_line(self, line: str):
        parsed = parse_log_line(line)
        if not parsed:
            return

        ip = parsed["ip"]
        endpoint = parsed["endpoint"]
        method = parsed["method"]
        status_code = parsed["status_code"]
        user_agent = parsed["user_agent"]

        geo = self.geoip.lookup(ip)
        country = geo.get("country", "Unknown")

        # Update Statistik
        with self.stats_lock:
            self.total_hits += 1
            self.ip_counter[ip] += 1
            self.country_counter[country] += 1
            if status_code:
                self.status_counter[status_code] += 1
            self.last_hit_info = {
                "ip": ip,
                "method": method,
                "endpoint": endpoint,
                "time": datetime.now().strftime("%H:%M:%S")
            }

        # Analisis Ancaman (Security Alert)
        is_threat, reason, hits = self.detector.process_hit(ip, endpoint)
        if is_threat and reason:
            logger.warning(f"THREAT DETECTED: {ip} - {reason}")
            self.bot.send_security_alert(
                ip=ip,
                geo=geo,
                method=method,
                endpoint=endpoint,
                status_code=status_code,
                user_agent=user_agent,
                reason=reason,
                hits=hits
            )

    def _scheduled_reporter_loop(self):
        """Loop latar belakang untuk mengirimkan laporan berkala ke Telegram."""
        while self.running:
            time.sleep(REPORT_INTERVAL_SECONDS)
            if not self.running:
                break
            try:
                with self.stats_lock:
                    if self.total_hits == 0:
                        continue

                    top_ips_raw = self.ip_counter.most_common(5)
                    top_ips = [
                        (ip, count, self.geoip.lookup(ip).get("country", "??"))
                        for ip, count in top_ips_raw
                    ]

                    stats = {
                        "total_hits": self.total_hits,
                        "unique_ips_count": len(self.ip_counter),
                        "top_ips": top_ips,
                        "top_countries": self.country_counter.most_common(5),
                        "status_codes": dict(self.status_counter),
                        "interval_desc": f"{REPORT_INTERVAL_SECONDS // 3600} Jam" if REPORT_INTERVAL_SECONDS >= 3600 else f"{REPORT_INTERVAL_SECONDS // 60} Menit"
                    }

                self.bot.send_summary_report(stats)
            except Exception as e:
                logger.error(f"Gagal mengirimkan laporan berkala: {e}")

    def tail_log_file(self):
        """
        Membaca file log secara terus-menerus (seperti tail -F),
        mendukung deteksi logrotate (inode / size change).
        """
        if not os.path.exists(LOG_FILE_PATH):
            logger.warning(f"File log {LOG_FILE_PATH} belum ditemukan. Menunggu file dibuat...")
            while self.running and not os.path.exists(LOG_FILE_PATH):
                time.sleep(3)

        logger.info(f"Mulai memonitor log di: {LOG_FILE_PATH}")
        try:
            file_obj = open(LOG_FILE_PATH, "r", encoding="utf-8", errors="replace")
            # Lompat ke akhir file agar tidak spam memproses seluruh histori lama saat baru start
            file_obj.seek(0, os.SEEK_END)
            current_inode = os.fstat(file_obj.fileno()).st_ino
        except Exception as e:
            logger.error(f"Gagal membuka file log {LOG_FILE_PATH}: {e}")
            return

        while self.running:
            line = file_obj.readline()
            if line:
                self._process_line(line)
            else:
                # Periksa apakah file telah di-rotate oleh logrotate
                time.sleep(0.2)
                try:
                    if os.path.exists(LOG_FILE_PATH):
                        new_inode = os.stat(LOG_FILE_PATH).st_ino
                        if new_inode != current_inode:
                            logger.info("Logrotate terdeteksi! Membuka ulang file log baru...")
                            file_obj.close()
                            file_obj = open(LOG_FILE_PATH, "r", encoding="utf-8", errors="replace")
                            current_inode = os.fstat(file_obj.fileno()).st_ino
                    else:
                        time.sleep(1)
                except Exception as e:
                    logger.debug(f"Pemeriksaan inode logrotate error: {e}")

        file_obj.close()

    def start(self):
        logger.info("VPS Log Monitor & Security Bot sedang berjalan...")

        # Jalankan Telegram command listener
        self.bot.start_polling()

        # Jalankan scheduled reporter thread
        reporter_thread = threading.Thread(target=self._scheduled_reporter_loop, daemon=True)
        reporter_thread.start()

        # Notifikasi boot ke admin Telegram
        self.bot.send_message(
            "🚀 <b>VPS Log Monitor Aktif!</b>\n"
            f"File: <code>{LOG_FILE_PATH}</code>\n"
            f"Waktu Mulai: {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}\n"
            "Ketik /help untuk opsi perintah."
        )

        # Jalankan loop tailing log (blokir di thread utama)
        try:
            self.tail_log_file()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        logger.info("Menghentikan service...")
        self.running = False
        self.bot.stop_polling()
        self.geoip.close()
        logger.info("Service berhenti.")

def main():
    service = LogMonitorService()

    def signal_handler(sig, frame):
        logger.info("Menerima sinyal terminasi (SIGINT/SIGTERM).")
        service.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    service.start()

if __name__ == "__main__":
    main()
