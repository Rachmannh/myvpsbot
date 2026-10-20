import logging
import time
import threading
import requests
import psutil
from datetime import datetime, timedelta
from typing import Dict, Any, Callable, Optional, List

logger = logging.getLogger("vps_bot.telegram")

class TelegramNotifier:
    def __init__(self, token: str, chat_id: str):
        self.token = token
        self.chat_id = str(chat_id)
        self.base_url = f"https://api.telegram.org/bot{self.token}"
        self.last_update_id = 0
        self.is_running = False
        self.polling_thread = None
        self.command_handlers: Dict[str, Callable[[], str]] = {}

    def send_message(self, text: str, parse_mode: str = "HTML") -> bool:
        """Mengirim pesan teks ke Telegram Chat ID terdaftar."""
        if not self.token or not self.chat_id:
            logger.warning("Telegram Bot Token atau Chat ID belum diset.")
            return False

        url = f"{self.base_url}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True
        }
        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 200:
                return True
            else:
                logger.error(f"Gagal kirim pesan Telegram: {resp.status_code} - {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Exception saat kirim pesan Telegram: {e}")
            return False

    def send_security_alert(
        self,
        ip: str,
        geo: Dict[str, str],
        method: str,
        endpoint: str,
        status_code: int,
        user_agent: str,
        reason: str,
        hits: int
    ):
        """Mengirim pesan Security Alert instan."""
        country = geo.get("country", "Unknown")
        city = geo.get("city", "-")
        code = geo.get("country_code", "??")
        
        # Potong user-agent jika terlalu panjang
        ua_short = (user_agent[:120] + "...") if len(user_agent) > 120 else user_agent

        msg = (
            "🚨 <b>SECURITY ALERT: AKTIVITAS MENCURIGAKAN!</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"⚠️ <b>Pemicu:</b> {reason}\n"
            f"🌐 <b>IP Address:</b> <code>{ip}</code>\n"
            f"📍 <b>Lokasi:</b> {country} ({code}), {city}\n"
            f"🎯 <b>Target:</b> <code>{method} {endpoint}</code> (Status: {status_code})\n"
            f"📊 <b>Total Hits:</b> {hits} requests\n"
            f"🕒 <b>Waktu:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"🖥 <b>User-Agent:</b>\n<code>{ua_short}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "💡 <i>Saran: Periksa log atau pertimbangkan untuk memblokir IP ini via UFW / iptables jika berbahaya.</i>"
        )
        self.send_message(msg)

    def send_summary_report(self, stats: Dict[str, Any]):
        """Mengirim laporan ringkasan berkala."""
        total_hits = stats.get("total_hits", 0)
        unique_ips = stats.get("unique_ips_count", 0)
        top_ips = stats.get("top_ips", [])
        top_countries = stats.get("top_countries", [])
        status_codes = stats.get("status_codes", {})
        interval_desc = stats.get("interval_desc", "Berkala")

        top_ips_str = "\n".join([
            f"  • <code>{ip}</code> ({geo}) — <b>{count}</b> hits"
            for ip, count, geo in top_ips[:5]
        ]) or "  <i>Belum ada data</i>"

        top_countries_str = "\n".join([
            f"  • {c} — <b>{count}</b> hits"
            for c, count in top_countries[:5]
        ]) or "  <i>Belum ada data</i>"

        # Format status code
        status_str = ", ".join([f"{k}: {v}" for k, v in sorted(status_codes.items())]) or "-"

        msg = (
            f"📊 <b>RINGKASAN LOG AKSES ({interval_desc.upper()})</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📈 <b>Total Requests:</b> {total_hits:,}\n"
            f"👥 <b>Unique IPs:</b> {unique_ips:,}\n"
            f"🏷 <b>HTTP Status:</b> {status_str}\n\n"
            f"🏆 <b>Top 5 IP Pengunjung:</b>\n{top_ips_str}\n\n"
            f"🌍 <b>Top 5 Negara Asal:</b>\n{top_countries_str}\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🕒 <i>Dicatat pada: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
        )
        self.send_message(msg)

    def register_command(self, command: str, handler: Callable[[], str]):
        self.command_handlers[command.lower()] = handler

    def start_polling(self):
        """Memulai background thread untuk mendengarkan perintah dari Telegram."""
        if self.is_running:
            return
        self.is_running = True
        self.polling_thread = threading.Thread(target=self._poll_updates, daemon=True)
        self.polling_thread.start()
        logger.info("Telegram command polling thread started.")

    def stop_polling(self):
        self.is_running = False

    def _poll_updates(self):
        while self.is_running:
            try:
                url = f"{self.base_url}/getUpdates"
                params = {"offset": self.last_update_id + 1, "timeout": 20}
                resp = requests.get(url, params=params, timeout=25)
                if resp.status_code == 200:
                    data = resp.json()
                    for update in data.get("result", []):
                        self.last_update_id = update["update_id"]
                        msg = update.get("message")
                        if not msg:
                            continue
                        
                        sender_chat_id = str(msg.get("chat", {}).get("id"))
                        # Keamanan: Hanya proses perintah jika berasal dari Chat ID admin yang diizinkan
                        if sender_chat_id != self.chat_id:
                            logger.warning(f"Akses tidak sah dari chat_id: {sender_chat_id}")
                            continue

                        text = msg.get("text", "").strip()
                        if text.startswith("/"):
                            cmd = text.split()[0].split("@")[0].lower()
                            self._handle_command(cmd)
                time.sleep(1)
            except Exception as e:
                logger.debug(f"Polling update error (normal on network lag): {e}")
                time.sleep(5)

    def _handle_command(self, cmd: str):
        if cmd in self.command_handlers:
            try:
                response = self.command_handlers[cmd]()
                self.send_message(response)
            except Exception as e:
                self.send_message(f"❌ Terjadi kesalahan saat memproses perintah <code>{cmd}</code>: {e}")
        elif cmd in ["/start", "/help"]:
            help_text = (
                "🤖 <b>VPS Log Monitor & Security Bot</b>\n"
                "━━━━━━━━━━━━━━━━━━━━━━\n"
                "Daftar perintah yang tersedia:\n\n"
                "🔹 <code>/status</code> - Status performa VPS (CPU, RAM, Disk) & ringkasan log\n"
                "🔹 <code>/top_ips</code> - Daftar 10 IP pengunjung terbanyak\n"
                "🔹 <code>/stats</code> - Statistik pembagian HTTP status code\n"
                "🔹 <code>/help</code> - Menampilkan menu bantuan ini\n"
                "━━━━━━━━━━━━━━━━━━━━━━\n"
                "💡 <i>Bot ini memantau log secara real-time dan akan otomatis mengirim peringatan jika ada brute-force/spam.</i>"
            )
            self.send_message(help_text)
        else:
            self.send_message(f"❓ Perintah <code>{cmd}</code> tidak dikenal. Ketik /help untuk melihat menu.")

def get_vps_status_metrics() -> Dict[str, Any]:
    """Mengambil metrik performa VPS (CPU, RAM, Disk, Uptime) via psutil."""
    # CPU
    cpu_percent = psutil.cpu_percent(interval=0.5)
    cpu_count = psutil.cpu_count(logical=True)

    # RAM
    ram = psutil.virtual_memory()
    ram_total_gb = ram.total / (1024 ** 3)
    ram_used_gb = ram.used / (1024 ** 3)
    ram_percent = ram.percent

    # Disk
    disk = psutil.disk_usage("/")
    disk_total_gb = disk.total / (1024 ** 3)
    disk_used_gb = disk.used / (1024 ** 3)
    disk_percent = disk.percent

    # Uptime
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime_delta = datetime.now() - boot_time
    uptime_days = uptime_delta.days
    uptime_hours, rem = divmod(uptime_delta.seconds, 3600)
    uptime_minutes, _ = divmod(rem, 60)
    uptime_str = f"{uptime_days}d {uptime_hours}h {uptime_minutes}m"

    return {
        "cpu_percent": cpu_percent,
        "cpu_count": cpu_count,
        "ram_total_gb": ram_total_gb,
        "ram_used_gb": ram_used_gb,
        "ram_percent": ram_percent,
        "disk_total_gb": disk_total_gb,
        "disk_used_gb": disk_used_gb,
        "disk_percent": disk_percent,
        "uptime": uptime_str
    }
