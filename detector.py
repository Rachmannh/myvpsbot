import time
from collections import defaultdict, deque
from typing import Dict, Deque, Optional, Tuple, List

class ThreatDetector:
    def __init__(
        self,
        threshold: int = 20,
        window_seconds: int = 60,
        cooldown_seconds: int = 600,
        sensitive_paths: Optional[List[str]] = None
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.sensitive_paths = [p.lower() for p in (sensitive_paths or [])]

        # Menyimpan antrean timestamp akses per IP: {ip: deque([t1, t2, ...])}
        self.ip_hits: Dict[str, Deque[float]] = defaultdict(deque)

        # Menyimpan waktu alert terakhir dikirim per IP: {ip: timestamp}
        self.last_alert_time: Dict[str, float] = {}

        # Waktu terakhir dilakukan garbage collection memory
        self.last_cleanup = time.time()

    def is_sensitive_endpoint(self, endpoint: str) -> bool:
        ep_lower = endpoint.lower()
        return any(sensitive in ep_lower for sensitive in self.sensitive_paths)

    def process_hit(self, ip: str, endpoint: str) -> Tuple[bool, Optional[str], int]:
        """
        Memproses 1 hit log.
        Mengembalikan: (is_threat: bool, reason: str, total_hits_in_window: int)
        """
        now = time.time()
        hits_queue = self.ip_hits[ip]
        hits_queue.append(now)

        # Hapus hit di luar jendela waktu (sliding window)
        min_valid_time = now - self.window_seconds
        while hits_queue and hits_queue[0] < min_valid_time:
            hits_queue.popleft()

        total_hits = len(hits_queue)
        is_sensitive = self.is_sensitive_endpoint(endpoint)

        # Logika ambang batas:
        # Jika mengakses endpoint sensitif, ambang batas lebih sensitif (misal separuh threshold atau >= 10 hits)
        sensitive_threshold = max(5, self.threshold // 2)
        triggered = False
        reason = ""

        if is_sensitive and total_hits >= sensitive_threshold:
            triggered = True
            reason = f"Akses berulang ke endpoint sensitif (`{endpoint}`): {total_hits} hit dalam {self.window_seconds}s"
        elif total_hits >= self.threshold:
            triggered = True
            reason = f"Flooding/Spam request: {total_hits} hit dalam {self.window_seconds}s"

        # Cek apakah masih dalam masa cooldown notifikasi
        if triggered:
            last_alert = self.last_alert_time.get(ip, 0)
            if (now - last_alert) >= self.cooldown_seconds:
                self.last_alert_time[ip] = now
                return True, reason, total_hits
            else:
                # Terdeteksi sebagai threat tapi sedang dalam cooldown agar tidak spam Telegram
                return False, None, total_hits

        # Bersihkan memori secara berkala tiap 5 menit
        if now - self.last_cleanup > 300:
            self._cleanup_idle_ips(now)

        return False, None, total_hits

    def _cleanup_idle_ips(self, now: float):
        """Menghapus IP yang sudah lama tidak aktif untuk menjaga pemakaian RAM VPS tetap minimal."""
        min_valid_time = now - self.window_seconds
        inactive_ips = [
            ip for ip, q in self.ip_hits.items()
            if not q or q[-1] < min_valid_time
        ]
        for ip in inactive_ips:
            del self.ip_hits[ip]

        # Bersihkan juga cooldown yang sudah expired
        expired_alerts = [
            ip for ip, t in self.last_alert_time.items()
            if now - t > self.cooldown_seconds
        ]
        for ip in expired_alerts:
            del self.last_alert_time[ip]

        self.last_cleanup = now
