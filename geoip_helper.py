import ipaddress
import logging
import os
import requests
from typing import Dict, Any, Optional

try:
    import geoip2.database
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False

logger = logging.getLogger("vps_bot.geoip")

class GeoIPLookup:
    def __init__(self, db_path: str = ""):
        self.db_path = db_path
        self.reader = None
        self._cache: Dict[str, Dict[str, str]] = {}
        self._init_reader()

    def _init_reader(self):
        if HAS_GEOIP2 and self.db_path and os.path.exists(self.db_path):
            try:
                self.reader = geoip2.database.Reader(self.db_path)
                logger.info(f"Loaded local MaxMind database: {self.db_path}")
            except Exception as e:
                logger.warning(f"Gagal memuat MaxMind DB di {self.db_path}: {e}. Fallback ke Web API.")
                self.reader = None
        else:
            if not HAS_GEOIP2:
                logger.info("Library geoip2 tidak terinstall. Menggunakan fallback web API.")
            else:
                logger.info(f"File database GeoIP tidak ditemukan di {self.db_path}. Menggunakan fallback web API.")

    def is_private_ip(self, ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
        except ValueError:
            return False

    def lookup(self, ip: str) -> Dict[str, str]:
        """
        Mengembalikan dictionary berisi:
        {
            "country": "Indonesia",
            "country_code": "ID",
            "city": "Jakarta",
            "flag": "🇮🇩" (jika tersedia)
        }
        """
        if not ip:
            return {"country": "Unknown", "country_code": "??", "city": "Unknown"}

        # Cek Cache
        if ip in self._cache:
            return self._cache[ip]

        # Cek apakah Private/Local IP
        if self.is_private_ip(ip):
            res = {"country": "Private Network", "country_code": "LAN", "city": "Local"}
            self._cache[ip] = res
            return res

        # 1. Coba lewat Local MaxMind Database
        if self.reader:
            try:
                response = self.reader.city(ip)
                country_name = response.country.name or response.registered_country.name or "Unknown"
                country_code = response.country.iso_code or response.registered_country.iso_code or "??"
                city_name = response.city.name or "Unknown"
                result = {
                    "country": country_name,
                    "country_code": country_code,
                    "city": city_name
                }
                self._cache[ip] = result
                return result
            except Exception:
                # Coba mode country jika database hanya Country DB
                try:
                    response = self.reader.country(ip)
                    country_name = response.country.name or "Unknown"
                    country_code = response.country.iso_code or "??"
                    result = {
                        "country": country_name,
                        "country_code": country_code,
                        "city": "-"
                    }
                    self._cache[ip] = result
                    return result
                except Exception:
                    pass

        # 2. Fallback ke IP-API.com publik (Gratis, tanpa API key untuk non-commercial)
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city"
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    result = {
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", "??"),
                        "city": data.get("city", "Unknown")
                    }
                    self._cache[ip] = result
                    return result
        except Exception as e:
            logger.debug(f"Gagal melakukan fallback GeoIP API untuk {ip}: {e}")

        fallback_res = {"country": "Unknown", "country_code": "??", "city": "Unknown"}
        self._cache[ip] = fallback_res
        return fallback_res

    def close(self):
        if self.reader:
            try:
                self.reader.close()
            except Exception:
                pass
