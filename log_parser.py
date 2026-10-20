import re
from typing import Optional, Dict, Any

# Regex Combined Log Format untuk Nginx & Apache
# 1: Client IP
# 2: Remote user
# 3: Timestamp
# 4: Request line (Method + Path + Protocol)
# 5: Status code
# 6: Body bytes sent
# 7: Referer
# 8: User-Agent
COMBINED_LOG_REGEX = re.compile(
    r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\d+|-)\s+"([^"]*)"\s+"([^"]*)"'
)

def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Mem-parsing baris log access Nginx/Apache.
    Mengembalikan dict berisi:
    ip, timestamp, method, endpoint, status_code, user_agent, raw_request
    """
    line = line.strip()
    if not line:
        return None

    match = COMBINED_LOG_REGEX.match(line)
    if not match:
        # Fallback regex sederhana jika ada variasi format
        simple_match = re.search(r'^(\S+).*?\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s"]+)', line)
        if simple_match:
            return {
                "ip": simple_match.group(1),
                "timestamp": simple_match.group(2),
                "method": simple_match.group(3),
                "endpoint": simple_match.group(4),
                "status_code": 0,
                "user_agent": "Unknown",
                "raw_request": ""
            }
        return None

    ip = match.group(1)
    timestamp = match.group(3)
    raw_request = match.group(4)
    status_code = int(match.group(5))
    user_agent = match.group(8)

    # Ekstraksi Method dan Endpoint dari request line (misal: "GET /index.php HTTP/1.1")
    request_parts = raw_request.split()
    if len(request_parts) >= 2:
        method = request_parts[0]
        endpoint = request_parts[1]
    elif len(request_parts) == 1:
        method = request_parts[0]
        endpoint = "/"
    else:
        method = "-"
        endpoint = "-"

    return {
        "ip": ip,
        "timestamp": timestamp,
        "method": method,
        "endpoint": endpoint,
        "status_code": status_code,
        "user_agent": user_agent,
        "raw_request": raw_request
    }
