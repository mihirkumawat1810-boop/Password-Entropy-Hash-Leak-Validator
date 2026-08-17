import hashlib
import requests

def check_hibp_breach(password: str, timeout: float = 3.0) -> tuple[int, str]:
    if not password:
        return 0, "Empty input"

    try:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    except UnicodeEncodeError:
        return -1, "Encoding error"

    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    del sha1_hash

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": "Password-Security-Auditor"}

    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code == 429:
            return -1, "Rate limit exceeded"
        elif response.status_code != 200:
            return -1, f"HTTP Error {response.status_code}"

        for line in response.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0].strip() == suffix:
                return int(parts[1].strip()), "Match found"
        
        return 0, "No breach match found"
    except requests.RequestException:
        return -1, "Network unreachable"