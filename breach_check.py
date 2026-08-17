import hashlib
import requests


def check_hibp_breach(password: str, timeout: float = 3.0) -> tuple[int, str]:
    if not password:
        return 0, "Empty input"

    try:
        # SHA-1 is used here because HIBP's k-anonymity API requires it.
        sha1_hash = hashlib.sha1(
            password.encode("utf-8")
        ).hexdigest().upper()

    except UnicodeEncodeError:
        return -1, "Encoding error"

    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    headers = {
        "User-Agent": "Password-Security-Auditor"
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout
        )

        if response.status_code == 429:
            return -1, "Rate limit exceeded"

        if response.status_code != 200:
            return -1, f"HTTP Error {response.status_code}"

        for line in response.text.splitlines():

            if ":" not in line:
                continue

            hash_suffix, count = line.split(":", 1)

            if hash_suffix.strip().upper() == suffix:
                try:
                    return int(count.strip()), "Match found"
                except ValueError:
                    return -1, "Invalid breach count"

        return 0, "No breach match found"

    except requests.Timeout:
        return -1, "Request timed out"

    except requests.ConnectionError:
        return -1, "Connection error"

    except requests.RequestException as e:
        return -1, f"Request error: {str(e)}"