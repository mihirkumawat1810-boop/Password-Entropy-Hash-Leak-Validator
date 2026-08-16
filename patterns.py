import re

COMMON_PASSWORDS = {
    "password", "123456", "qwerty", "admin", "password123", 
    "letmein", "welcome", "12345678", "password2026", "summer2026"
}

LEET_MAP = str.maketrans({
    '@': 'a', '4': 'a', '$': 's', '5': 's', 
    '0': 'o', '1': 'i', '!': 'i', '3': 'e', '7': 't'
})

def detect_patterns(password: str) -> list:
    warnings = []
    pw_lower = password.lower()
    norm_pw = password.translate(LEET_MAP).lower()

    if pw_lower in COMMON_PASSWORDS or norm_pw in COMMON_PASSWORDS:
        warnings.append("Matches known common password pattern")

    if any(password[i] == password[i+1] == password[i+2] for i in range(len(password) - 2)):
        warnings.append("Excessive character repetition detected")

    for i in range(len(pw_lower) - 2):
        c1, c2, c3 = ord(pw_lower[i]), ord(pw_lower[i+1]), ord(pw_lower[i+2])
        if (c2 == c1 + 1 and c3 == c2 + 1) or (c2 == c1 - 1 and c3 == c2 - 1):
            if pw_lower[i:i+3].isalnum():
                warnings.append("Sequential character pattern detected")
                break

    keyboard_rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
    for row in keyboard_rows:
        for i in range(len(row) - 2):
            pat = row[i:i+3]
            if pat in pw_lower or pat[::-1] in pw_lower:
                warnings.append("Keyboard row sequence detected")
                break

    if re.search(r'(19\d\d|20\d\d)', password):
        warnings.append("Contains standard 4-digit year format")

    return warnings