import math
import string

def analyze_character_sets(password: str) -> dict:
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_symbols = any(c in string.punctuation for c in password)
    
    pool_size = (26 if has_lower else 0) + (26 if has_upper else 0) + (10 if has_digits else 0) + (32 if has_symbols else 0)
    entropy = round(len(password) * math.log2(pool_size), 1) if pool_size > 0 and len(password) > 0 else 0.0

    return {
        "lower": has_lower,
        "upper": has_upper,
        "digits": has_digits,
        "symbols": has_symbols,
        "pool_size": pool_size,
        "entropy": entropy
    }