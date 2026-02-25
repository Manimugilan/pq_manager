import secrets
import string
import zxcvbn as zx


def generate_password(length: int = 16, include_symbols: bool = True) -> str:
    """Generate a cryptographically secure random password."""
    chars = string.ascii_letters + string.digits
    if include_symbols:
        chars += '!@#$%^&*()-_=+[]{}|;:,.<>?'

    while True:
        pwd = ''.join(secrets.choice(chars) for _ in range(length))
        has_lower  = any(c.islower() for c in pwd)
        has_upper  = any(c.isupper() for c in pwd)
        has_digit  = any(c.isdigit() for c in pwd)
        has_symbol = any(c in string.punctuation for c in pwd) if include_symbols else True
        if has_lower and has_upper and has_digit and has_symbol:
            return pwd


def analyze_password_strength(password: str) -> dict:
    """Use zxcvbn to score a password. Returns score (0-4), feedback, and crack time."""
    result = zx.zxcvbn(password)
    return {
        'score':     result['score'],
        'feedback':  result['feedback'],
        'crack_time': result['crack_times_display']['offline_slow_hashing_1e4_per_second'],
        'guesses':   result['guesses']
    }
