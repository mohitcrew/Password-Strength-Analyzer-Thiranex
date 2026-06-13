import re
import secrets
import string
import argparse
import math
from typing import List, Tuple


# A small list of common passwords. In production, consider loading a larger
# benchmark list (e.g. rockyou) and/or using a breached-passwords API.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "111111", "1234567", "sunshine", "qwerty", "iloveyou",
    "admin", "welcome", "password123", "123123", "abc123"
}

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/|\\"


def calculate_entropy(password: str) -> float:
    """Estimate the entropy (in bits) of the password based on character classes present."""
    pool = 0
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[{}]".format(re.escape(SYMBOLS)), password):
        pool += len(SYMBOLS)
    # Fallback: if none matched, use unique chars seen
    if pool == 0:
        pool = len(set(password)) or 1
    return len(password) * math.log2(pool)


def has_sequence(password: str, seq_len: int = 3) -> bool:
    """Detect simple increasing/decreasing sequences like 'abc' or '123'."""
    pw = password.lower()
    for i in range(len(pw) - seq_len + 1):
        chunk = pw[i : i + seq_len]
        # letters
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(len(chunk) - 1)):
            return True
        if all(ord(chunk[j]) - ord(chunk[j + 1]) == 1 for j in range(len(chunk) - 1)):
            return True
    return False


def analyze_password(password: str) -> Tuple[int, str, List[str]]:
    """Analyze password and return a score (0-100), strength label, and feedback list."""
    feedback: List[str] = []

    length = len(password)
    entropy_bits = calculate_entropy(password)

    # Component scores (weights sum to 100)
    length_score = min(length, 20) / 20 * 30  # up to 30
    variety = 0
    variety += 1 if re.search(r"[A-Z]", password) else 0
    variety += 1 if re.search(r"[a-z]", password) else 0
    variety += 1 if re.search(r"\d", password) else 0
    variety += 1 if re.search(r"[{}]".format(re.escape(SYMBOLS)), password) else 0
    variety_score = (variety / 4) * 30  # up to 30

    entropy_score = min(entropy_bits, 60) / 60 * 30  # up to 30

    uniqueness_score = 0 if password.lower() in COMMON_PASSWORDS else 10

    raw_score = length_score + variety_score + entropy_score + uniqueness_score

    # Penalties
    if len(set(password)) < max(4, length // 2):
        feedback.append("Avoid repeated characters or low diversity.")
        raw_score -= 10
    if has_sequence(password):
        feedback.append("Avoid simple sequences like 'abc' or '123'.")
        raw_score -= 10
    if password.lower() in COMMON_PASSWORDS:
        feedback.append("This is a commonly used password; choose a unique one.")
        raw_score = max(0, raw_score - 40)

    score = int(max(0, min(100, round(raw_score))))

    # Strength label
    if score < 35:
        strength = "Weak"
    elif score < 60:
        strength = "Moderate"
    elif score < 80:
        strength = "Strong"
    else:
        strength = "Very Strong"

    # Actionable feedback
    if length < 12:
        feedback.append("Use at least 12 characters; 16+ is better for high security.")
    if not re.search(r"[A-Z]", password):
        feedback.append("Add uppercase letters.")
    if not re.search(r"[a-z]", password):
        feedback.append("Add lowercase letters.")
    if not re.search(r"\d", password):
        feedback.append("Add digits.")
    if not re.search(r"[{}]".format(re.escape(SYMBOLS)), password):
        feedback.append("Add special characters (e.g. !@#$%).")

    # Deduplicate feedback while preserving order
    seen = set()
    dedup_feedback = []
    for f in feedback:
        if f not in seen:
            dedup_feedback.append(f)
            seen.add(f)

    return score, strength, dedup_feedback


def generate_strong_password(length: int = 16) -> str:
    """Generate a cryptographically secure password ensuring all character classes are present."""
    if length < 4:
        raise ValueError("Password length must be at least 4 to include all classes.")

    classes = [string.ascii_uppercase, string.ascii_lowercase, string.digits, SYMBOLS]
    # Ensure at least one char from each class
    password_chars = [secrets.choice(c) for c in classes]
    all_chars = ''.join(classes)
    for _ in range(length - len(password_chars)):
        password_chars.append(secrets.choice(all_chars))
    # Shuffle securely
    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)


def main() -> None:
    parser = argparse.ArgumentParser(description="Password strength analyzer and secure generator")
    parser.add_argument("-p", "--password", help="Password to analyze (use quotes)")
    parser.add_argument("-g", "--generate", type=int, nargs="?", const=16,
                        help="Generate a strong password of given length (default 16 when flag used without value)")
    args = parser.parse_args()

    if args.generate:
        pwd = generate_strong_password(args.generate)
        print(pwd)
        return

    if args.password:
        password = args.password
    else:
        try:
            password = input("Enter Password: ")
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return

    score, strength, feedback = analyze_password(password)

    print("\n===== Password Analysis =====")
    print("Password Strength :", strength)
    print("Security Score    :", f"{score}/100")
    print(f"Estimated Entropy: {calculate_entropy(password):.1f} bits")

    if feedback:
        print("\nSuggestions:")
        for item in feedback:
            print("-", item)
        print("\nSuggested Strong Password:")
        print(generate_strong_password(max(16, len(password))))
    else:
        print("\nExcellent! Your password follows security best practices.")


if __name__ == "__main__":
    main()
    