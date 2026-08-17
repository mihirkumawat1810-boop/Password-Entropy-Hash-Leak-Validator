import getpass
from entropy import analyze_character_sets
from patterns import detect_patterns
from breach_check import check_hibp_breach

def main():
    print("=" * 40)
    print("      PASSWORD SECURITY AUDIT (CLI)     ")
    print("=" * 40)
    
    password = getpass.getpass("Enter password: ")
    if not password:
        print("Empty password. Exiting.")
        return

    char_data = analyze_character_sets(password)
    warnings = detect_patterns(password)
    breach_count, breach_msg = check_hibp_breach(password)

    print(f"\nEntropy: {char_data['entropy']} bits")
    print(f"Warnings: {warnings if warnings else 'None'}")
    print(f"Breach Status: {breach_msg} (Found in {breach_count} leaks)")

    del password

if __name__ == "__main__":
    main()