import argparse
import sys

# list of (prefix, name, note)
PREFIXES = [
    ("$argon2id$", "Argon2id", "modern PHC string"),
    ("$argon2i$", "Argon2i", "PHC string"),
    ("$argon2d$", "Argon2d", "PHC string"),
    ("$2y$", "bcrypt", "bcrypt 2y"),
    ("$2b$", "bcrypt", "bcrypt 2b"),
    ("$2a$", "bcrypt", "bcrypt 2a"),
    ("$2x$", "bcrypt", "bcrypt 2x"),
    ("$6$", "SHA-512 crypt", "unix crypt sha512"),
    ("$5$", "SHA-256 crypt", "unix crypt sha256"),
    ("$1$", "MD5 crypt", "unix crypt md5, old"),
    ("$apr1$", "Apache MD5-crypt", "htpasswd -m"),
    ("$y$", "yescrypt", "newer linux default"),
    ("$P$", "phpass", "wordpress/phpbb"),
    ("$H$", "phpass", "phpbb variant"),
    ("$S$", "Drupal 7", "drupal hash"),
    ("$7$", "scrypt", "scrypt style"),
    ("pbkdf2_sha256$", "Django PBKDF2-SHA256", "django default"),
    ("pbkdf2_sha1$", "Django PBKDF2-SHA1", "django old"),
    ("bcrypt_sha256$", "Django bcrypt-SHA256", "django wrapper"),
    ("argon2$", "Django Argon2", "django wrapper"),
    ("{SSHA}", "LDAP SSHA", "ldap salted sha1"),
    ("{SHA}", "LDAP SHA", "ldap sha1"),
    ("{SMD5}", "LDAP SMD5", "ldap salted md5"),
    ("{MD5}", "LDAP MD5", "ldap md5"),
    ("{CRYPT}", "LDAP CRYPT", "ldap wraps crypt"),
]

HEX_CHARS = "0123456789abcdefABCDEF"
HEX_CHARS_UPPER = "0123456789ABCDEF"
DESCRYPT_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

LENGTH_GUESSES = {
    16: ["MySQL323", "CRC-64"],
    32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    40: ["SHA-1", "RIPEMD-160"],
    48: ["Tiger-192"],
    56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256", "RIPEMD-256"],
    80: ["RIPEMD-320"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"],
}


def is_hex(s):
    if len(s) == 0:
        return False
    for ch in s:
        if ch not in HEX_CHARS:
            return False
    return True


def is_mysql5(s):
    if len(s) != 41:
        return False
    if s[0] != "*":
        return False
    body = s[1:]
    for ch in body:
        if ch not in HEX_CHARS_UPPER:
            return False
    return True


def is_descrypt(s):
    if len(s) != 13:
        return False
    for ch in s:
        if ch not in DESCRYPT_CHARS:
            return False
    return True


def identify(raw_input):
    text = raw_input.strip()
    results = []

    if text == "":
        return results

    #checking prefixes
    for prefix, name, note in PREFIXES:
        if text.startswith(prefix):
            results.append({
                "algorithm": name,
                "confidence": "high",
                "reason": "prefix " + prefix + " - " + note,
            })
            return results

    #netntlm stuff
    if "::" in text and text.count(":") >= 4:
        parts = text.split(":")
        if len(parts) >= 6 and len(parts[4]) == 32 and is_hex(parts[4]):
            results.append({
                "algorithm": "NetNTLMv2",
                "confidence": "high",
                "reason": "looks like netntlmv2 format",
            })
            return results
        if len(parts) >= 6 and len(parts[3]) == 48 and is_hex(parts[3]):
            results.append({
                "algorithm": "NetNTLMv1",
                "confidence": "high",
                "reason": "looks like netntlmv1 format",
            })
            return results

    if is_mysql5(text):
        results.append({
            "algorithm": "MySQL5",
            "confidence": "high",
            "reason": "starts with * and 40 uppercase hex chars",
        })
        return results

    if is_descrypt(text):
        results.append({
            "algorithm": "DES crypt",
            "confidence": "medium",
            "reason": "13 chars, old unix crypt format",
        })
        return results

    #hex length guessing
    if is_hex(text):
        length = len(text)
        if length in LENGTH_GUESSES:
            guesses = LENGTH_GUESSES[length]
            for i in range(len(guesses)):
                if i == 0:
                    conf = "medium"
                    reason = str(length) + " hex chars, most likely one"
                else:
                    conf = "low"
                    reason = str(length) + " hex chars, also possible"
                results.append({
                    "algorithm": guesses[i],
                    "confidence": conf,
                    "reason": reason,
                })
        return results

    #phc guess
    if text.startswith("$"):
        rest = text[1:]
        if "$" in rest:
            algo_name = rest.split("$", 1)[0]
            ok = True
            for ch in algo_name:
                if not (ch.isalnum() or ch == "-" or ch == "_"):
                    ok = False
            if algo_name != "" and ok:
                results.append({
                    "algorithm": "PHC string (" + algo_name + ")",
                    "confidence": "low",
                    "reason": "generic phc shape, no exact rule",
                })
                return results

    #jwt
    if text.startswith("eyJ"):
        results.append({
            "algorithm": "JWT (not a hash)",
            "confidence": "low",
            "reason": "starts with eyJ, probably a jwt token",
        })
        return results

    has_b64_char = False
    for ch in text:
        if ch == "+" or ch == "/" or ch == "=":
            has_b64_char = True
    if has_b64_char and len(text) > 8:
        results.append({
            "algorithm": "Base64 blob (not a hash)",
            "confidence": "low",
            "reason": "has base64 chars like + / =",
        })
        return results

    return results


def main():
    parser = argparse.ArgumentParser(prog="hashid", description="Try to guess what hash algo this string is")
    parser.add_argument("hash", help="the hash string to check")
    parser.add_argument("--top", "-n", type=int, default=5, help="max results to show")
    args = parser.parse_args()

    candidates = identify(args.hash)

    if len(candidates) == 0:
        print("Didn't match anything .")
        return 1

    candidates = candidates[:args.top]

    print("Candidates for:", args.hash.strip())
    print("~" * 50)
    for c in candidates:
        print(c["algorithm"], "|", c["confidence"], "|", c["reason"])
    print("~" * 50)

    if candidates[0]["confidence"] == "high":
        print("High confidence!")

    return 0


if __name__ == "__main__":
    sys.exit(main())