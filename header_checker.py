#!/usr/bin/env python3

import sys
import requests
from urllib.parse import urlparse

SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "HSTS",
        "Forces browsers to use HTTPS"
    ),
    "Content-Security-Policy": (
        "CSP",
        "Helps mitigate XSS and content-injection attacks"
    ),
    "X-Content-Type-Options": (
        "MIME protection",
        "Prevents MIME-type sniffing"
    ),
    "X-Frame-Options": (
        "Clickjacking protection",
        "Controls whether the site can be embedded in frames"
    ),
    "Referrer-Policy": (
        "Referrer protection",
        "Controls how much referrer information is exposed"
    ),
    "Permissions-Policy": (
        "Browser permissions",
        "Restricts access to sensitive browser features"
    ),
}


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.hostname:
        raise ValueError("Invalid URL")

    return url


def audit(url):
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "SecurityHeaderAuditor/1.0"
            }
        )
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")
        return

    headers = {
        key.lower(): value
        for key, value in response.headers.items()
    }

    print("\n" + "=" * 65)
    print("HTTP SECURITY HEADER AUDIT")
    print("=" * 65)

    print(f"Target : {response.url}")
    print(f"Status : {response.status_code}")

    if response.url.startswith("https://"):
        print("HTTPS  : [PASS]")
    else:
        print("HTTPS  : [WARN] Site is not using HTTPS")

    print("\nSecurity Headers")
    print("-" * 65)

    passed = 0
    missing = 0

    for header, (name, description) in SECURITY_HEADERS.items():

        if header.lower() in headers:
            passed += 1

            value = headers[header.lower()]

            print(f"[PASS] {header}")
            print(f"       {value}")

        else:
            missing += 1

            print(f"[MISS] {header}")
            print(f"       {description}")

    print("\n" + "-" * 65)

    total = passed + missing

    print(f"Present : {passed}/{total}")
    print(f"Missing : {missing}/{total}")

    if missing == 0:
        print("Result  : Good security-header coverage")
    elif missing <= 2:
        print("Result  : Moderate security-header coverage")
    else:
        print("Result  : Several recommended headers are missing")

    print("=" * 65)


def main():
    if len(sys.argv) != 2:
        print("Usage:")
        print(f"  python {sys.argv[0]} <URL>")
        print()
        print("Example:")
        print(f"  python {sys.argv[0]} example.com")
        return

    try:
        url = normalize_url(sys.argv[1])
        audit(url)

    except ValueError as e:
        print(f"[!] {e}")


if __name__ == "__main__":
    main()