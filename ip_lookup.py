import socket
import ipaddress
import sys
import requests


def lookup(target):
    try:
        # Resolve hostname
        ip = socket.gethostbyname(target)

        print(f"\nTarget : {target}")
        print(f"IP     : {ip}")

        # Basic IP classification
        address = ipaddress.ip_address(ip)

        print(f"Version  : IPv{address.version}")
        print(f"Private  : {address.is_private}")
        print(f"Loopback : {address.is_loopback}")
        print(f"Global   : {address.is_global}")

        # Public IP information
        if address.is_global:
            response = requests.get(
                f"https://ipinfo.io/{ip}/json",
                timeout=5
            )

            if response.ok:
                data = response.json()

                print("\nNetwork Information")
                print("-" * 35)
                print(f"Hostname : {data.get('hostname', 'N/A')}")
                print(f"City     : {data.get('city', 'N/A')}")
                print(f"Region   : {data.get('region', 'N/A')}")
                print(f"Country  : {data.get('country', 'N/A')}")
                print(f"Org      : {data.get('org', 'N/A')}")
                print(f"Timezone : {data.get('timezone', 'N/A')}")

    except socket.gaierror:
        print("[!] Could not resolve target.")

    except requests.RequestException:
        print("[!] Could not retrieve network information.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <domain>")
        sys.exit(1)

    lookup(sys.argv[1])