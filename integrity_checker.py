import hashlib
import json
import os

BASELINE_FILE = "baseline.json"


def calculate_hash(filename):
    sha256 = hashlib.sha256()

    with open(filename, "rb") as file:
        while chunk := file.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


def create_baseline():
    files = {}

    for filename in os.listdir("."):
        if filename.endswith(".py"):
            files[filename] = calculate_hash(filename)

    with open(BASELINE_FILE, "w") as file:
        json.dump(files, file, indent=4)

    print("Baseline created successfully.")


def check_integrity():
    if not os.path.exists(BASELINE_FILE):
        print("No baseline found.")
        print("Run option 1 first.")
        return

    with open(BASELINE_FILE, "r") as file:
        baseline = json.load(file)

    for filename, old_hash in baseline.items():

        if not os.path.exists(filename):
            print(f"[DELETED] {filename}")
            continue

        new_hash = calculate_hash(filename)

        if new_hash != old_hash:
            print(f"[MODIFIED] {filename}")
        else:
            print(f"[OK] {filename}")


while True:
    print("\n=== File Integrity Checker ===")
    print("1. Create baseline")
    print("2. Check integrity")
    print("3. Exit")

    choice = input("\nChoose an option: ").strip()

    if choice == "1":
        create_baseline()

    elif choice == "2":
        check_integrity()

    elif choice == "3":
        print("Goodbye!")
        break

    else:
        print("Invalid option.")

