import os
import json
from vulnerability_scanner import VulnerabilityScanner
from credential_checker import EnhancedCredentialChecker
from report_generator import generate_report
import network_portscanner
import pyfiglet
from termcolor import cprint  # ✅ FIXED: Proper import

# Configuration
REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

def display_banner():
    cprint("=" * 70, "red", attrs=["bold"])
    banner = pyfiglet.figlet_format("V-Scanner", font="slant")
    cprint(banner, "magenta", attrs=["bold"])
    cprint("=" * 70, "red", attrs=["bold"])

def run_network_scanner():
    print("\n=== Network & Port Scanner ===")
    print("1. Automatic Scan")
    print("2. Manual Scan")
    choice = input("Select option (1-2): ").strip()

    if choice == "1":
        print("[*] Running automatic scan...")
        network_portscanner.main()
    elif choice == "2":
        print("[*] Running manual scan...")
        network_portscanner.manual_scan()
    else:
        print("Invalid input.")

def run_vulnerability_scanner():
    print("\n=== Vulnerability Scanner ===")
    try:
        with open("reports/portscanner.json", "r") as f:
            scan_data = json.load(f)
    except FileNotFoundError:
        print("❌ No network scan results found. Run network scan first.")
        input("Press Enter to continue...")
        return

    print("\nScanned Devices:")
    for i, device in enumerate(scan_data["devices"]):
        print(f"{i+1}. {device['ip']} - {len(device['open_ports'])} open ports")

    try:
        selection = int(input("\nSelect target device (number): ")) - 1
        target_ip = scan_data["devices"][selection]["ip"]
        ports = scan_data["devices"][selection]["open_ports"]

        print(f"\nOpen ports on {target_ip}:")
        for i, port in enumerate(ports):
            print(f"{i+1}. Port {port['port']} ({port['service']})")

        port_choice = int(input("\nSelect port to scan (number): ")) - 1
        target_port = ports[port_choice]["port"]

        print(f"\n[*] Scanning {target_ip}:{target_port} for vulnerabilities...")
        scanner = VulnerabilityScanner(api_key="d1e70f55-a5ac-4a33-b5f7-e5a8a72abd93")  
        scanner.scan(target_ip, target_port)
        print("[+] Vulnerability scan completed!")
    except (ValueError, IndexError):
        print("Invalid selection.")

    input("Press Enter to continue...")

def run_credential_checker():
    print("\n=== Credential Checker ===")
    checker = EnhancedCredentialChecker()

    while True:
        print("\n1. Check Username")
        print("2. Check Email")
        print("3. Check Password")
        print("4. Back to Main Menu")
        choice = input("Select option (1-4): ").strip()

        if choice == "1":
            username = input("Enter username: ").strip()
            checker.check_credential("username", username)
        elif choice == "2":
            email = input("Enter email: ").strip()
            checker.check_credential("email", email)
        elif choice == "3":
            password = input("Enter password: ").strip()
            checker.check_password(password)
        elif choice == "4":
            break
        else:
            print("Invalid input. Try again.")

def main():
    display_banner()  # ✅ FIXED: Replaced undefined `show_banner()` with `display_banner()`
    while True:
        print("\n=== MAIN MENU ===")
        print("1. Network & Port Scanning")
        print("2. Vulnerability Scanner")
        print("3. Credential Checker")
        print("4. Generate Final Report")
        print("5. Exit")

        choice = input("Choose an option (1-5): ").strip()

        if choice == "1":
            run_network_scanner()
        elif choice == "2":
            run_vulnerability_scanner()
        elif choice == "3":
            run_credential_checker()
        elif choice == "4":
            generate_report()
        elif choice == "5":
            print("👋 Exiting. Goodbye!")
            break
        else:
            print("Invalid input. Try again.")

if __name__ == "__main__":
    main()
