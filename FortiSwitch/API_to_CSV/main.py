import requests
import json
import csv
import re
from getpass import getpass
import logging
import datetime
from retry import retry

# Configure logging
logging.basicConfig(
    filename="fortimanager.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Suppress only InsecureRequestWarning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def validate_ip(ip):
    """Validate if the input string is a valid IP address."""
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if not re.match(ip_regex, ip):
        logging.warning("Invalid IP address format entered.")
        print("[-] Invalid IP address format. Please try again.")
        return False
    return True


@retry(tries=3, delay=5, backoff=2)
def make_request_with_retries(url, headers, payload):
    """Send a POST request with retry logic."""
    response = requests.post(url, headers=headers, json=payload, verify=False, timeout=10)
    response.raise_for_status()  # Raise an exception for HTTP errors
    return response


def fortimanager_connect(fmg_ip, username, password):
    url = f"https://{fmg_ip}/jsonrpc"
    payload = {
        "id": 1,
        "method": "exec",
        "params": [
            {
                "data": [{"passwd": password, "user": username}],
                "url": "sys/login/user"
            }
        ],
        "session": None,
    }
    headers = {"Content-Type": "application/json"}

    try:
        response = make_request_with_retries(url, headers, payload)
        response_data = response.json()
        session_id = response_data.get("session")
        if not session_id:
            logging.error("Failed to connect to FortiManager. Invalid credentials.")
            print("[-] Failed to connect to FortiManager. Check your credentials.")
            exit(1)
        logging.info("Successfully connected to FortiManager.")
        print("[+] Successfully connected to FortiManager.")
        return session_id
    except requests.exceptions.RequestException as e:
        logging.error(f"Connection error: {e}")
        print(f"[-] Connection error: {e}")
        exit(1)


def get_fortigates(fmg_ip, session_id):
    url = f"https://{fmg_ip}/jsonrpc"
    payload = {
        "id": 2,
        "method": "get",
        "params": [{"ostype": "FortiGate", "url": "/dvmdb/device/"}],
        "session": session_id,
        "verbose": 1,
    }
    headers = {"Content-Type": "application/json"}

    try:
        response = make_request_with_retries(url, headers, payload)
        devices = response.json().get("result", [{}])[0].get("data", [])
        fortigates = [{"name": dev["name"], "ip": dev["ip"]} for dev in devices]
        logging.info("Successfully fetched FortiGate list.")
        return fortigates
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch FortiGate list: {e}")
        print(f"[-] Failed to fetch FortiGate list: {e}")
        exit(1)


def get_fortiswitches(fmg_ip, session_id, fortigate_name):
    url = f"https://{fmg_ip}/jsonrpc"
    payload = {
        "id": 3,
        "method": "get",
        "params": [
            {
                "ostype": "FortiSwitch",
                "url": f"/pm/config/device/{fortigate_name}/vdom/root/switch-controller/managed-switch",
            }
        ],
        "session": session_id,
        "verbose": 1,
    }
    headers = {"Content-Type": "application/json"}

    try:
        response = make_request_with_retries(url, headers, payload)
        switches = response.json().get("result", [{}])[0].get("data", [])
        switch_ids = [{"switch-id": switch["switch-id"], "fortigate": fortigate_name} for switch in switches if "switch-id" in switch]
        logging.info(f"Successfully fetched switches for FortiGate {fortigate_name}.")
        return switch_ids
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch FortiSwitches for FortiGate {fortigate_name}: {e}")
        print(f"[-] Failed to fetch FortiSwitches for FortiGate {fortigate_name}: {e}")
        return []


def save_to_csv(switch_data, filename):
    with open(filename, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["fortigate", "switch-id"])
        writer.writeheader()
        for switch in switch_data:
            writer.writerow(switch)
    logging.info(f"Results saved to {filename}.")


def main():
    # Prompt user for FortiManager details
    while True:
        fmg_ip = input("Enter FortiManager IP (e.g., 10.1.1.217): ").strip()
        if validate_ip(fmg_ip):
            break

    username = input("Enter username: ").strip()
    password = getpass("Enter password: ").strip()  # Hides password input with *

    # Step 1: Connect to FortiManager
    session_id = fortimanager_connect(fmg_ip, username, password)

    # Step 2: Get FortiGates
    fortigates = get_fortigates(fmg_ip, session_id)
    print("\nAvailable FortiGates:")
    for idx, fg in enumerate(fortigates, 1):
        print(f"{idx}. {fg['name']} ({fg['ip']})")

    print(f"{len(fortigates) + 1}. All FortiGates")

    # Step 3: Prompt user to select a FortiGate or all
    while True:
        try:
            choice = int(input("\nSelect a FortiGate by number (or choose All): ").strip())
            if 1 <= choice <= len(fortigates) + 1:
                break
            else:
                print("[-] Invalid choice. Please enter a valid number.")
        except ValueError:
            print("[-] Invalid input. Please enter a number.")

    if choice == len(fortigates) + 1:  # User selected All
        all_switch_data = []
        for fg in fortigates:
            print(f"\nFetching switches for FortiGate: {fg['name']}...")
            switch_data = get_fortiswitches(fmg_ip, session_id, fg["name"])
            all_switch_data.extend(switch_data)
        print("\nAll Switch Data:")
        for switch in all_switch_data:
            print(f"FortiGate: {switch['fortigate']}, Switch ID: {switch['switch-id']}")

        # Save results to CSV with a timestamped filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"all_fortiswitch_switch_ids_{timestamp}.csv"
        save_to_csv(all_switch_data, filename)
        print(f"[+] Results saved to '{filename}'.")
    else:  # User selected a specific FortiGate
        selected_fg = fortigates[choice - 1]
        print(f"\nFetching switches for FortiGate: {selected_fg['name']}...")
        switch_data = get_fortiswitches(fmg_ip, session_id, selected_fg["name"])
        print("\nSwitch Data:")
        for switch in switch_data:
            print(f"FortiGate: {switch['fortigate']}, Switch ID: {switch['switch-id']}")

if __name__ == "__main__":
    main()
