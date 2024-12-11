import requests
import json
import csv
import re
from getpass import getpass
import logging
import datetime

# Configure logging
logging.basicConfig(
    filename="fortimanager.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def validate_ip(ip):
    """Validate if the input string is a valid IP address."""
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(ip_regex, ip) is not None


def make_request(url, headers, payload):
    """Send a POST request and return the response."""
    response = requests.post(url, headers=headers, json=payload, verify=False, timeout=10)
    response.raise_for_status()
    return response


def fortimanager_connect(fmg_ip, username, password):
    """Login to FortiManager and retrieve the session ID."""
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

    response = make_request(url, headers, payload)
    response_data = response.json()
    session_id = response_data.get("session")
    if not session_id:
        logging.error("Failed to connect to FortiManager. Invalid credentials.")
        raise Exception("Failed to connect to FortiManager. Check your credentials.")
    logging.info("Successfully connected to FortiManager.")
    return session_id


def fortimanager_logout(fmg_ip, session_id):
    """Logout from FortiManager to close the session."""
    url = f"https://{fmg_ip}/jsonrpc"
    payload = {
        "id": 5,
        "method": "exec",
        "params": [{"url": "/sys/logout"}],
        "session": session_id,
    }
    headers = {"Content-Type": "application/json"}

    try:
        response = make_request(url, headers, payload)
        if response.status_code == 200:
            logging.info("Successfully logged out from FortiManager.")
            print("[+] Session successfully closed.")
        else:
            logging.warning("Failed to log out from FortiManager.")
            print("[-] Failed to close the session.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error while logging out: {e}")
        print(f"[-] Error while logging out: {e}")


def get_fortigates(fmg_ip, session_id):
    """Retrieve a list of FortiGates from FortiManager."""
    url = f"https://{fmg_ip}/jsonrpc"
    payload = {
        "id": 2,
        "method": "get",
        "params": [{"ostype": "FortiGate", "url": "/dvmdb/device/"}],
        "session": session_id,
        "verbose": 1,
    }
    headers = {"Content-Type": "application/json"}

    response = make_request(url, headers, payload)
    devices = response.json().get("result", [{}])[0].get("data", [])
    return [{"name": dev["name"], "ip": dev["ip"]} for dev in devices]


def get_interfaces(fmg_ip, session_id, fortigate_name):
    """Retrieve interfaces and their link status for a specific FortiGate."""
    url = f"https://{fmg_ip}/jsonrpc"
    payload = {
        "id": "1",
        "method": "exec",
        "params": [
            {
                "url": "sys/proxy/json",
                "data": {
                    "target": [f"device/{fortigate_name}"],
                    "action": "get",
                    "resource": "/api/v2/monitor/system/interface"
                }
            }
        ],
        "session": session_id,
    }
    headers = {"Content-Type": "application/json"}

    response = make_request(url, headers, payload)
    results = response.json()["result"][0]["data"][0]["response"]["results"]

    # Prepare data for CSV
    return [
        {"device": fortigate_name, "interface": value["name"], "link": "UP" if value["link"] else "DOWN"}
        for key, value in results.items()
    ]


def save_to_csv(data, filename):
    """Save the interface data to a CSV file."""
    with open(filename, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["device", "interface", "link"])
        writer.writeheader()
        writer.writerows(data)
    logging.info(f"Results saved to {filename}.")
    print(f"Interface data saved to {filename}")


def main():
    # Prompt user for FortiManager details
    while True:
        fmg_ip = input("Enter FortiManager IP (e.g., 10.1.1.217): ").strip()
        if validate_ip(fmg_ip):
            break
        print("Invalid IP format. Please enter a valid IP address.")

    username = input("Enter Username: ").strip()
    password = getpass("Enter Password: ").strip()

    # Step 1: Connect to FortiManager
    session_id = fortimanager_connect(fmg_ip, username, password)

    try:
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

        # Step 4: Fetch and save interface data
        interface_data = []
        if choice == len(fortigates) + 1:  # User selected All
            for fg in fortigates:
                print(f"Fetching interfaces for FortiGate: {fg['name']}...")
                interface_data.extend(get_interfaces(fmg_ip, session_id, fg["name"]))
        else:  # User selected a specific FortiGate
            selected_fg = fortigates[choice - 1]
            print(f"Fetching interfaces for FortiGate: {selected_fg['name']}...")
            interface_data = get_interfaces(fmg_ip, session_id, selected_fg["name"])

        # Save results to CSV with a timestamped filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"fortigate_interfaces_{timestamp}.csv"
        save_to_csv(interface_data, filename)

    finally:
        # Ensure session is torn down
        fortimanager_logout(fmg_ip, session_id)


if __name__ == "__main__":
    main()
