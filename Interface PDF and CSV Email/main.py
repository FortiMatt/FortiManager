import os
import json
import smtplib
import logging
import datetime
import requests
from requests.adapters import HTTPAdapter, Retry
import csv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from getpass import getpass
from collections import defaultdict, Counter
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.platypus import  BaseDocTemplate, Frame, PageTemplate, SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import hashlib
import hmac

# Path to secrets file
SECRETS_FILE = "secrets.json"

# Configure logging
logging.basicConfig(
    filename="fortimanager.log",
    level=logging.DEBUG,  # Set to DEBUG for detailed logs
    format="%(asctime)s | %(levelname)s | %(filename)s:%(lineno)d | %(message)s",
)

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def generate_key(master_password):
    """Generate a 32-byte key from the master password using SHA-256."""
    return hashlib.sha256(master_password.encode()).digest()

def xor_decrypt(encrypted_hex, key):
    """Decrypt data using XOR with the provided key."""
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    decrypted = bytearray()
    key_len = len(key)
    for i, byte in enumerate(encrypted_bytes):
        decrypted.append(byte ^ key[i % key_len])  # XOR each byte with key
    return decrypted.decode()  # Convert bytes back to string

def load_secrets():
    """Prompt for the password, decrypt secrets, and store them in environment variables."""
    if not os.path.exists(SECRETS_FILE):
        logging.error("Secrets file not found.")
        raise FileNotFoundError(f"Secrets file '{SECRETS_FILE}' not found. Run secrets.py first.")

    for attempt in range(3, 0, -1):
        master_password = getpass("Enter the password to decrypt secrets: ")
        key = generate_key(master_password)

        with open(SECRETS_FILE, "r") as f:
            encrypted_data = json.load(f)

        try:
            decrypted_secrets = {k: xor_decrypt(v, key) for k, v in encrypted_data.items()}
            os.environ.update(decrypted_secrets)  # Store in environment variables
            logging.info("[+] Secrets loaded into environment variables securely.")
            return decrypted_secrets
        except Exception:
            logging.warning(f"[-] Incorrect password. Attempts left: {attempt - 1}")

def get_config(key, default=None):
    """Retrieve configuration values from environment variables."""
    value = os.getenv(key, default)
    if value is None:
        logging.warning(f"[!] Missing config value: {key}")
    return value

    logging.error("[-] Maximum password attempts exceeded.")
    raise SystemExit("[-] Exiting due to incorrect password attempts.")
def make_request(url, headers, payload):
    """Perform a POST request with retries and timeout."""
    session = requests.Session()
    retries = Retry(
        total=3,  # Retry failed requests up to 3 times
        backoff_factor=2,  # Exponential backoff (2s, 4s, 8s)
        status_forcelist=[500, 502, 503, 504],  # Retry on server errors
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))

    try:
        response = session.post(url, headers=headers, json=payload, verify=False, timeout=10)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"[!] HTTP Request failed: {e}")
        raise SystemExit(f"[-] Network error: {e}")

def fortimanager_connect(fmg_ip, username, password):
    """Attempt to authenticate with FortiManager and retrieve a session ID."""
    url = f"https://{fmg_ip}/jsonrpc"
    payload = {
        "id": 1,
        "method": "exec",
        "params": [{"data": [{"passwd": password, "user": username}], "url": "sys/login/user"}],
        "session": None,
    }

    try:
        response = make_request(url, {"Content-Type": "application/json"}, payload)
        session_id = response.json().get("session")

        if not session_id:
            logging.error("[-] Authentication failed: Invalid credentials.")
            raise ValueError("[-] Failed to connect to FortiManager. Check your credentials.")

        logging.info("[+] Successfully connected to FortiManager.")
        return session_id
    except requests.exceptions.RequestException as e:
        logging.error(f"[!] FortiManager connection error: {e}")
        raise SystemExit(f"[-] Unable to connect to FortiManager: {e}")


def fortimanager_logout(fmg_ip, session_id):
    url = f"https://{fmg_ip}/jsonrpc"
    payload = {"id": 5, "method": "exec", "params": [{"url": "/sys/logout"}], "session": session_id}
    try:
        make_request(url, {"Content-Type": "application/json"}, payload)
        print("[+] Session successfully closed.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error while logging out: {e}")

def get_fortigates(fmg_ip, session_id, adom):
    url = f"https://{fmg_ip}/jsonrpc"
    payload = {"id": 2, "method": "get", "params": [{"ostype": "FortiGate", "url": f"/dvmdb/adom/{adom}/device/"}], "session": session_id}
    response = make_request(url, {"Content-Type": "application/json"}, payload)
    devices = response.json().get("result", [{}])[0].get("data", [])
    return [{"name": dev["name"], "ip": dev["ip"]} for dev in devices]

def get_interfaces(fmg_ip, session_id, adom, fortigate_name, allowed_ports):
    url = f"https://{fmg_ip}/jsonrpc"
    payload = {
        "id": "1",
        "method": "exec",
        "params": [
            {
                "url": "sys/proxy/json",
                "data": {
                    "target": [f"adom/{adom}/device/{fortigate_name}"],
                    "action": "get",
                    "resource": "/api/v2/monitor/system/interface",
                },
            }
        ],
        "session": session_id,
    }
    response = make_request(url, {"Content-Type": "application/json"}, payload)
    results = response.json()["result"][0]["data"][0]["response"]["results"]

    return [
        {"device": fortigate_name, "interface": value["name"], "link": "UP" if value["link"] else "DOWN"}
        for key, value in results.items() if value["name"] in allowed_ports
    ]

def save_to_csv(data, filename):
    """Save the filtered interface data to a CSV file."""
    with open(filename, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["device", "interface", "link"])
        writer.writeheader()
        writer.writerows(data)
    logging.info(f"Results saved to {filename}.")
    print(f"Interface data saved to {filename}")

def aggregate_interfaces(csv_file):
    """Aggregate all interfaces and statuses into a single row per device."""
    device_interfaces = defaultdict(list)
    max_columns = 0
    summary = Counter()

    with open(csv_file, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            device = row["device"]
            interface_status = [row["interface"], row["link"]]
            device_interfaces[device].append(interface_status)
            summary[(row["interface"], row["link"])] += 1
            max_columns = max(max_columns, len(device_interfaces[device]) * 2)

    header = ["Device"]
    for i in range(1, (max_columns // 2) + 1):
        header.extend([f"Interface {i}", f"Status {i}"])

    aggregated_data = [header]
    for device, interfaces in device_interfaces.items():
        row = [device]
        for interface, status in interfaces:
            row.extend([interface, status])
        row.extend([""] * (max_columns - len(row) + 1))
        aggregated_data.append(row)

    return aggregated_data, summary

def create_summary_table(summary):
    """Create a summary table showing counts of UP/DOWN statuses for each interface."""
    summary_data = [["Interface", "Status", "Count"]]
    for (interface, status), count in summary.items():
        summary_data.append([interface, status, count])
    return summary_data

def create_pdf_with_summary(data, summary_data, output_pdf):
    """Generate a PDF report with tables and a footer displaying the timestamp."""
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def footer(canvas, doc):
        """Draw footer with timestamp on every page."""
        canvas.saveState()
        footer_text = f"Report generated on: {timestamp}"
        canvas.setFont("Helvetica", 9)
        canvas.drawCentredString(4.15 * inch, 0.5 * inch, footer_text)  # Position footer at the bottom
        canvas.restoreState()

    # Define the PDF document with a footer template
    pdf = BaseDocTemplate(output_pdf, pagesize=letter)
    frame = Frame(pdf.leftMargin, pdf.bottomMargin, pdf.width, pdf.height - 1 * inch, id='normal')
    template = PageTemplate(id='footer_template', frames=frame, onPage=footer)
    pdf.addPageTemplates([template])

    elements = []

    # Main Table
    main_table = Table(data)
    main_table_style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ])
    main_table.setStyle(main_table_style)
    elements.append(Paragraph("Main Table: Device Interfaces", getSampleStyleSheet()['Heading2']))
    elements.append(main_table)

    # Summary Table
    summary_table = Table(summary_data)
    summary_table_style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ])
    summary_table.setStyle(summary_table_style)
    elements.append(Paragraph("\nSummary Table: Interface Status Counts", getSampleStyleSheet()['Heading2']))
    elements.append(summary_table)

    pdf.build(elements)
    print(f"[+] PDF report saved as: {output_pdf}")

def send_email(subject, body, attachments, smtp_server, smtp_port, smtp_security, smtp_username, smtp_password, smtp_email_to):
    """Send an email with multiple attachments (PDF & CSV)."""
    
    msg = MIMEMultipart()
    msg["From"] = smtp_username
    msg["To"] = smtp_email_to
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    for attachment_path in attachments:
        if os.path.exists(attachment_path):  # Check if file exists before attaching
            with open(attachment_path, "rb") as attachment:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(attachment_path)}")
            msg.attach(part)
        else:
            logging.warning(f"[!] Attachment file not found: {attachment_path}")

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        if smtp_security.upper() == "TLS":
            server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(smtp_username, smtp_email_to, msg.as_string())
        server.quit()
        print(f"[+] Email with attachments sent successfully to {smtp_email_to}!")
    except smtplib.SMTPException as e:
        logging.error(f"[-] Failed to send email: {e}")
        print(f"[-] Error sending email: {e}")

def delete_generated_files(files):
    """Deletes the specified files from the filesystem."""
    for file in files:
        try:
            if os.path.exists(file):
                os.remove(file)
                logging.info(f"Deleted file: {file}")
                print(f"[+] Deleted file: {file}")
            else:
                logging.warning(f"File not found: {file}")
        except Exception as e:
            logging.error(f"Error deleting file {file}: {e}")

def main():
    # Prompt for master password and decrypt secrets
    attempts = 3
    secrets = None

    while attempts > 0:
        try:
            secrets = load_secrets()
            break  # Exit loop if decryption is successful
        except ValueError as e:
            attempts -= 1
            logging.warning(f"Failed to decrypt secrets. Attempts left: {attempts}")
            print(f"[-] Incorrect password or data corruption detected. Attempts remaining: {attempts}")

    if not secrets:
        print("[-] Maximum password attempts exceeded. Exiting.")
        logging.error("Max password attempts exceeded. Exiting.")
        return

    # Start FortiManager session
    attempts = 3
    session_id = None

    while attempts > 0:
        try:
            session_id = fortimanager_connect(
                get_config("fortimanager_ip"),
                get_config("fortimanager_username"),
                get_config("fortimanager_password"),
            )
            break  # Exit loop on success
        except ValueError as e:
            attempts -= 1
            logging.warning(f"[-] FortiManager login failed. Attempts remaining: {attempts}")
            print(f"[-] Login failed. Attempts left: {attempts}")

    if not session_id:
        logging.error("[-] Maximum login attempts exceeded.")
        raise SystemExit("[-] Exiting due to failed authentication attempts.")


    try:
        fortigates = get_fortigates(secrets["fortimanager_ip"], session_id, secrets["adom"])
        allowed_ports = [port.strip() for port in secrets["ports"].split(",")]

        interface_data = []
        for fg in fortigates:
            print(f"Fetching interfaces for FortiGate: {fg['name']}...")
            interface_data.extend(
                get_interfaces(secrets["fortimanager_ip"], session_id, secrets["adom"], fg["name"], allowed_ports)
            )

        csv_filename = f"interface_data_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        save_to_csv(interface_data, csv_filename)

        aggregated_data, summary = aggregate_interfaces(csv_filename)
        summary_table = create_summary_table(summary)

        pdf_filename = f"interface_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        create_pdf_with_summary(aggregated_data, summary_table, pdf_filename)

        send_email(
            "Interface Report",
            "Please find the attached interface report.",
            [pdf_filename, csv_filename],  # Send both PDF and CSV
            secrets["smtp_server"],
            int(secrets["smtp_port"]),
            secrets["smtp_security"],
            secrets["smtp_username"],
            secrets["smtp_password"],
            secrets["smtp_email_to"],
        )

        # Delete files after email is sent
        delete_generated_files([csv_filename, pdf_filename])

    finally:
        fortimanager_logout(secrets["fortimanager_ip"], session_id)


if __name__ == "__main__":
    main()
