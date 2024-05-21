import sys
import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, Raw
import threading

signature_rules = [
    {"pattern": b"/etc/passwd", "msg": "Potential Directory Traversal Attack: Attempt to access system password file."},
    {"pattern": b"SELECT * FROM users", "msg": "Potential SQL Injection Attack: Attempt to retrieve all records from the 'users' table."},
    {"pattern": b"DROP TABLE", "msg": "Potential SQL Injection Attack: Attempt to drop a database table."},
    {"pattern": b"cmd.exe", "msg": "Potential Command Injection Attack: Attempt to execute a system command on Windows."},
    {"pattern": b"; exec(", "msg": "Potential Command Injection Attack: Attempt to execute a system command on Unix."},
    {"pattern": b"passwd:", "msg": "Potential Password Leak: Identification of 'passwd:' keyword in the payload."},
    {"pattern": b"ssh-rsa", "msg": "Potential SSH Key Exchange: Identification of SSH RSA key exchange."},
    {"pattern": b"SELECT * FROM passwords", "msg": "Potential SQL Injection Attack: Attempt to retrieve all records from the 'passwords' table."},
    {"pattern": b"/bin/sh", "msg": "Potential Command Injection Attack: Attempt to execute a shell command."},
    {"pattern": b"/etc/shadow", "msg": "Potential Directory Traversal Attack: Attempt to access system password hash file."},
    {"pattern": b"UNION ALL SELECT", "msg": "Potential SQL Injection Attack: Attempt to perform a UNION-based SQL injection."},
    {"pattern": b"<script>alert(", "msg": "Potential Cross-Site Scripting (XSS) Attack: Attempt to execute a JavaScript alert."},
    {"pattern": b"DELETE FROM", "msg": "Potential SQL Injection Attack: Attempt to delete records from a database table."},
    {"pattern": b"exec sp_", "msg": "Potential SQL Injection Attack: Attempt to execute a stored procedure in SQL Server."},
    {"pattern": b"/bin/bash", "msg": "Potential Command Injection Attack: Attempt to execute a bash command."},
    {"pattern": b"ORA-", "msg": "Potential Oracle Database Error: Identification of 'ORA-' error message."},
    {"pattern": b"ALTER TABLE", "msg": "Potential SQL Injection Attack: Attempt to alter database table structure."},
    {"pattern": b"<script>window.location", "msg": "Potential Redirection Attack: Attempt to redirect the user to another page."},
    {"pattern": b"admin' OR '1'='1", "msg": "Potential SQL Injection Attack: Attempt to bypass authentication."},
    {"pattern": b"root:", "msg": "Potential Privilege Escalation: Identification of 'root:' keyword in the payload."},
    {"pattern": b"GET /etc/passwd", "msg": "Potential Directory Traversal Attack: Attempt to retrieve system password file via HTTP GET request."},
    {"pattern": b"127.0.0.1", "msg": "Potential Localhost Access: Identification of '127.0.0.1' IP address in the payload."},
    {"pattern": b"SELECT * FROM information_schema", "msg": "Potential SQL Injection Attack: Attempt to retrieve database schema information."},
    {"pattern": b"<script>document.cookie", "msg": "Potential Cross-Site Scripting (XSS) Attack: Attempt to access user cookies."},
    {"pattern": b"UPDATE users SET password", "msg": "Potential SQL Injection Attack: Attempt to update user passwords."},
    {"pattern": b"DROP DATABASE", "msg": "Potential SQL Injection Attack: Attempt to drop the entire database."},
    {"pattern": b"<script>window.open(", "msg": "Potential Pop-up Window Attack: Attempt to open a new browser window."},
    {"pattern": b"DELETE FROM users", "msg": "Potential SQL Injection Attack: Attempt to delete all records from the 'users' table."},
    {"pattern": b"xp_cmdshell", "msg": "Potential Command Injection Attack: Attempt to execute a system command using xp_cmdshell in SQL Server."},
]

# Function to detect intrusion based on signature rules
def detect_intrusion(packet, signature_matches_listbox):
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        for rule in signature_rules:
            if rule["pattern"] in payload:
                print(f"Signature match: {rule['msg']}")
                # print payload
                print("Packet Details:")
                print("====================")
                print(f"Source IP: {packet[IP].src}")
                print(f"Destination IP: {packet[IP].dst}")
                print(f"Protocol: {packet[IP].proto}")
                print(f"Packet Length: {len(packet)} bytes")
                print(f"Raw Packet Data: {packet.summary()}")
                print("Packet Payload:")
                print(payload.decode("utf-8", "ignore"))
                print("====================\n")
                signature_matches_listbox.insert(tk.END, rule["msg"])


# Function to update the packet list
def update_packet_list(packet, packet_listbox):
    if not packet.haslayer(IP):
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    protocol_number = packet[IP].proto
    protocol = "TCP" if protocol_number == 6 else "UDP" if protocol_number == 17 else "Other"
    packet_length = len(packet)
    #packet_payload = packet[Raw].load.decode("utf-8", "ignore") if packet.haslayer(Raw) else ""
    packet_info = f"Source IP: {source_ip} | Destination IP: {destination_ip} | Protocol: {protocol} | Length: {packet_length} bytes"
    packet_listbox.insert(tk.END, packet_info)


# Create Tkinter GUI
def create_gui(interface):
    root = tk.Tk()
    root.title("Intrusion Detection System")

    # Set the window size to cover the entire desktop
    window_width = root.winfo_screenwidth()
    window_height = root.winfo_screenheight()
    root.geometry(f"{window_width}x{window_height}")

    # Packet List Section
    packet_frame = ttk.Frame(root, width=window_width // 2, height=window_height)
    packet_frame.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.BOTH, expand=True)

    packet_label = ttk.Label(packet_frame, text="Packet List", font=("Helvetica", 16, "bold"))
    packet_label.pack(pady=10)

    packet_scrollbar = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL)
    packet_listbox = tk.Listbox(packet_frame, yscrollcommand=packet_scrollbar.set, font=("Courier", 12), width=50, selectmode=tk.MULTIPLE)
    packet_scrollbar.config(command=packet_listbox.yview)
    packet_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    packet_listbox.pack(fill=tk.BOTH, expand=True)

    # Signature Matches Section
    signature_frame = ttk.Frame(root, width=window_width // 2, height=window_height)
    signature_frame.pack(side=tk.RIGHT, padx=10, pady=10, fill=tk.BOTH, expand=True)

    signature_label = ttk.Label(signature_frame, text="Signature Matches", font=("Helvetica", 16, "bold"))
    signature_label.pack(pady=10)

    signature_scrollbar = ttk.Scrollbar(signature_frame, orient=tk.VERTICAL)
    signature_matches_listbox = tk.Listbox(signature_frame, yscrollcommand=signature_scrollbar.set, font=("Courier", 12), width=50)
    signature_scrollbar.config(command=signature_matches_listbox.yview)
    signature_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    signature_matches_listbox.pack(fill=tk.BOTH, expand=True)

    # Start packet capture and intrusion detection
    def start_capture():
        threading.Thread(target=lambda: sniff(iface=interface, prn=lambda x: update_packet_list(x, packet_listbox), store=0)).start()
        threading.Thread(target=lambda: sniff(iface=interface, prn=lambda x: detect_intrusion(x, signature_matches_listbox), store=0)).start()

    start_button = ttk.Button(root, text="Start Capture", command=start_capture)
    start_button.pack()

    root.mainloop()

def main():
    if len(sys.argv) != 2:
        print("Usage: python sniffer.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    create_gui(interface)

if __name__ == "__main__":
    main()
