import sys
from scapy.all import sniff, IP, Raw

# Define signature rules (just a simple example)
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

def detect_intrusion(packet):
    # Check if the packet has Raw layer
    if packet.haslayer(Raw):
        payload = packet[Raw].load

        # Compare packet payload against each signature rule
        for rule in signature_rules:
            if rule["pattern"] in payload:
                print(f"Signature match: {rule['msg']}")
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
                # Take appropriate action here (e.g., logging, alerting)

def main():
    if len(sys.argv) != 2:
        print("Usage: python sniffer.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]

    print(f"Sniffing on interface: {interface}")
    sniff(iface=interface, prn=detect_intrusion, store=0)

if __name__ == "__main__":
    main()
