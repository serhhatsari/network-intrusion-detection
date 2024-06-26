import sys
import tkinter as tk
from tkinter import ttk, messagebox, Toplevel
from scapy.all import sniff, IP, Raw
import threading
from patterns import signature_rules

packet_details = {}
signature_details = []

# Function to detect intrusion based on signature rules
def detect_intrusion(packet, signature_matches_listbox, packet_listbox, packet_id):
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        for rule in signature_rules:
            if rule["pattern"] in payload:
                signature_details.append({
                    "msg": rule['msg'],
                    "src_ip": packet[IP].src,
                    "dst_ip": packet[IP].dst,
                    "proto": packet[IP].proto,
                    "length": len(packet),
                    "data": payload.decode("utf-8", "ignore")
                })
                signature_matches_listbox.insert(tk.END, rule["msg"])
                packet_listbox.itemconfig(packet_id, {'bg':'red'})

# Function to update the packet list
def update_packet_list(packet, packet_listbox, signature_matches_listbox):
    if not packet.haslayer(IP):
        return

    packet_id = len(packet_details)
    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    protocol_number = packet[IP].proto
    protocol = "TCP" if protocol_number == 6 else "UDP" if protocol_number == 17 else "Other"
    packet_length = len(packet)
    packet_info = f"Source IP: {source_ip} | Destination IP: {destination_ip} | Protocol: {protocol} | Length: {packet_length} bytes"
    packet_listbox.insert(tk.END, packet_info)
    packet_details[packet_id] = {
        "src_ip": source_ip,
        "dst_ip": destination_ip,
        "proto": protocol,
        "length": packet_length,
        "data": packet[Raw].load.decode("utf-8", "ignore") if packet.haslayer(Raw) else "No Raw Data"
    }
    detect_intrusion(packet, signature_matches_listbox, packet_listbox, packet_id)

# Function to show packet details in a popup window
def show_packet_details(event, packet_listbox):
    selection = packet_listbox.curselection()
    if selection:
        packet_id = selection[0]
        details = packet_details[packet_id]

        details_window = Toplevel()
        details_window.title("Packet Details")

        ttk.Label(details_window, text="Source IP:").pack(anchor="w")
        ttk.Label(details_window, text=details["src_ip"]).pack(anchor="w")

        ttk.Label(details_window, text="Destination IP:").pack(anchor="w")
        ttk.Label(details_window, text=details["dst_ip"]).pack(anchor="w")

        ttk.Label(details_window, text="Protocol:").pack(anchor="w")
        ttk.Label(details_window, text=details["proto"]).pack(anchor="w")

        ttk.Label(details_window, text="Length:").pack(anchor="w")
        ttk.Label(details_window, text=f"{details['length']} bytes").pack(anchor="w")

        ttk.Label(details_window, text="Data:").pack(anchor="w")
        data_text = tk.Text(details_window, wrap="word", height=10, width=50)
        data_text.insert(tk.END, details["data"])
        data_text.config(state=tk.DISABLED)
        data_text.pack(anchor="w")

# Function to show signature match details in a popup window
def show_match_details(event, signature_matches_listbox):
    selection = signature_matches_listbox.curselection()
    if selection:
        match_id = selection[0]
        details = signature_details[match_id]

        details_window = Toplevel()
        details_window.title("Signature Match Details")

        ttk.Label(details_window, text="Message:").pack(anchor="w")
        ttk.Label(details_window, text=details["msg"]).pack(anchor="w")

        ttk.Label(details_window, text="Source IP:").pack(anchor="w")
        ttk.Label(details_window, text=details["src_ip"]).pack(anchor="w")

        ttk.Label(details_window, text="Destination IP:").pack(anchor="w")
        ttk.Label(details_window, text=details["dst_ip"]).pack(anchor="w")

        ttk.Label(details_window, text="Protocol:").pack(anchor="w")
        ttk.Label(details_window, text=details["proto"]).pack(anchor="w")

        ttk.Label(details_window, text="Length:").pack(anchor="w")
        ttk.Label(details_window, text=f"{details['length']} bytes").pack(anchor="w")

        ttk.Label(details_window, text="Data:").pack(anchor="w")
        data_text = tk.Text(details_window, wrap="word", height=10, width=50)
        data_text.insert(tk.END, details["data"])
        data_text.config(state=tk.DISABLED)
        data_text.pack(anchor="w")

# Function to show pattern details in a popup window
def show_pattern_details(event, pattern_listbox):
    selection = pattern_listbox.curselection()
    if selection:
        pattern_id = selection[0]
        details = signature_rules[pattern_id]

        details_window = Toplevel()
        details_window.title("Pattern Details")

        ttk.Label(details_window, text="Pattern:").pack(anchor="w")
        ttk.Label(details_window, text=details["pattern"].decode()).pack(anchor="w")

        ttk.Label(details_window, text="Message:").pack(anchor="w")
        ttk.Label(details_window, text=details["msg"]).pack(anchor="w")

# Function to add a new pattern
def add_pattern(pattern_entry, message_entry, pattern_listbox):
    pattern = pattern_entry.get()
    message = message_entry.get()
    if pattern and message:
        try:
            pattern_bytes = pattern.encode()
            signature_rules.append({"pattern": pattern_bytes, "msg": message})
            pattern_listbox.insert(tk.END, f"Pattern: {pattern} | Message: {message}")
            pattern_entry.delete(0, tk.END)
            message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Invalid pattern: {e}")
    else:
        messagebox.showerror("Error", "Both pattern and message fields must be filled out.")

# Create Tkinter GUI
def create_gui(interface):
    root = tk.Tk()
    root.title("Intrusion Detection System")

    # Set the window size to cover the entire desktop
    window_width = root.winfo_screenwidth()
    window_height = root.winfo_screenheight()
    root.geometry(f"{window_width}x{window_height}")

    # Packet List Section
    packet_frame = ttk.Frame(root, width=window_width // 3, height=window_height)
    packet_frame.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.BOTH, expand=True)

    packet_label = ttk.Label(packet_frame, text="Packet List", font=("Helvetica", 16, "bold"))
    packet_label.pack(pady=10)

    packet_scrollbar = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL)
    packet_listbox = tk.Listbox(packet_frame, yscrollcommand=packet_scrollbar.set, font=("Courier", 12), width=50, selectmode=tk.SINGLE)
    packet_scrollbar.config(command=packet_listbox.yview)
    packet_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    packet_listbox.pack(fill=tk.BOTH, expand=True)

    # Bind double-click event to packet listbox
    packet_listbox.bind("<Double-1>", lambda event: show_packet_details(event, packet_listbox))

    # Signature Matches Section
    signature_frame = ttk.Frame(root, width=window_width // 3, height=window_height)
    signature_frame.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.BOTH, expand=True)

    signature_label = ttk.Label(signature_frame, text="Signature Matches", font=("Helvetica", 16, "bold"))
    signature_label.pack(pady=10)

    signature_scrollbar = ttk.Scrollbar(signature_frame, orient=tk.VERTICAL)
    signature_matches_listbox = tk.Listbox(signature_frame, yscrollcommand=signature_scrollbar.set, font=("Courier", 12), width=50)
    signature_scrollbar.config(command=signature_matches_listbox.yview)
    signature_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    signature_matches_listbox.pack(fill=tk.BOTH, expand=True)

    # Bind double-click event to signature matches listbox
    signature_matches_listbox.bind("<Double-1>", lambda event: show_match_details(event, signature_matches_listbox))

    # Add Pattern Section
    add_pattern_frame = ttk.Frame(root, width=window_width // 3, height=window_height)
    add_pattern_frame.pack(side=tk.RIGHT, padx=10, pady=10, fill=tk.BOTH, expand=True)

    add_pattern_label = ttk.Label(add_pattern_frame, text="Add New Pattern", font=("Helvetica", 16, "bold"))
    add_pattern_label.pack(pady=10)

    ttk.Label(add_pattern_frame, text="Pattern (regex):").pack(anchor="w")
    pattern_entry = ttk.Entry(add_pattern_frame, font=("Courier", 12), width=50)
    pattern_entry.pack(pady=5)

    ttk.Label(add_pattern_frame, text="Message:").pack(anchor="w")
    message_entry = ttk.Entry(add_pattern_frame, font=("Courier", 12), width=50)
    message_entry.pack(pady=5)

    add_pattern_button = ttk.Button(add_pattern_frame, text="Add Pattern", command=lambda: add_pattern(pattern_entry, message_entry, pattern_listbox))
    add_pattern_button.pack(pady=10)

    pattern_listbox = tk.Listbox(add_pattern_frame, font=("Courier", 12), width=50)
    pattern_listbox.pack(fill=tk.BOTH, expand=True)

    # Bind double-click event to pattern listbox
    pattern_listbox.bind("<Double-1>", lambda event: show_pattern_details(event, pattern_listbox))

    # Initialize the pattern listbox with existing patterns
    for rule in signature_rules:
        pattern_listbox.insert(tk.END, f"Pattern: {rule['pattern'].decode()} | Message: {rule['msg']}")

    # Start packet capture and intrusion detection
    def start_capture():
        threading.Thread(target=lambda: sniff(iface=interface, prn=lambda x: update_packet_list(x, packet_listbox, signature_matches_listbox), store=0)).start()

    start_button = ttk.Button(root, text="Start Capture", command=start_capture)
    start_button.pack(pady=10)

    root.mainloop()

def main():
    if len(sys.argv) != 2:
        print("Usage: python sniffer.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    create_gui(interface)

if __name__ == "__main__":
    main()
