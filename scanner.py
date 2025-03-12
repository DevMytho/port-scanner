import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk
import subprocess
import shutil
import os

NMAP_AVAILABLE = bool(shutil.which("nmap"))

# Global Variables
stop_scan = False

# Function to grab banners using Nmap
def grab_banner_nmap(ip, port):
    try:
        cmd = f"sudo nmap -p {port} --script=banner {ip}"
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=60)
        lines = result.stdout.split("\n")
        for line in lines:
            if "open" in line and "Service Info" not in line:
                return line.strip()
        return "No Banner Found"
    except Exception:
        return "Nmap banner grabbing failed"

# Function to scan ports
def scan_port(ip, port, total_ports):
    global stop_scan

    if stop_scan:
        return

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        if result == 0:
            banner = grab_banner_nmap(ip, port) if NMAP_AVAILABLE else "Nmap not available"
            output = f"[+] Port {port} is Open | Service: {banner}"
        else:
            output = f"[-] Port {port} is Closed"
        
        s.close()
    except Exception as e:
        output = f"[!] Error scanning port {port}: {e}"

    # Update UI
    text_area.insert(tk.END, output + "\n")
    text_area.yview(tk.END)  # Auto-scroll

    # Save results to file
    with open("scan_results.txt", "a") as log_file:
        log_file.write(output + "\n")

    # Update Progress Bar
    progress_bar["value"] += 1
    progress_label.config(text=f"Progress: {int((progress_bar['value'] / total_ports) * 100)}%")

# Start scanning in a separate thread
def start_scan():
    global stop_scan
    stop_scan = False
    ip = ip_entry.get()
    start_port = int(start_port_entry.get() or 1)
    end_port = int(end_port_entry.get() or 65535)

    text_area.delete('1.0', tk.END)  # Clear previous results
    text_area.insert(tk.END, f"Scanning {ip} from port {start_port} to {end_port}\n\n")

    # Clear scan results file
    with open("scan_results.txt", "w") as log_file:
        log_file.write(f"Scan Results for {ip} (Ports {start_port}-{end_port})\n")
        log_file.write("=" * 50 + "\n")

    total_ports = end_port - start_port + 1
    progress_bar["maximum"] = total_ports
    progress_bar["value"] = 0

    for port in range(start_port, end_port + 1):
        if stop_scan:
            break
        thread = threading.Thread(target=scan_port, args=(ip, port, total_ports))
        thread.start()

# Stop scan function
def stop_scan_action():
    global stop_scan
    stop_scan = True
    text_area.insert(tk.END, "\n[!] Scan Stopped by User.\n")

# Function to open scan_results.txt
def open_results():
    if os.path.exists("scan_results.txt"):
        if os.name == "nt":  # Windows
            os.system("notepad scan_results.txt")
        else:  # macOS/Linux
            subprocess.run(["xdg-open", "scan_results.txt"])
    else:
        text_area.insert(tk.END, "\n[!] No scan results found. Run a scan first.\n")

# GUI Setup
root = tk.Tk()
root.title("Port Scanner")
root.geometry("600x550")

# Labels and Entry fields
tk.Label(root, text="IP Address:").grid(row=0, column=0, padx=5, pady=5)
ip_entry = tk.Entry(root, width=25)
ip_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(root, text="Start Port:").grid(row=1, column=0, padx=5, pady=5)
start_port_entry = tk.Entry(root, width=10)
start_port_entry.grid(row=1, column=1, padx=5, pady=5)

tk.Label(root, text="End Port:").grid(row=2, column=0, padx=5, pady=5)
end_port_entry = tk.Entry(root, width=10)
end_port_entry.grid(row=2, column=1, padx=5, pady=5)

# Scan and Stop Buttons
scan_button = tk.Button(root, text="Start Scan", command=start_scan, bg="green", fg="white")
scan_button.grid(row=3, column=0, pady=10)

stop_button = tk.Button(root, text="Stop Scan", command=stop_scan_action, bg="red", fg="white")
stop_button.grid(row=3, column=1, pady=10)

# Open Results Button
open_button = tk.Button(root, text="Open Results", command=open_results, bg="blue", fg="white")
open_button.grid(row=3, column=2, pady=10)

# Output Text Area (Scrollable)
text_area = scrolledtext.ScrolledText(root, width=70, height=15)
text_area.grid(row=4, column=0, columnspan=3, padx=5, pady=5)

# Progress Bar
progress_bar = ttk.Progressbar(root, length=500, mode="determinate")
progress_bar.grid(row=5, column=0, columnspan=3, pady=10)

progress_label = tk.Label(root, text="Progress: 0%")
progress_label.grid(row=6, column=0, columnspan=3, pady=5)

# Run the Tkinter event loop
root.mainloop()
