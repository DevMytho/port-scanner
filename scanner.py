import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
from concurrent.futures import ThreadPoolExecutor
import queue
import subprocess
import shutil
import os
import platform

# ─────────────────────────────────────────────
# Detect OS
# ─────────────────────────────────────────────
OS_TYPE = platform.system()  # "Linux", "Darwin" (macOS), "Windows"

# ─────────────────────────────────────────────
# Auto-install Dependencies
# ─────────────────────────────────────────────
def install_nmap():
    print(f"[*] Detected OS: {OS_TYPE}")
    print("[*] Attempting to install nmap...")
    try:
        if OS_TYPE == "Linux":
            subprocess.run(["sudo", "apt-get", "install", "-y", "nmap"], check=True)
        elif OS_TYPE == "Darwin":
            if not shutil.which("brew"):
                print("[!] Homebrew not found. Install from https://brew.sh then run: brew install nmap")
                return False
            subprocess.run(["brew", "install", "nmap"], check=True)
        elif OS_TYPE == "Windows":
            if shutil.which("winget"):
                subprocess.run(["winget", "install", "-e", "--id", "Insecure.Nmap"], check=True)
            else:
                print("[!] Please install nmap manually from: https://nmap.org/download.html")
                return False
        print("[+] nmap installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to install nmap: {e}")
        return False


def check_and_install_dependencies():
    if not shutil.which("nmap"):
        print("[!] nmap not found. Trying to install...")
        success = install_nmap()
        if not success:
            print("[!] Could not auto-install nmap. Banner grabbing will be disabled.")
    else:
        print("[+] nmap is already installed.")


check_and_install_dependencies()
NMAP_AVAILABLE = bool(shutil.which("nmap"))

# ─────────────────────────────────────────────
# Global State
# ─────────────────────────────────────────────
stop_scan = False
gui_queue = queue.Queue()  # background threads post updates here; main thread reads


# ─────────────────────────────────────────────
# Banner Grabbing (OS-aware)
# ─────────────────────────────────────────────
def grab_banner_nmap(ip, port):
    try:
        if OS_TYPE == "Windows":
            cmd = f"nmap -p {port} --script=banner {ip}"
        else:
            cmd = f"sudo nmap -p {port} --script=banner {ip}"
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=60)
        for line in result.stdout.split("\n"):
            if "open" in line and "Service Info" not in line:
                return line.strip()
        return "No Banner Found"
    except Exception:
        return "Banner grab failed"


# ─────────────────────────────────────────────
# Port Scan Worker  (runs inside ThreadPoolExecutor)
# ─────────────────────────────────────────────
def scan_port_worker(ip, port, total_ports):
    global stop_scan
    if stop_scan:
        return

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        s.close()

        if result == 0:
            banner = grab_banner_nmap(ip, port) if NMAP_AVAILABLE else "nmap unavailable"
            output = f"[+] Port {port} — OPEN  |  {banner}\n"
            tag    = "open"
        else:
            output = f"[-] Port {port} — closed\n"
            tag    = "closed"

    except Exception as e:
        output = f"[!] Port {port} — error: {e}\n"
        tag    = "error"

    # Save to file
    with open("scan_results.txt", "a") as f:
        f.write(output)

    # Never touch Tkinter from here — use the queue instead
    gui_queue.put(("log", output, tag))
    gui_queue.put(("progress", total_ports))


# ─────────────────────────────────────────────
# GUI Queue Processor — runs on main thread via root.after()
# ─────────────────────────────────────────────
def process_gui_queue():
    try:
        while True:
            msg = gui_queue.get_nowait()

            if msg[0] == "log":
                _, output, tag = msg
                text_area.insert(tk.END, output, tag)
                text_area.yview(tk.END)

            elif msg[0] == "progress":
                _, total = msg
                progress_bar["value"] += 1
                pct = int((progress_bar["value"] / total) * 100)
                progress_label.config(text=f"  {pct}%")

            elif msg[0] == "done":
                text_area.insert(tk.END, "\n[*] Scan complete.\n", "info")
                scan_button.config(state="normal")

    except queue.Empty:
        pass

    root.after(50, process_gui_queue)  # poll every 50ms


# ─────────────────────────────────────────────
# Start Scan
# ─────────────────────────────────────────────
def start_scan():
    global stop_scan
    stop_scan = False

    ip = ip_entry.get().strip()
    if not ip:
        messagebox.showwarning("Missing Input", "Please enter an IP address.")
        return

    try:
        start_port = int(start_port_entry.get() or 1)
        end_port   = int(end_port_entry.get() or 1024)
    except ValueError:
        messagebox.showerror("Invalid Input", "Ports must be numbers.")
        return

    text_area.delete("1.0", tk.END)
    text_area.insert(tk.END, f"[*] OS      : {OS_TYPE}\n",                   "info")
    text_area.insert(tk.END, f"[*] nmap    : {NMAP_AVAILABLE}\n",            "info")
    text_area.insert(tk.END, f"[*] Target  : {ip}\n",                        "info")
    text_area.insert(tk.END, f"[*] Range   : {start_port} → {end_port}\n\n", "info")

    with open("scan_results.txt", "w") as f:
        f.write(f"Scan: {ip} | Ports {start_port}-{end_port}\n{'='*50}\n")

    total_ports = end_port - start_port + 1
    progress_bar["maximum"] = total_ports
    progress_bar["value"]   = 0
    scan_button.config(state="disabled")

    def run_pool():
        # max_workers=100 caps concurrent threads — no more "can't start new thread"
        with ThreadPoolExecutor(max_workers=100) as executor:
            for port in range(start_port, end_port + 1):
                if stop_scan:
                    break
                executor.submit(scan_port_worker, ip, port, total_ports)
        gui_queue.put(("done",))

    threading.Thread(target=run_pool, daemon=True).start()


# ─────────────────────────────────────────────
# Stop Scan
# ─────────────────────────────────────────────
def stop_scan_action():
    global stop_scan
    stop_scan = True
    text_area.insert(tk.END, "\n[!] Scan stopped by user.\n", "warning")
    scan_button.config(state="normal")


# ─────────────────────────────────────────────
# Open Results (OS-aware)
# ─────────────────────────────────────────────
def open_results():
    if not os.path.exists("scan_results.txt"):
        text_area.insert(tk.END, "\n[!] No results yet. Run a scan first.\n", "warning")
        return
    if OS_TYPE == "Windows":
        os.system("notepad scan_results.txt")
    elif OS_TYPE == "Darwin":
        subprocess.run(["open", "scan_results.txt"])
    else:
        subprocess.run(["xdg-open", "scan_results.txt"])


# ─────────────────────────────────────────────
# Theme
# ─────────────────────────────────────────────
BG         = "#0a0a0f"
BG2        = "#111118"
BG3        = "#1c1c28"
GREEN      = "#00ff88"
RED        = "#ff6b6b"
BLUE       = "#4fc3f7"
YELLOW     = "#ffd54f"
DIM        = "#444466"
FG         = "#e0e0e0"
FONT_MONO  = ("Courier", 10)
FONT_LABEL = ("Courier", 9)

# ─────────────────────────────────────────────
# GUI
# ─────────────────────────────────────────────
root = tk.Tk()
root.title(f"MeowCode — Port Scanner [{OS_TYPE}]")
root.geometry("700x620")
root.resizable(False, False)
root.configure(bg=BG)

# Title bar
title_frame = tk.Frame(root, bg=BG3, pady=10)
title_frame.pack(fill="x")
tk.Label(title_frame, text="🐱 MeowCode  //  Port Scanner",
         font=("Courier", 13, "bold"), bg=BG3, fg=GREEN).pack(side="left", padx=16)
tk.Label(title_frame, text=f"{OS_TYPE}  |  {'✓ nmap ready' if NMAP_AVAILABLE else '✗ nmap missing'}",
         font=FONT_LABEL, bg=BG3,
         fg=GREEN if NMAP_AVAILABLE else RED).pack(side="right", padx=16)

tk.Frame(root, bg=GREEN, height=2).pack(fill="x")

# Input fields
input_frame = tk.Frame(root, bg=BG, pady=12, padx=16)
input_frame.pack(fill="x")

def make_label(parent, text):
    return tk.Label(parent, text=text, font=FONT_LABEL, bg=BG, fg=DIM, anchor="w")

def make_entry(parent, width=22):
    return tk.Entry(parent, width=width, font=FONT_MONO,
                    bg=BG2, fg=GREEN, insertbackground=GREEN,
                    relief="flat", bd=0, highlightthickness=1,
                    highlightcolor=GREEN, highlightbackground=DIM)

make_label(input_frame, "TARGET IP").grid(row=0, column=0, sticky="w", padx=(0, 10))
ip_entry = make_entry(input_frame, width=24)
ip_entry.grid(row=0, column=1, sticky="w", padx=(0, 30))

make_label(input_frame, "START PORT").grid(row=0, column=2, sticky="w", padx=(0, 10))
start_port_entry = make_entry(input_frame, width=8)
start_port_entry.grid(row=0, column=3, sticky="w", padx=(0, 16))

make_label(input_frame, "END PORT").grid(row=0, column=4, sticky="w", padx=(0, 10))
end_port_entry = make_entry(input_frame, width=8)
end_port_entry.grid(row=0, column=5, sticky="w")

# Buttons
btn_frame = tk.Frame(root, bg=BG, pady=6, padx=16)
btn_frame.pack(fill="x")

def make_btn(parent, text, cmd, color, textcolor="#0a0a0f"):
    return tk.Button(parent, text=text, command=cmd,
                     font=("Courier", 10, "bold"),
                     bg=color, fg=textcolor,
                     activebackground=color, activeforeground=textcolor,
                     relief="flat", bd=0, padx=18, pady=6, cursor="hand2")

scan_button = make_btn(btn_frame, "▶  START SCAN",   start_scan,       GREEN)
stop_button = make_btn(btn_frame, "■  STOP",          stop_scan_action, RED,  "#ffffff")
open_button = make_btn(btn_frame, "📄  OPEN RESULTS", open_results,     BG3,  BLUE)
scan_button.pack(side="left", padx=(0, 10))
stop_button.pack(side="left", padx=(0, 10))
open_button.pack(side="left")

# Terminal output
tk.Frame(root, bg=DIM, height=1).pack(fill="x", pady=(10, 0))
term_header = tk.Frame(root, bg=BG3, pady=6)
term_header.pack(fill="x")
for dot in ["#ff5f57", "#ffbd2e", "#28c840"]:
    tk.Label(term_header, text="●", fg=dot, bg=BG3, font=("Courier", 10)).pack(side="left", padx=3)
tk.Label(term_header, text="scan_output.log", font=FONT_LABEL, bg=BG3, fg=DIM).pack(side="left", padx=8)

text_area = scrolledtext.ScrolledText(root, width=82, height=16,
                                       font=FONT_MONO, bg=BG2, fg=FG,
                                       insertbackground=GREEN,
                                       relief="flat", bd=0, padx=12, pady=10, wrap="word")
text_area.pack(fill="both")
text_area.tag_config("open",    foreground=GREEN)
text_area.tag_config("closed",  foreground=DIM)
text_area.tag_config("error",   foreground=RED)
text_area.tag_config("info",    foreground=BLUE)
text_area.tag_config("warning", foreground=YELLOW)

# Progress bar
tk.Frame(root, bg=DIM, height=1).pack(fill="x")
progress_frame = tk.Frame(root, bg=BG, pady=10, padx=16)
progress_frame.pack(fill="x")

style = ttk.Style()
style.theme_use("default")
style.configure("green.Horizontal.TProgressbar",
                troughcolor=BG3, background=GREEN, thickness=8)

progress_bar = ttk.Progressbar(progress_frame, length=560, mode="determinate",
                                style="green.Horizontal.TProgressbar")
progress_bar.pack(side="left")

progress_label = tk.Label(progress_frame, text="  0%", font=FONT_LABEL, bg=BG, fg=GREEN)
progress_label.pack(side="left", padx=10)

# Kick off the queue processor on the main thread
root.after(50, process_gui_queue)

root.mainloop()
