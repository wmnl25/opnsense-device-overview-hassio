import os
from flask import Flask, render_template_string
import requests
from requests.auth import HTTPBasicAuth
import urllib3
from datetime import datetime
import socket
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

# Suppress insecure HTTPS warnings if OPNsense uses a self-signed certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables from the .env file
# --- DIAGNOSTIC BLOCK ---
basedir = os.path.abspath(os.path.dirname(__file__))
env_path = os.path.join(basedir, '.env')

print("--- DEBUG INFO ---")
print(f"Looking for .env at: {env_path}")
print(f"Does file exist? {os.path.exists(env_path)}")
print(f"Files in directory: {os.listdir(basedir)}")
print("------------------")

load_dotenv(env_path)
# ------------------------

app = Flask(__name__)

# --- CONFIGURATION ---
OPNSENSE_URL = os.environ.get("OPNSENSE_URL")
API_KEY = os.environ.get("OPNSENSE_API_KEY")
API_SECRET = os.environ.get("OPNSENSE_API_SECRET")

print(f"URL: {OPNSENSE_URL}")
print(f"KEY: {API_KEY}")
print(f"SECRET: {API_SECRET}")
# ---------------------

if not API_KEY or not API_SECRET:
    print("WARNING: API credentials not found in environment variables!")

def guess_device_info(vendor, hostname):
    v = vendor.lower()
    h = hostname.lower()
    
    icon = "📱" 
    dev_type = "Unknown"

    if any(k in v for k in ["apple", "samsung", "xiaomi", "redmi", "motorola"]):
        icon = "📱"
        dev_type = "Phone/Tablet"
    elif any(k in v for k in ["espressif", "tuya", "sonoff", "shelly"]):
        icon = "🔌"
        dev_type = "IoT/Smart Plug"
    elif "google" in v:
        icon = "🔊"
        dev_type = "Smart Speaker"
    elif any(k in v for k in ["lg electronics", "samsung", "sony"]):
        icon = "📺"
        dev_type = "TV/Display"
    elif any(k in v for k in ["ubiquiti", "netgear", "tp-link", "routerboard"]):
        icon = "📡"
        dev_type = "Network Gear"
    elif any(k in v for k in ["proxmox", "hewlett packard", "dell", "synology"]):
        icon = "🖥️"
        dev_type = "Server/PC"
    elif any(k in v for k in ["hikvision", "dahua", "reolink", "ezviz"]):
        icon = "📹"
        dev_type = "Camera"
    elif "dreame" in v or "vacuum" in h:
        icon = "🤖"
        dev_type = "Robot Vacuum"
        
    return icon, dev_type

def scan_ports(device):
    ip = device['address']
    
    def is_open(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)  # Fast timeout for local networks
                s.connect((ip, port))
            return True
        except Exception:
            return False

    device['http_open'] = is_open(80)
    device['https_open'] = is_open(443)
    return device


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Devices</title>
    <style>
        :root {
            --bg-color: #f3f4f6;
            --card-bg: #ffffff;
            --text-main: #1f2937;
            --text-muted: #6b7280;
            --accent: #3b82f6;
            --border-color: #e5e7eb;
            --success: #10b981;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
        body { background-color: var(--bg-color); color: var(--text-main); padding: 1rem; }
        
        .header { text-align: center; margin-bottom: 1rem; }
        .header h1 { font-size: 1.5rem; color: var(--text-main); }
        .header p { font-size: 0.9rem; color: var(--text-muted); margin-top: 0.25rem; }
        
        .controls { 
            max-width: 600px; 
            margin: 0 auto 1.5rem auto; 
            display: flex; 
            flex-direction: column; 
            gap: 0.75rem; 
            position: sticky;
            top: 10px;
            z-index: 100;
        }
        
        input[type="text"], select {
            width: 100%;
            padding: 0.75rem 1rem;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            font-size: 1rem;
            background-color: var(--card-bg);
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            outline: none;
        }
        input[type="text"]:focus, select:focus {
            border-color: var(--accent);
        }

        .container { max-width: 600px; margin: 0 auto; display: flex; flex-direction: column; gap: 1rem; }
        
        .device-card {
            background-color: var(--card-bg);
            border-radius: 12px;
            padding: 1rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        
        .card-header { display: flex; justify-content: space-between; align-items: flex-start; }
        .title-block { display: flex; align-items: center; gap: 0.5rem; }
        .icon { font-size: 1.5rem; }
        .name-vendor { display: flex; flex-direction: column; }
        .hostname { font-weight: 600; font-size: 1.1rem; word-break: break-all; }
        .vendor { font-size: 0.75rem; color: var(--text-muted); }
        
        .interface { font-size: 0.75rem; background: var(--bg-color); padding: 0.2rem 0.5rem; border-radius: 6px; color: var(--text-muted); text-transform: uppercase; white-space: nowrap;}
        
        .ip-address { font-family: monospace; font-size: 1.25rem; color: var(--accent); font-weight: 700; margin-top: 0.25rem;}
        
        .details { display: flex; justify-content: space-between; font-size: 0.85rem; color: var(--text-muted); border-top: 1px solid var(--border-color); padding-top: 0.5rem; margin-top: 0.25rem;}
        .mac { font-family: monospace; }
        .time { text-align: right; }
        
        .actions {
            display: flex;
            gap: 0.5rem;
            margin-top: 0.25rem;
        }
        .portal-btn {
            background-color: var(--accent);
            color: white;
            text-decoration: none;
            padding: 0.5rem 0;
            border-radius: 6px;
            font-size: 0.85rem;
            font-weight: 600;
            text-align: center;
            flex: 1;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .portal-btn.https {
            background-color: var(--success);
        }
        
        .hidden { display: none !important; }
    </style>
</head>
<body>

    <div class="header">
        <h1>Network Devices</h1>
        <p id="deviceCount">Loading...</p>
    </div>

    <div class="controls">
        <input type="text" id="searchInput" placeholder="Search IP, MAC, Hostname, or Vendor...">
        <select id="interfaceFilter">
            <option value="all">All Interfaces</option>
            {% for iface in interfaces %}
                <option value="{{ iface }}">{{ iface }}</option>
            {% endfor %}
        </select>
    </div>

    <div class="container" id="deviceContainer">
        {% for device in devices %}
            <div class="device-card" data-interface="{{ device.interface }}" data-search="{{ device.hostname | lower }} {{ device.address }} {{ device.mac | lower }} {{ device.vendor | lower }} {{ device.dev_type | lower }}">
                <div class="card-header">
                    <div class="title-block">
                        <span class="icon">{{ device.icon }}</span>
                        <div class="name-vendor">
                            <span class="hostname">{{ device.hostname }}</span>
                            <span class="vendor">{{ device.vendor }} ({{ device.dev_type }})</span>
                        </div>
                    </div>
                    <span class="interface">{{ device.interface }}</span>
                </div>
                <div class="ip-address">{{ device.address }}</div>
                
                {% if device.http_open or device.https_open %}
                <div class="actions">
                    {% if device.http_open %}
                        <a href="http://{{ device.address }}" target="_blank" rel="noopener noreferrer" class="portal-btn">🌐 Open HTTP</a>
                    {% endif %}
                    {% if device.https_open %}
                        <a href="https://{{ device.address }}" target="_blank" rel="noopener noreferrer" class="portal-btn https">🔒 Open HTTPS</a>
                    {% endif %}
                </div>
                {% endif %}
                
                <div class="details">
                    <span class="mac">{{ device.mac }}</span>
                    <span class="time">Exp: {{ device.timestamp }}</span>
                </div>
            </div>
        {% else %}
            <p style="text-align: center; color: var(--text-muted);">No active leases found.</p>
        {% endfor %}
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const searchInput = document.getElementById('searchInput');
            const interfaceFilter = document.getElementById('interfaceFilter');
            const cards = document.querySelectorAll('.device-card');
            const countDisplay = document.getElementById('deviceCount');

            function filterDevices() {
                const searchTerm = searchInput.value.toLowerCase();
                const selectedInterface = interfaceFilter.value;
                let visibleCount = 0;

                cards.forEach(card => {
                    const searchableText = card.getAttribute('data-search');
                    const cardInterface = card.getAttribute('data-interface');
                    
                    const matchesSearch = searchableText.includes(searchTerm);
                    const matchesInterface = selectedInterface === 'all' || cardInterface === selectedInterface;

                    if (matchesSearch && matchesInterface) {
                        card.classList.remove('hidden');
                        visibleCount++;
                    } else {
                        card.classList.add('hidden');
                    }
                });

                countDisplay.textContent = `Showing ${visibleCount} devices (Newest first)`;
            }

            searchInput.addEventListener('input', filterDevices);
            interfaceFilter.addEventListener('change', filterDevices);
            
            filterDevices();
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    try:
        response = requests.get(
            OPNSENSE_URL,
            auth=HTTPBasicAuth(API_KEY, API_SECRET),
            verify=False,
            timeout=5
        )
        response.raise_for_status()
        data = response.json()
        
        leases = data.get('rows', [])
        active_leases = []
        unique_interfaces = set()

        for lease in leases:
            address = lease.get('address', '')
            
            if address:  
                mac = lease.get('hwaddr', 'Unknown MAC')
                hostname = lease.get('hostname', '')
                interface = lease.get('if_descr', lease.get('if_name', 'LAN'))
                vendor = lease.get('mac_info', '')
                
                if not vendor:
                    vendor = 'Unknown Vendor'
                    
                unique_interfaces.add(interface)
                
                if not hostname or hostname.isspace() or hostname == '*':
                    hostname = 'Unknown Device'
                    
                icon, dev_type = guess_device_info(vendor, hostname)
                
                expire_raw = lease.get('expire', 0)
                try:
                    expire_int = int(expire_raw)
                    if expire_int > 0:
                        dt_object = datetime.fromtimestamp(expire_int)
                        timestamp_str = dt_object.strftime('%b %d, %H:%M:%S')
                    else:
                        timestamp_str = "Unknown"
                        expire_int = 0
                except (ValueError, TypeError):
                    timestamp_str = "Unknown"
                    expire_int = 0
                
                active_leases.append({
                    'address': address,
                    'mac': mac.upper(),
                    'hostname': hostname,
                    'vendor': vendor,
                    'dev_type': dev_type,
                    'icon': icon,
                    'interface': interface,
                    'expire_epoch': expire_int, 
                    'timestamp': timestamp_str
                })

        # Scan ports concurrently using ThreadPoolExecutor for speed
        with ThreadPoolExecutor(max_workers=50) as executor:
            scanned_leases = list(executor.map(scan_ports, active_leases))

        sorted_leases = sorted(scanned_leases, key=lambda x: x['expire_epoch'], reverse=True)
        sorted_interfaces = sorted(list(unique_interfaces))

        return render_template_string(
            HTML_TEMPLATE, 
            devices=sorted_leases, 
            interfaces=sorted_interfaces
        )

    except Exception as e:
        return f"<div style='color:red; font-family:sans-serif; padding:1rem;'><strong>Error parsing OPNsense payload:</strong><br>{str(e)}</div>"



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)