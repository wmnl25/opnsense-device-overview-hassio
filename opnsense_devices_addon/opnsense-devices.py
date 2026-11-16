import os
import json
import re
from urllib.parse import urlsplit
from flask import Flask, render_template_string, request, jsonify, redirect
import requests
from requests.auth import HTTPBasicAuth
import urllib3
from datetime import datetime, timedelta
import socket
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

# Suppress insecure HTTPS warnings if OPNsense uses a self-signed certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables from the .env file
basedir = os.path.abspath(os.path.dirname(__file__))
env_path = os.path.join(basedir, '.env')
load_dotenv(env_path)

app = Flask(__name__)

# --- CONFIGURATION ---
OPNSENSE_URL = os.environ.get("OPNSENSE_URL")
API_KEY = os.environ.get("OPNSENSE_API_KEY")
API_SECRET = os.environ.get("OPNSENSE_API_SECRET")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "") # Optional: Add Discord/Slack webhook to .env
ENABLE_ALIASES = os.environ.get("ENABLE_ALIASES", "false").strip().lower() in ("1", "true", "yes", "on")
KNOWN_DEVICES_FILE = os.path.join(basedir, 'known_devices.json')
DEVICE_ALIASES = {
    'blocklist': 'DEVICE_OVERVIEW_BLOCKLIST',
    'whitelist': 'DEVICE_OVERVIEW_WHITELIST'
}

if not API_KEY or not API_SECRET:
    print("WARNING: API credentials not found in environment variables!")

# --- HELPER FUNCTIONS ---

def load_known_devices():
    if os.path.exists(KNOWN_DEVICES_FILE):
        try:
            with open(KNOWN_DEVICES_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_known_devices(data):
    try:
        with open(KNOWN_DEVICES_FILE, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error saving known devices: {e}")

def opnsense_api_url(path):
    if not OPNSENSE_URL:
        raise RuntimeError("OPNSENSE_URL is not configured")
    parsed_url = urlsplit(OPNSENSE_URL)
    return f"{parsed_url.scheme}://{parsed_url.netloc}/api/{path.lstrip('/')}"

def opnsense_api(method, path, payload=None):
    response = requests.request(
        method,
        opnsense_api_url(path),
        auth=HTTPBasicAuth(API_KEY, API_SECRET),
        json=payload,
        verify=False,
        timeout=15
    )
    if not response.ok:
        details = (response.text or '').strip()
        raise RuntimeError(
            f"OPNsense API {method} {path} returned HTTP {response.status_code}"
            + (f": {details[:800]}" if details else '')
        )
    result = response.json()
    if isinstance(result, dict) and (
        result.get('status') == 'failed'
        or result.get('result') == 'failed'
        or result.get('error')
        or result.get('validations')
    ):
        details = result.get('message') or result.get('error') or result.get('validations')
        raise RuntimeError(str(details or 'OPNsense API request failed'))
    return result

def _alias_payload(api_result):
    if not isinstance(api_result, dict):
        return {}
    alias = api_result.get('alias', api_result)
    return alias if isinstance(alias, dict) else {}

def _alias_members(content):
    if isinstance(content, dict):
        values = [
            key for key, option in content.items()
            if isinstance(option, dict)
            and str(option.get('SELECTED', option.get('selected', '0'))).lower() in ('1', 'true')
        ]
    elif isinstance(content, list):
        values = content
    else:
        values = re.split(r'[\s,;]+', str(content or ''))
    return {
        normalized for value in values
        if (normalized := str(value).strip().upper().replace('-', ':'))
        and re.fullmatch(r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}', normalized)
    }

def _selected_option(value, default):
    if isinstance(value, dict):
        for key, option in value.items():
            if isinstance(option, dict) and str(option.get('SELECTED', option.get('selected', '0'))).lower() in ('1', 'true'):
                return key
        return default
    return value or default

def _get_or_create_alias(name):
    search_result = opnsense_api('POST', 'firewall/alias/searchItem', {
        'current': 1, 'rowCount': 1000, 'sort': {}, 'searchPhrase': ''
    })
    rows = search_result.get('rows', []) if isinstance(search_result, dict) else []
    existing = next((row for row in rows if row.get('name', '').casefold() == name.casefold()), None)

    if existing:
        if existing.get('type', '').casefold() != 'mac':
            raise RuntimeError(f"An OPNsense alias named '{name}' already exists but is not a MAC alias")
        alias_uuid = existing.get('uuid') or existing.get('id')
        if not alias_uuid:
            raise RuntimeError(f"Found alias '{name}' but OPNsense did not return its UUID")
    else:
        created = opnsense_api('POST', 'firewall/alias/addItem', {
            'alias': {
                'enabled': '1',
                'name': name,
                'type': 'mac',
                'content': '',
                'description': 'Managed by OPNsense Devices dashboard'
            }
        })
        alias_uuid = created.get('uuid') if isinstance(created, dict) else None
        if not alias_uuid:
            # Some OPNsense versions omit the UUID on add; check the alias table again.
            follow_up = opnsense_api('POST', 'firewall/alias/searchItem', {
                'current': 1, 'rowCount': 1000, 'sort': {}, 'searchPhrase': ''
            })
            rows = follow_up.get('rows', []) if isinstance(follow_up, dict) else []
            existing = next((row for row in rows if row.get('name', '').casefold() == name.casefold()), None)
            if not existing or existing.get('type', '').casefold() != 'mac':
                raise RuntimeError(f"OPNsense did not return a UUID for newly created alias '{name}'")
            alias_uuid = existing.get('uuid') or existing.get('id')
            if not alias_uuid:
                raise RuntimeError(f"Found alias '{name}' but OPNsense did not return its UUID")
        opnsense_api('POST', 'firewall/alias/reconfigure', {})

    item_result = opnsense_api('GET', f'firewall/alias/getItem/{alias_uuid}')
    item = _alias_payload(item_result)
    if not item:
        item = dict(existing or {})
    return {'uuid': alias_uuid, 'item': item, 'members': _alias_members(item.get('content', ''))}

def load_device_aliases():
    return {key: _get_or_create_alias(name) for key, name in DEVICE_ALIASES.items()}

def update_alias_membership(alias_key, mac, should_contain):
    if not ENABLE_ALIASES:
        raise RuntimeError('OPNsense alias management is disabled in add-on settings')
    if alias_key not in DEVICE_ALIASES:
        raise ValueError('Unknown device list')
    normalized_mac = mac.upper().replace('-', ':')
    if not re.fullmatch(r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}', normalized_mac):
        raise ValueError('Invalid MAC address')

    alias = _get_or_create_alias(DEVICE_ALIASES[alias_key])
    members = alias['members']
    if should_contain:
        members.add(normalized_mac)
    else:
        members.discard(normalized_mac)

    fetched_item = alias['item']
    content = '\n'.join(sorted(members))
    # Submit only editable model fields; getItem may include server-side metadata
    # that is not accepted by setItem on some OPNsense versions.
    alias_payload = {
        'enabled': fetched_item.get('enabled', '1'),
        'name': fetched_item.get('name', DEVICE_ALIASES[alias_key]),
        'type': _selected_option(fetched_item.get('type'), 'mac'),
        'content': content,
        'description': fetched_item.get('description', 'Managed by OPNsense Devices dashboard')
    }
    opnsense_api('POST', f"firewall/alias/setItem/{alias['uuid']}", {'alias': alias_payload})
    opnsense_api('POST', 'firewall/alias/reconfigure', {})
    return normalized_mac

def send_webhook_alert(device_info):
    if not WEBHOOK_URL:
        return
    
    # Broken into multiple lines to prevent text-editor wrap errors
    msg = (
        f"🚀 **New Device Joined!**\n"
        f"**Hostname:** {device_info['hostname']}\n"
        f"**IP:** {device_info['address']}\n"
        f"**MAC:** {device_info['mac']}\n"
        f"**Vendor:** {device_info['vendor']}\n"
        f"**Type:** {device_info['icon']} {device_info['dev_type']}"
    )
    
    payload = {"content": msg}
    
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=2)
    except Exception as e:
        print(f"Webhook error: {e}")

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
    # Check 80, 443, 8080, 8443, 8123 (Home Assistant), 22 (SSH)
    ports_to_scan = [80, 443, 8080, 8443, 8123, 22]
    open_ports = []
    
    def is_open(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                s.connect((ip, port))
            return True
        except Exception:
            return False

    for port in ports_to_scan:
        if is_open(port):
            open_ports.append(port)
            
    device['open_ports'] = open_ports
    return device

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en" data-theme="light">
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
            --warning: #f59e0b;
            --blocklist-bg: #ffe4e6;
            --whitelist-bg: #dcfce7;
            --card-header-bg: #e9eef5;
        }
        
        /* Dark mode support */
        @media (prefers-color-scheme: dark) {
            :root {
                --bg-color: #111827;
                --card-bg: #1f2937;
                --text-main: #f9fafb;
                --text-muted: #9ca3af;
                --accent: #60a5fa;
                --border-color: #374151;
                --blocklist-bg: #4a252c;
                --whitelist-bg: #1e4532;
                --card-header-bg: #273548;
            }
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
        body { background-color: var(--bg-color); color: var(--text-main); padding: 1rem; transition: background-color 0.3s, color 0.3s; }
        
        .header { text-align: center; margin-bottom: 1rem; position: relative; max-width: 1400px; margin-left: auto; margin-right: auto;}
        .header h1 { font-size: 1.5rem; color: var(--text-main); }
        .header p { font-size: 0.9rem; color: var(--text-muted); margin-top: 0.25rem; }
        
        .refresh-toggle {
            position: absolute;
            right: 0;
            top: 0;
            font-size: 0.8rem;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 0.3rem 0.6rem;
            border-radius: 6px;
            cursor: pointer;
        }
        .refresh-toggle.active {
            background: var(--success);
            color: white;
            border-color: var(--success);
        }
        
        /* Desktop-aware controls */
        .controls { 
            max-width: 1400px; 
            margin: 0 auto 1.5rem auto; 
            display: flex; 
            flex-direction: column; 
            gap: 0.75rem; 
            position: sticky;
            top: 10px;
            z-index: 100;
        }
        @media (min-width: 768px) {
            .controls { flex-direction: row; }
            #searchInput { flex: 2; }
            #interfaceFilter, #listFilter { flex: 1; }
        }
        
        input[type="text"], select {
            width: 100%;
            padding: 0.75rem 1rem;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            font-size: 1rem;
            background-color: var(--card-bg);
            color: var(--text-main);
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
            outline: none;
        }
        input[type="text"]:focus, select:focus {
            border-color: var(--accent);
        }

        /* Responsive CSS Grid Container */
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            display: grid; 
            grid-template-columns: 1fr; /* Mobile first: 1 column */
            gap: 1rem; 
        }
        @media (min-width: 768px) {
            .container { grid-template-columns: repeat(2, 1fr); } /* Tablets: 2 columns */
        }
        @media (min-width: 1024px) {
            .container { grid-template-columns: repeat(3, 1fr); } /* Desktops: 3 columns */
        }
        @media (min-width: 1440px) {
            .container { grid-template-columns: repeat(3, 1fr); } /* Ultra-wide: 4 columns */
        }
        
        .device-card {
            background-color: var(--card-bg);
            border-radius: 12px;
            padding: 1rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            position: relative;
            overflow: hidden;
            height: 100%; /* Ensures cards stretch evenly in the grid */
        }
        .device-card.is-blocklisted { background-color: var(--blocklist-bg); }
        .device-card.is-whitelisted:not(.is-blocklisted) { background-color: var(--whitelist-bg); }
        .device-card.is-blocklisted.is-whitelisted {
            background: linear-gradient(120deg, var(--blocklist-bg) 0 50%, var(--whitelist-bg) 50% 100%);
        }
        .device-card.is-new { padding-bottom: 2.25rem; }
        .device-card.is-new .badge-new { position: absolute; left: 1rem; bottom: 0.65rem; }
        
        /* New device highlight */
        .device-card.is-new::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 4px;
            background-color: var(--success);
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            width: calc(100% + 2rem);
            margin: -1rem -1rem 0;
            padding: 0.8rem 1rem;
            background-color: var(--card-header-bg);
            border-bottom: 1px solid var(--border-color);
        }
        .title-block { display: flex; align-items: center; gap: 0.5rem; min-width: 0; flex: 1; }
        .header-side { display: flex; flex-direction: column; align-items: flex-end; gap: 0.4rem; flex-shrink: 0; margin-left: 0.5rem; }
        .icon { font-size: 1.5rem; }
        .name-vendor { display: flex; flex-direction: column; }
        .hostname { font-weight: 600; font-size: 1.1rem; word-break: break-all; display: flex; align-items: center; gap: 0.5rem;}
        .vendor { font-size: 0.75rem; color: var(--text-muted); }
        
        .badge-new {
            background-color: var(--success);
            color: white;
            font-size: 0.6rem;
            padding: 0.1rem 0.4rem;
            border-radius: 4px;
            text-transform: uppercase;
            font-weight: bold;
        }
        
        .interface { font-size: 0.75rem; background: var(--bg-color); padding: 0.2rem 0.5rem; border-radius: 6px; color: var(--text-muted); text-transform: uppercase; white-space: nowrap;}
        
        .ip-address { font-family: monospace; font-size: 1.25rem; color: var(--accent); font-weight: 700; margin-top: 0.25rem;}
        
        .details { display: flex; justify-content: space-between; font-size: 0.85rem; color: var(--text-muted); border-top: 1px solid var(--border-color); padding-top: 0.5rem; margin-top: auto;}
        .mac { font-family: monospace; }
        .time { text-align: right; display:flex; flex-direction: column; gap: 0.2rem;}
        .first-seen { font-size: 0.7rem; color: var(--warning);}

        .list-controls { display: flex; align-items: center; gap: 0.45rem; }
        .list-toggle { display: inline-flex; align-items: center; justify-content: center; gap: 0.15rem; cursor: pointer; font-size: 0.8rem; }
        .list-toggle input { width: 0.85rem; height: 0.85rem; margin: 0; accent-color: var(--accent); }
        .list-toggle input:disabled { cursor: not-allowed; }
        .list-error { max-width: 1400px; margin: 0 auto 0.75rem; color: #b91c1c; font-size: 0.85rem; }
        .list-status { display: flex; align-items: center; gap: 0.4rem; font-size: 0.7rem; color: var(--text-muted); min-height: 1em; }
        .save-spinner {
            width: 0.85rem;
            height: 0.85rem;
            border: 2px solid var(--border-color);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: save-spin 0.7s linear infinite;
        }
        .save-spinner.hidden { display: none; }
        @keyframes save-spin { to { transform: rotate(360deg); } }
        
        .actions {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.25rem;
        }
        .portal-btn {
            background-color: var(--bg-color);
            color: var(--text-main);
            text-decoration: none;
            padding: 0.4rem 0.6rem;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 600;
            text-align: center;
            flex: 1;
            min-width: 80px;
            border: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.3rem;
            transition: opacity 0.2s;
        }
        .portal-btn:hover { opacity: 0.8; }
        .portal-btn.http { background-color: var(--accent); color: white; border: none;}
        .portal-btn.https { background-color: var(--success); color: white; border: none;}
        
        .hidden { display: none !important; }
        
        #lastUpdated { font-size: 0.75rem; color: var(--text-muted); display: block; margin-top: 0.2rem;}
    </style>
</head>
<body>

    <div class="header">
        <h1>Network Devices</h1>
        <p id="deviceCount">Loading...</p>
        <span id="lastUpdated"></span>
        <button id="autoRefreshBtn" class="refresh-toggle">Auto-Refresh: OFF</button>
    </div>

    <div class="controls">
        <input type="text" id="searchInput" placeholder="Search IP, MAC, Hostname, or Vendor...">
        <select id="interfaceFilter">
            <option value="all">All Interfaces</option>
            {% for iface in interfaces %}
                <option value="{{ iface }}">{{ iface }}</option>
            {% endfor %}
        </select>
        {% if aliases_enabled %}
        <select id="listFilter" aria-label="Filter by whitelist or blacklist">
            <option value="all">All List Statuses</option>
            <option value="whitelist">On whitelist</option>
            <option value="blocklist">On blacklist</option>
        </select>
        {% endif %}
    </div>
    {% if alias_error %}
        <p class="list-error">OPNsense blocklist/whitelist controls unavailable: {{ alias_error }}</p>
    {% endif %}

    <div class="container" id="deviceContainer">
        {% for device in devices %}
            <div class="device-card {% if device.is_new %}is-new{% endif %} {% if aliases_enabled and device.blocklisted %}is-blocklisted{% endif %} {% if aliases_enabled and device.whitelisted %}is-whitelisted{% endif %}" data-mac="{{ device.mac }}" data-interface="{{ device.interface }}" data-search="{{ device.hostname | lower }} {{ device.address }} {{ device.mac | lower }} {{ device.vendor | lower }} {{ device.dev_type | lower }}">
                <div class="card-header">
                    <div class="title-block">
                        <span class="icon">{{ device.icon }}</span>
                        <div class="name-vendor">
                            <span class="hostname">
                                {{ device.hostname }}
                            </span>
                            <span class="vendor">{{ device.vendor }} ({{ device.dev_type }})</span>
                        </div>
                    </div>
                    <div class="header-side">
                        <span class="interface">{{ device.interface }}</span>
                        {% if aliases_enabled %}
                        <span class="list-controls">
                            <label class="list-toggle" title="Add to blocklist" aria-label="Add {{ device.mac }} to blocklist">
                                <input type="checkbox" class="alias-toggle" data-list="blocklist" {% if device.blocklisted %}checked{% endif %} {% if alias_error %}disabled{% endif %}>
                                🚫
                            </label>
                            <label class="list-toggle" title="Add to whitelist" aria-label="Add {{ device.mac }} to whitelist">
                                <input type="checkbox" class="alias-toggle" data-list="whitelist" {% if device.whitelisted %}checked{% endif %} {% if alias_error %}disabled{% endif %}>
                                ✅
                            </label>
                        </span>
                        {% endif %}
                    </div>
                </div>
                <div class="ip-address">{{ device.address }}</div>
                
                {% if device.open_ports %}
                <div class="actions">
                    {% if 80 in device.open_ports %}
                        <a href="http://{{ device.address }}" target="_blank" class="portal-btn http">🌐 :80</a>
                    {% endif %}
                    {% if 443 in device.open_ports %}
                        <a href="https://{{ device.address }}" target="_blank" class="portal-btn https">🔒 :443</a>
                    {% endif %}
                    {% if 8080 in device.open_ports %}
                        <a href="http://{{ device.address }}:8080" target="_blank" class="portal-btn">🌐 :8080</a>
                    {% endif %}
                    {% if 8443 in device.open_ports %}
                        <a href="https://{{ device.address }}:8443" target="_blank" class="portal-btn">🔒 :8443</a>
                    {% endif %}
                    {% if 8123 in device.open_ports %}
                        <a href="http://{{ device.address }}:8123" target="_blank" class="portal-btn">🏠 :8123</a>
                    {% endif %}
                    {% if 22 in device.open_ports %}
                        <a href="ssh://{{ device.address }}" class="portal-btn">🖥️ :22</a>
                    {% endif %}
                </div>
                {% endif %}
                
                <div class="details">
                    <span class="mac">{{ device.mac }}</span>
                    <span class="time">
                        <span>Exp: {{ device.timestamp }}</span>
                        {% if device.first_seen_str %}
                            <span class="first-seen">First seen: {{ device.first_seen_str }}</span>
                        {% endif %}
                    </span>
                </div>
                {% if aliases_enabled %}
                <span class="list-status" aria-live="polite">
                    <span class="save-spinner hidden" aria-hidden="true"></span>
                    <span class="list-status-text"></span>
                </span>
                {% endif %}
                {% if device.is_new %}
                    <span class="badge-new">New</span>
                {% endif %}
            </div>
        {% else %}
            <p style="text-align: center; color: var(--text-muted);">No active leases found.</p>
        {% endfor %}
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const searchInput = document.getElementById('searchInput');
            const interfaceFilter = document.getElementById('interfaceFilter');
            const listFilter = document.getElementById('listFilter');
            const cards = document.querySelectorAll('.device-card');
            const countDisplay = document.getElementById('deviceCount');
            const lastUpdated = document.getElementById('lastUpdated');
            const autoRefreshBtn = document.getElementById('autoRefreshBtn');

            document.querySelectorAll('.alias-toggle').forEach(toggle => {
                toggle.addEventListener('change', () => {
                    const card = toggle.closest('.device-card');
                    const status = card.querySelector('.list-status');
                    const statusText = status.querySelector('.list-status-text');
                    const spinner = status.querySelector('.save-spinner');
                    const requestedState = toggle.checked;
                    toggle.disabled = true;
                    spinner.classList.remove('hidden');
                    statusText.textContent = 'Saving…';
                    // Use a normal page navigation: some proxies reject fetch/XHR under Ingress.
                    const updateUrl = new URL(window.location.href);
                    const dashboardUrl = new URL(window.location.href);
                    for (const key of ['action', 'mac', 'list', 'enabled', 'return']) {
                        dashboardUrl.searchParams.delete(key);
                    }
                    updateUrl.searchParams.set('action', 'device-list');
                    updateUrl.searchParams.set('mac', card.dataset.mac);
                    updateUrl.searchParams.set('list', toggle.dataset.list);
                    updateUrl.searchParams.set('enabled', String(requestedState));
                    updateUrl.searchParams.set('return', dashboardUrl.pathname + dashboardUrl.search + dashboardUrl.hash);
                    window.setTimeout(() => window.location.assign(updateUrl.toString()), 100);
                });
            });
            
            // Set Last Updated Time
            const now = new Date();
            lastUpdated.textContent = 'Updated: ' + now.toLocaleTimeString();

            // Filter logic
            function filterDevices() {
                const searchTerm = searchInput.value.toLowerCase();
                const selectedInterface = interfaceFilter.value;
                const selectedList = listFilter ? listFilter.value : 'all';
                let visibleCount = 0;

                cards.forEach(card => {
                    const searchableText = card.getAttribute('data-search');
                    const cardInterface = card.getAttribute('data-interface');
                    const isBlocklisted = card.classList.contains('is-blocklisted');
                    const isWhitelisted = card.classList.contains('is-whitelisted');
                    
                    const matchesSearch = searchableText.includes(searchTerm);
                    const matchesInterface = selectedInterface === 'all' || cardInterface === selectedInterface;
                    const matchesList = selectedList === 'all'
                        || (selectedList === 'whitelist' && isWhitelisted)
                        || (selectedList === 'blocklist' && isBlocklisted);

                    if (matchesSearch && matchesInterface && matchesList) {
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
            if (listFilter) listFilter.addEventListener('change', filterDevices);
            
            // Initial filter run
            filterDevices();
            
            // Auto Refresh Logic
            let refreshInterval;
            let isAutoRefresh = sessionStorage.getItem('autoRefresh') === 'true';
            
            function toggleAutoRefresh() {
                isAutoRefresh = !isAutoRefresh;
                sessionStorage.setItem('autoRefresh', isAutoRefresh);
                applyAutoRefreshState();
            }
            
            function applyAutoRefreshState() {
                if (isAutoRefresh) {
                    autoRefreshBtn.textContent = 'Auto-Refresh: ON (30s)';
                    autoRefreshBtn.classList.add('active');
                    refreshInterval = setInterval(() => {
                        window.location.reload();
                    }, 30000); // 30 seconds
                } else {
                    autoRefreshBtn.textContent = 'Auto-Refresh: OFF';
                    autoRefreshBtn.classList.remove('active');
                    clearInterval(refreshInterval);
                }
            }
            
            autoRefreshBtn.addEventListener('click', toggleAutoRefresh);
            applyAutoRefreshState(); // Apply on load
        });
    </script>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        return update_device_list_request()
    if request.args.get('action') == 'device-list':
        update_response = update_device_list_request({
            'mac': request.args.get('mac', ''),
            'list': request.args.get('list'),
            'enabled': request.args.get('enabled', '').lower() == 'true'
        })
        if not isinstance(update_response, tuple) or update_response[1] < 400:
            return_path = request.args.get('return', '')
            return_parts = urlsplit(return_path)
            if return_path.startswith('/') and not return_parts.netloc and not return_parts.scheme:
                return redirect(return_path)
            referrer = request.referrer
            if referrer:
                referrer_parts = urlsplit(referrer)
                is_ingress_page = referrer_parts.path.startswith('/api/hassio_ingress/')
                is_same_host = referrer_parts.netloc == request.host
                if referrer_parts.scheme in ('http', 'https') and (is_ingress_page or is_same_host):
                    return redirect(referrer)
        return update_response

    try:
        # Load persistent known devices
        known_devices = load_known_devices()
        new_device_found = False
        current_time = datetime.now()

        if ENABLE_ALIASES:
            try:
                device_aliases = load_device_aliases()
                alias_error = None
            except Exception as alias_exception:
                print(f"Unable to load OPNsense device aliases: {alias_exception}")
                device_aliases = {}
                alias_error = str(alias_exception)
        else:
            device_aliases = {}
            alias_error = None
        
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
                mac = lease.get('hwaddr', 'Unknown MAC').upper().replace('-', ':')
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
                
                # --- NEW DEVICE TRACKING LOGIC ---
                is_new = False
                first_seen_str = ""
                
                if mac not in known_devices:
                    # Brand new device!
                    known_devices[mac] = current_time.isoformat()
                    new_device_found = True
                    is_new = True
                    first_seen_str = "Just now"
                    
                    # Alert payload
                    alert_info = {
                        'hostname': hostname, 'address': address, 'mac': mac, 
                        'vendor': vendor, 'icon': icon, 'dev_type': dev_type
                    }
                    # Fire webhook in background thread to not block page load
                    with ThreadPoolExecutor(max_workers=1) as executor:
                        executor.submit(send_webhook_alert, alert_info)
                        
                else:
                    # Seen before, check how old it is
                    try:
                        first_seen_dt = datetime.fromisoformat(known_devices[mac])
                        # Flag as 'New' in UI if seen within the last 24 hours
                        if current_time - first_seen_dt < timedelta(hours=24):
                            is_new = True
                            
                        # Format the first seen date for the UI
                        first_seen_str = first_seen_dt.strftime('%b %d, %H:%M')
                    except ValueError:
                        first_seen_str = "Unknown"
                # ---------------------------------
                
                active_leases.append({
                    'address': address,
                    'mac': mac,
                    'hostname': hostname,
                    'vendor': vendor,
                    'dev_type': dev_type,
                    'icon': icon,
                    'interface': interface,
                    'expire_epoch': expire_int, 
                    'timestamp': timestamp_str,
                    'is_new': is_new,
                    'first_seen_str': first_seen_str,
                    'blocklisted': mac in device_aliases.get('blocklist', {}).get('members', set()),
                    'whitelisted': mac in device_aliases.get('whitelist', {}).get('members', set())
                })

        # Save state if we found new devices
        if new_device_found:
            save_known_devices(known_devices)

        # Scan ports concurrently using ThreadPoolExecutor for speed
        with ThreadPoolExecutor(max_workers=50) as executor:
            scanned_leases = list(executor.map(scan_ports, active_leases))

        # Sort: True 'New' devices (first seen < 24h) first, then by expiration
        sorted_leases = sorted(scanned_leases, key=lambda x: (x['is_new'], x['expire_epoch']), reverse=True)
        sorted_interfaces = sorted(list(unique_interfaces))

        return render_template_string(
            HTML_TEMPLATE, 
            devices=sorted_leases, 
            interfaces=sorted_interfaces,
            alias_error=alias_error,
            aliases_enabled=ENABLE_ALIASES
        )

    except Exception as e:
        return f"<div style='color:red; font-family:sans-serif; padding:1rem;'><strong>Error parsing OPNsense payload:</strong><br>{str(e)}</div>"

def update_device_list_request(payload=None):
    if not ENABLE_ALIASES:
        return jsonify({'error': 'OPNsense alias management is disabled in add-on settings'}), 403
    payload = payload if payload is not None else (request.get_json(silent=True) or {})
    try:
        update_alias_membership(payload.get('list'), payload.get('mac', ''), payload.get('enabled') is True)
        response = jsonify({'success': True})
        response.headers['Cache-Control'] = 'no-store'
        return response
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        print(f"Unable to update OPNsense device alias: {e}")
        return jsonify({'error': str(e)}), 502

@app.route('/api/device-list', methods=['POST'])
def device_list_membership():
    return update_device_list_request()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
