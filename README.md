# OPNsense Mobile-First Network Scanner

A lightweight, lightning-fast web dashboard that connects to your OPNsense router (via the Dnsmasq API) to display active network leases. Designed specifically with a mobile-first approach, this tool makes it incredibly easy to identify recently joined devices, check open web portals, and monitor your homelab or smart home from your phone.

## ✨ Features

* **Mobile-First & Responsive:** Clean UI that scales from a single column on phones to a multi-column grid on desktop monitors. Supports automatic OS-level **Dark Mode**.
* **"First Seen" Tracking:** Remembers when a device first joined the network. Brand new hardware is flagged with a prominent green "NEW" badge for its first 24 hours.
* **Concurrent Port Scanning:** Instantly scans each active lease for common web/management ports (80, 443, 8080, 8443, 8123, 22) and generates clickable quick-access buttons.
* **Smart Icon Mapping:** Automatically reads MAC OUI vendor strings to assign logical emojis and device types (e.g., Apple = 📱, Ubiquiti = 📡, Home Assistant = 🏠).
* **Live Search & Filter:** Filter devices instantly by Interface (VLAN), IP, MAC, Hostname, or Vendor without reloading the page.
* **Webhook Alerts (Optional):** Sends a push notification to Discord/Slack the exact moment a previously unseen MAC address joins your network.
* **Auto-Refresh:** Handy toggle to automatically refresh the dashboard every 30 seconds while you are pairing new IoT devices.

---

## 📋 Prerequisites

1.  **OPNsense Router** using **Dnsmasq** for DHCP.
2.  **API Credentials:** You must generate an API Key and Secret in OPNsense (**System > Access > Users**).
3.  Ensure the user account attached to the API key has the **Services: Dnsmasq DNS: Leases** privilege (or full Admin privileges for a dedicated local service account).

---

## ⚙️ Configuration

This script relies on environment variables. Create a `.env` file in the root directory with the following keys:

```env
# Required
OPNSENSE_URL=https://<YOUR_OPNSENSE_IP>/api/dnsmasq/leases/search
OPNSENSE_API_KEY=your_api_key_here
OPNSENSE_API_SECRET=your_api_secret_here

# Optional: Add a Discord or Slack Webhook URL for "New Device" push alerts
WEBHOOK_URL=https://discord.com/api/webhooks/...
```

> **⚠️ SECURITY WARNING:** Never commit your `.env` file or the `known_devices.json` file to version control. Ensure they are listed in your `.gitignore`.

---

## 🐳 Deployment (Docker / Portainer)

The recommended way to run this long-term is via Docker Compose or a Portainer Stack. 

1. Ensure your `.env`, `requirements.txt`, and `opnsense-devices.py` files are in a dedicated folder on your host machine.
2. Use the following `docker-compose.yml` structure:

```yaml
version: '3.8'

services:
  network-scanner:
    image: python:3.9-slim
    container_name: network-scanner
    working_dir: /app
    # Mount your local folder so the container can read .env and save persistent history
    volumes:
      - /path/to/your/local/folder:/app
    # Install dependencies on startup and run the Flask server
    command: /bin/sh -c "pip install --no-cache-dir -r requirements.txt && python opnsense-devices.py"
    ports:
      - "5001:5001"
    restart: unless-stopped
```
3. Access the dashboard at `http://<your-server-ip>:5001`

*(If using Portainer's GitHub integration, do not map the local volume. Instead, configure the environment variables directly within the Portainer UI to keep them secure, and map a persistent Docker volume to `/app/known_devices.json` if you wish to retain history across container rebuilds).*

---

## 💻 Local Development Run

If you want to run or test the script locally using Python:

1. Clone the repository.
2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```
3. Ensure your `.env` file is properly configured.
4. Run the script:
   ```bash
   python opnsense-devices.py
   ```
5. Open your browser to `http://localhost:5001`.