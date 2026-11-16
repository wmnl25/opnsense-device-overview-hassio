# OPNsense Devices Dashboard for Home Assistant

A lightweight, lightning-fast Home Assistant Add-on that connects to your OPNsense router (via the Dnsmasq API) to display active network leases right inside your Home Assistant dashboard via Ingress.

Designed specifically with a mobile-first approach, this tool makes it incredibly easy to identify recently joined devices, check open web portals, and monitor your homelab or smart home directly from the Home Assistant app.

## ✨ Features

* **Home Assistant Ingress:** Seamlessly embeds the dashboard into your HA sidebar. No external ports needed!
* **"First Seen" Tracking:** Remembers when a device first joined the network. Brand new hardware is flagged with a prominent green "NEW" badge for its first 24 hours. (Data persists securely in your HA `/share` folder).
* **Mobile-First & Responsive:** Clean UI that scales from a single column on phones to a multi-column grid on desktop monitors. Supports automatic OS-level **Dark Mode**.
* **Concurrent Port Scanning:** Instantly scans each active lease for common web/management ports (80, 443, 8080, 8443, 8123, 22) and generates clickable quick-access buttons.
* **Smart Icon Mapping:** Automatically reads MAC OUI vendor strings to assign logical emojis and device types (e.g., Apple = 📱, Ubiquiti = 📡, Home Assistant = 🏠).
* **Optional OPNsense MAC Lists:** Enable per-device whitelist and blacklist controls in add-on settings. When enabled, the add-on reuses or creates the `DEVICE_OVERVIEW_BLOCKLIST` and `DEVICE_OVERVIEW_WHITELIST` aliases.
* **Webhook Alerts (Optional):** Sends a push notification to Discord/Slack the exact moment a previously unseen MAC address joins your network.

---

## 📋 Prerequisites

1. **OPNsense Router** using **Dnsmasq** for DHCP.
2. **API Credentials:** You must generate an API Key and Secret in OPNsense (**System > Access > Users**).
3. Ensure the user account attached to the API key has the **Services: Dnsmasq DNS: Leases** privilege. Firewall alias search/add/edit/reconfigure privileges are only required if optional alias management is enabled.
4. When enabled, the add-on creates the MAC aliases on first dashboard load if they do not already exist. Existing aliases must be named `DEVICE_OVERVIEW_BLOCKLIST` and `DEVICE_OVERVIEW_WHITELIST` and have the MAC type.

If OPNsense logs `no active session, user not found` for an alias `setItem` request, verify the API key and secret are still assigned to an enabled user, grant that user the firewall alias edit/reconfigure privileges, then update the add-on credentials and restart it. This is an OPNsense authentication/authorization rejection; the dashboard cannot complete the alias change until OPNsense accepts the write request.

---

## 📥 Installation

### Method 1: Add via Custom Repository (Recommended)
If you have pushed this code to a public GitHub repository, you can add it directly to Home Assistant:
1. In Home Assistant, go to **Settings > Add-ons**.
2. Click the **ADD-ON STORE** button in the bottom right corner.
3. Click the three vertical dots (menu) in the top right corner and select **Repositories**.
4. Paste the URL of your GitHub repository and click **Add**.
5. Close the popup and refresh the page (or click the three dots and hit "Check for updates").
6. Scroll down to find the new repository section and click on **OPNsense Scanner**.
7. Click **Install**.

### Method 2: Install as a Local Add-on
1. Using the Samba Share or Studio Code Server add-on in HA, navigate to your `/addons` directory.
2. Create a new folder named `opnsense-scanner`.
3. Place all the add-on files (`config.yaml`, `Dockerfile`, `run.sh`, `opnsense-devices.py`, `requirements.txt`, and `icon.png`) into this folder.
4. In Home Assistant, go to **Settings > Add-ons > ADD-ON STORE**.
5. Click the three dots in the top right and select **Check for updates**.
6. "OPNsense Scanner" will appear at the top under "Local add-ons". Click it and hit **Install**.

---

## ⚙️ Configuration

Before starting the Add-on, go to the **Configuration** tab in the Home Assistant Add-on UI and set your parameters:

* **`opnsense_url`**: The API endpoint for your router (e.g., `https://192.168.1.1/api/dnsmasq/leases/search`). Be sure to include your custom port if you use one (e.g., `:444`).
* **`api_key`**: Your OPNsense API Key.
* **`api_secret`**: Your OPNsense API Secret.
* **`webhook_url`** *(Optional)*: A Discord or Slack webhook URL to receive push notifications when a new device joins the network.
* **`enable_aliases`** *(Optional, default: `false`)*: Turn on per-device whitelist/blacklist controls and filtering. When disabled, the add-on makes no firewall alias API calls and does not display alias-related controls.

Click **Save**, then go to the **Info** tab. 

Make sure **Show in sidebar** is toggled ON, and click **START**!
