#!/bin/bash

# Extract config from Home Assistant and export as environment variables
export OPNSENSE_URL=$(jq --raw-output '.opnsense_url' /data/options.json)
export OPNSENSE_API_KEY=$(jq --raw-output '.api_key' /data/options.json)
export OPNSENSE_API_SECRET=$(jq --raw-output '.api_secret' /data/options.json)
export WEBHOOK_URL=$(jq --raw-output '.webhook_url' /data/options.json)

# Change directory so known_devices.json saves to the persistent HA share folder
cd /share

# Start the Python app
echo "Starting OPNsense Scanner..."
python3 /app/opnsense-devices.py