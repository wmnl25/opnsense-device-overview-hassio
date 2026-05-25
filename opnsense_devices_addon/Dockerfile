FROM python:3.9-slim

# Install jq for parsing Home Assistant config
RUN apt-get update && apt-get install -y jq && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the python script and run script
COPY opnsense-devices.py .
COPY run.sh /run.sh

# Make the run script executable
RUN chmod a+x /run.sh

# Start the HA bridge script
CMD [ "/run.sh" ]