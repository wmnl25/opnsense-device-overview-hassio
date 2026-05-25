# Use a lightweight Python base image
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your actual script into the container
COPY app.py .

# Expose the port Flask runs on
EXPOSE 5001

# Command to run the application
CMD ["python", "opnsense-devices.py"]