FROM python:3.11-slim

WORKDIR /app

# Install system dependencies required to build native packages
RUN apt-get update && apt-get install -y gcc build-essential libffi-dev libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your app
COPY . .

ENTRYPOINT ["python", "wallet_checker.py"]
