FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY wallet_checker.py .

ENTRYPOINT ["python", "wallet_checker.py"]