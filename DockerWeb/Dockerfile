FROM python:3.12-slim

# Install system dependencies required by scapy
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5050

CMD ["python", "app.py"]
