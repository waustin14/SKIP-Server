FROM python:3.13-slim-bookworm

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y iproute2 iputils-ping net-tools grep gcc libssl-dev && rm -rf /var/lib/apt/lists/*
RUN python3 -m pip install --no-cache-dir --upgrade pip
RUN python3 -m pip install --no-cache-dir -r requirements.txt

COPY src/skip_server.py /app/skip_server.py
COPY src/secure_keystore.py /app/secure_keystore.py
COPY src/secure_keyloader.py /app/secure_keyloader.py
COPY src/pem_utils.py /app/pem_utils.py

EXPOSE 443/tcp 8443/tcp

CMD ["python3", "/app/skip_server.py", "--host", "0.0.0.0", "--config", "/data/appdata/config/skip.yaml"]
