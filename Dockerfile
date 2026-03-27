FROM python:3.13-slim-bookworm

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y iproute2 iputils-ping net-tools grep gcc libssl-dev cmake ninja-build make git && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_USE_OPENSSL=ON \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local && \
    cmake --build /tmp/liboqs/build && \
    cmake --install /tmp/liboqs/build && \
    ldconfig && \
    rm -rf /tmp/liboqs
RUN python3 -m pip install --no-cache-dir --upgrade pip
RUN python3 -m pip install --no-cache-dir -r requirements.txt

COPY src/skip_server.py /app/skip_server.py
COPY src/secure_keystore.py /app/secure_keystore.py
COPY src/secure_keyloader.py /app/secure_keyloader.py
COPY src/pem_utils.py /app/pem_utils.py

EXPOSE 443/tcp 8443/tcp

CMD ["python3", "/app/skip_server.py", "--host", "0.0.0.0", "--config", "/data/appdata/config/skip.yaml"]
