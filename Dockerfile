# ── Build stage ──────────────────────────────────────────────────────────────
FROM python:3.13-slim-bookworm AS builder

# Build-only dependencies (not copied to runtime image)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev libssl-dev cmake ninja-build make git \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs shared library
RUN git clone --depth 1 --branch 0.14.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_USE_OPENSSL=ON \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local && \
    cmake --build /tmp/liboqs/build && \
    cmake --install /tmp/liboqs/build && \
    rm -rf /tmp/liboqs

# Install Python dependencies (liboqs-python compiles against the liboqs headers above)
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache-dir --upgrade pip && \
    python3 -m pip install --no-cache-dir -r /tmp/requirements.txt


# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.13-slim-bookworm

WORKDIR /app

# Runtime tools for network diagnostics — no build toolchain
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iputils-ping net-tools grep \
    && rm -rf /var/lib/apt/lists/*

# Copy liboqs shared library only (no headers or cmake files)
COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/
RUN ldconfig

# Copy pip-installed packages and entry-point scripts (e.g. uvicorn)
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY src/skip_server.py /app/skip_server.py
COPY src/secure_keystore.py /app/secure_keystore.py
COPY src/secure_keyloader.py /app/secure_keyloader.py
COPY src/pem_utils.py /app/pem_utils.py

EXPOSE 443/tcp 8443/tcp

ENV PYTHONUNBUFFERED=1

CMD ["python3", "/app/skip_server.py", "--host", "0.0.0.0", "--config", "/data/appdata/config/skip.yaml"]
