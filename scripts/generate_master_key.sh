#!/bin/bash

# Generate a 32-byte (256-bit) master key for the keystore
# The key is output as hex-encoded string to stdout

KEY_SIZE=32  # 256-bit key for AES-256-GCM

# Check if openssl is installed
if ! command -v openssl &> /dev/null; then
    echo "Error: openssl is not installed. Please install it to run this script." >&2
    exit 1
fi

# Generate random bytes and output as hex
openssl rand -hex $KEY_SIZE
