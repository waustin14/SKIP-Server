#!/bin/bash

# Default values
PUB_FILE="kem_pub.key"
PRIV_FILE="kem_priv.key"
ALGORITHM="ML-KEM-1024" # Note: Some older OQS builds might use "kyber1024"

# Function to display usage
usage() {
    echo "Usage: $0 [-p <public_key_file>] [-s <private_key_file>]"
    echo ""
    echo "Arguments:"
    echo "  -p  Output path for Public Key (Optional, default: kem_pub.key)"
    echo "  -s  Output path for Private/Secret Key (Optional, default: kem_priv.key)"
    exit 1
}

# Parse command line arguments
while getopts "p:s:h" opt; do
    case ${opt} in
        p)
            PUB_FILE=$OPTARG
            ;;
        s)
            PRIV_FILE=$OPTARG
            ;;
        h)
            usage
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            usage
            ;;
    esac
done

# Check if openssl is installed
if ! command -v openssl &> /dev/null; then
    echo "Error: openssl is not installed."
    exit 1
fi

# Check if the algorithm is supported by the installed OpenSSL
# We look for the algorithm in the list of supported public key algorithms
if ! openssl list -public-key-algorithms | grep -iq "ML-KEM-1024"; then
    echo "Error: Algorithm '$ALGORITHM' not found in OpenSSL."
    echo "Note: You need OpenSSL with the OQS (Open Quantum Safe) provider enabled."
    echo "If you are using an older OQS build, the algorithm might be named 'kyber1024'."
    exit 1
fi

echo "Generating $ALGORITHM keypair..."

# 1. Generate the Private Key
if openssl genpkey -algorithm "$ALGORITHM" -out "$PRIV_FILE"; then
    echo "Private key generated: $PRIV_FILE"
else
    echo "Error generating private key."
    exit 1
fi

# 2. Secure the Private Key (Read/Write for owner only)
chmod 600 "$PRIV_FILE"

# 3. Derive the Public Key from the Private Key
if openssl pkey -in "$PRIV_FILE" -pubout -out "$PUB_FILE"; then
    echo "Public key generated:  $PUB_FILE"
else
    echo "Error generating public key."
    # Clean up partial file if failed
    rm -f "$PRIV_FILE"
    exit 1
fi

echo ""
echo "Success! ML-KEM-1024 keypair created."
