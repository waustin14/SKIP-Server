#!/bin/bash

# Default values
PUB_FILE="kem_pub.key"
PRIV_FILE="kem_priv.key"

# Candidate algorithm names, in priority order:
#   1. "ML-KEM-1024"  - native OpenSSL 3.5+ naming (FIPS 203 standard name)
#   2. "mlkem1024"    - current oqs-provider naming (liboqs >= 0.14.0-ish, post FIPS-203 rename)
#   3. "kyber1024"    - older oqs-provider naming (pre-rename, OpenSSL 3 provider era)
#   4. "Kyber1024"    - legacy openssl-oqs (OpenSSL 1.1.1 fork) capitalized naming
CANDIDATE_ALGORITHMS=("ML-KEM-1024" "mlkem1024" "kyber1024" "Kyber1024")
ALGORITHM=""

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

# Detect which algorithm name is actually supported by this OpenSSL install.
# We use word-boundary matching (-w) to avoid false-positive matches on
# hybrid variants like "x25519_mlkem1024" or "p521_mlkem1024".
AVAILABLE_ALGS=$(openssl list -public-key-algorithms 2>/dev/null)

for candidate in "${CANDIDATE_ALGORITHMS[@]}"; do
    if echo "$AVAILABLE_ALGS" | grep -iwq "$candidate"; then
        ALGORITHM="$candidate"
        break
    fi
done

if [ -z "$ALGORITHM" ]; then
    echo "Error: No supported ML-KEM-1024 algorithm name found in OpenSSL."
    echo "Note: You need OpenSSL with the OQS (Open Quantum Safe) provider enabled,"
    echo "      or an OpenSSL >= 3.5 build with native ML-KEM support."
    echo ""
    echo "Checked for the following names, none of which were found:"
    for candidate in "${CANDIDATE_ALGORITHMS[@]}"; do
        echo "  - $candidate"
    done
    echo ""
    echo "Run 'openssl list -public-key-algorithms' to see what's actually available."
    exit 1
fi

echo "Detected algorithm name: $ALGORITHM"
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
echo "Success! $ALGORITHM keypair created."
