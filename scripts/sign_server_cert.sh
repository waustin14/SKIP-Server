#!/bin/bash
#
# Sign a server certificate with a CA
#
# All configuration is baked in - no external config files needed.
#
# Examples:
#   ./sign_server_cert.sh -c ca.pem -k ca.key skip1.cml.lab "skip1.cml.lab,localhost" "10.89.0.2,127.0.0.1"
#   ./sign_server_cert.sh --ca-cert ca.pem --ca-key ca.key myserver.local
#

set -e

# Default values
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_CERT=""
CA_KEY=""
VALIDITY_DAYS="${VALIDITY_DAYS:-825}"
KEY_SIZE="${KEY_SIZE:-4096}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

usage() {
    cat << EOF
Usage: $0 [OPTIONS] <common_name> [dns_names] [ip_addresses]

Sign a server certificate with a CA. No external config files needed.

Arguments:
  common_name   - Certificate CN (e.g., skip1.cml.lab)
  dns_names     - Comma-separated DNS SANs (default: common_name,localhost)
  ip_addresses  - Comma-separated IP SANs (default: 127.0.0.1)

Options:
  -c, --ca-cert <file>   Path to CA certificate (default: ./ca.pem or \$SCRIPT_DIR/ca.pem)
  -k, --ca-key <file>    Path to CA private key (default: ./ca.key or \$SCRIPT_DIR/ca.key)
  -d, --days <days>      Certificate validity in days (default: 825)
  -s, --key-size <bits>  RSA key size in bits (default: 4096)
  -o, --output-dir <dir> Output directory for generated files (default: current dir)
  -h, --help             Show this help message

Environment variables:
  VALIDITY_DAYS - Certificate validity in days (default: 825)
  KEY_SIZE      - RSA key size in bits (default: 4096)

Examples:
  $0 -c ca.pem -k ca.key skip1.cml.lab
  $0 -c /path/to/ca.pem -k /path/to/ca.key skip1.cml.lab 'skip1.cml.lab,localhost' '10.89.0.2,127.0.0.1'
  $0 --ca-cert ca.pem --ca-key ca.key --days 365 myserver.local

EOF
    exit 1
}

# Parse command line options
OUTPUT_DIR="."
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--ca-cert)
            CA_CERT="$2"
            shift 2
            ;;
        -k|--ca-key)
            CA_KEY="$2"
            shift 2
            ;;
        -d|--days)
            VALIDITY_DAYS="$2"
            shift 2
            ;;
        -s|--key-size)
            KEY_SIZE="$2"
            shift 2
            ;;
        -o|--output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        -*)
            print_error "Unknown option: $1"
            usage
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

# Restore positional arguments
set -- "${POSITIONAL_ARGS[@]}"

# Validate required arguments
if [ $# -lt 1 ]; then
    print_error "Missing required argument: common_name"
    echo ""
    usage
fi

CN="$1"
DNS_NAMES="${2:-${CN},localhost}"
IP_ADDRS="${3:-127.0.0.1}"

# Find CA certificate if not specified
if [ -z "$CA_CERT" ]; then
    if [ -f "./ca.pem" ]; then
        CA_CERT="./ca.pem"
    elif [ -f "$SCRIPT_DIR/ca.pem" ]; then
        CA_CERT="$SCRIPT_DIR/ca.pem"
    else
        print_error "CA certificate not found. Use -c or --ca-cert to specify the path."
        exit 1
    fi
fi

# Find CA key if not specified
if [ -z "$CA_KEY" ]; then
    if [ -f "./ca.key" ]; then
        CA_KEY="./ca.key"
    elif [ -f "$SCRIPT_DIR/ca.key" ]; then
        CA_KEY="$SCRIPT_DIR/ca.key"
    else
        print_error "CA private key not found. Use -k or --ca-key to specify the path."
        exit 1
    fi
fi

# Validate CA files exist
if [ ! -f "$CA_CERT" ]; then
    print_error "CA certificate not found: $CA_CERT"
    exit 1
fi

if [ ! -f "$CA_KEY" ]; then
    print_error "CA private key not found: $CA_KEY"
    exit 1
fi

# Create output directory if needed
mkdir -p "$OUTPUT_DIR"

# Build SAN string
SAN=""
IFS=',' read -ra DNS_ARR <<< "$DNS_NAMES"
for i in "${!DNS_ARR[@]}"; do
    SAN="${SAN}DNS:${DNS_ARR[$i]},"
done
IFS=',' read -ra IP_ARR <<< "$IP_ADDRS"
for i in "${!IP_ARR[@]}"; do
    SAN="${SAN}IP:${IP_ARR[$i]},"
done
SAN="${SAN%,}"  # Remove trailing comma

OUTPUT_KEY="${OUTPUT_DIR}/${CN}_key.pem"
OUTPUT_CERT="${OUTPUT_DIR}/${CN}.pem.crt"

echo "Using CA certificate: $CA_CERT"
echo "Using CA private key: $CA_KEY"
echo ""

echo "Generating ${KEY_SIZE}-bit RSA private key..."
openssl genrsa -out "$OUTPUT_KEY" "$KEY_SIZE" 2>/dev/null
chmod 600 "$OUTPUT_KEY"
print_success "Created private key: $OUTPUT_KEY"

echo ""
echo "Generating certificate for CN=${CN}..."
echo "  SANs: ${SAN}"
echo "  Validity: ${VALIDITY_DAYS} days"

# Generate CSR and sign in one pipeline using inline extensions
openssl req -new -key "$OUTPUT_KEY" -subj "/CN=${CN}" | \
openssl x509 -req \
    -CA "$CA_CERT" \
    -CAkey "$CA_KEY" \
    -CAcreateserial \
    -out "$OUTPUT_CERT" \
    -days "$VALIDITY_DAYS" \
    -copy_extensions none \
    -extfile <(cat <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = ${SAN}
EOF
)

echo ""
print_success "Certificate signed successfully!"
echo ""
echo "Files created:"
echo "  Certificate: $OUTPUT_CERT"
echo "  Private Key: $OUTPUT_KEY"
echo ""
echo "Certificate details:"
openssl x509 -in "$OUTPUT_CERT" -noout -subject -dates
echo ""
echo "Verify with:"
echo "  openssl verify -CAfile '$CA_CERT' '$OUTPUT_CERT'"
