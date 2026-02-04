#!/bin/bash
#
# SKIP Server CA Creation Script
# Creates a Certificate Authority with proper key usage extensions for TLS/mTLS
#
# Requirements met:
#   - basicConstraints: critical, CA:true
#   - keyUsage: critical, digitalSignature, cRLSign, keyCertSign
#   - subjectKeyIdentifier
#   - authorityKeyIdentifier
#
# All configuration is baked into this script - no external config files needed.
#

set -e  # Exit on error

# Configuration - modify these as needed
CA_CN="${CA_CN:-My Lab CA}"
CA_KEY_SIZE="${CA_KEY_SIZE:-4096}"
CA_VALIDITY_DAYS="${CA_VALIDITY_DAYS:-3650}"  # 10 years
OUTPUT_DIR="${1:-./ca_output}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check for OpenSSL
if ! command -v openssl &> /dev/null; then
    print_error "OpenSSL is not installed or not in PATH"
    exit 1
fi

print_info "OpenSSL version: $(openssl version)"

# Create output directory
if [ -d "$OUTPUT_DIR" ]; then
    print_warn "Output directory '$OUTPUT_DIR' already exists"
    read -p "Do you want to overwrite? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Aborted by user"
        exit 0
    fi
    rm -rf "$OUTPUT_DIR"
fi

mkdir -p "$OUTPUT_DIR"
print_info "Created output directory: $OUTPUT_DIR"

# Define file paths
CA_KEY="$OUTPUT_DIR/ca.key"
CA_CERT="$OUTPUT_DIR/ca.pem"

# Generate CA private key
print_info "Generating ${CA_KEY_SIZE}-bit RSA private key..."
openssl genrsa -out "$CA_KEY" "$CA_KEY_SIZE" 2>/dev/null

# Secure the private key
chmod 600 "$CA_KEY"
print_info "Created CA private key: $CA_KEY (permissions: 600)"

# Generate self-signed CA certificate using inline config via process substitution
# Extensions:
#   - basicConstraints: critical, CA:true
#   - keyUsage: critical, digitalSignature, cRLSign, keyCertSign
#   - subjectKeyIdentifier: hash
#   - authorityKeyIdentifier: keyid:always,issuer
print_info "Generating self-signed CA certificate (valid for ${CA_VALIDITY_DAYS} days)..."

openssl req -x509 -new -nodes \
    -key "$CA_KEY" \
    -out "$CA_CERT" \
    -days "$CA_VALIDITY_DAYS" \
    -subj "/CN=${CA_CN}" \
    -addext "subjectKeyIdentifier = hash" \
    -addext "authorityKeyIdentifier = keyid:always,issuer" \
    -addext "basicConstraints = critical, CA:true" \
    -addext "keyUsage = critical, digitalSignature, cRLSign, keyCertSign"

print_info "Created CA certificate: $CA_CERT"

# Display certificate details
echo ""
echo "=============================================="
echo "           CA Certificate Details            "
echo "=============================================="
echo ""
openssl x509 -in "$CA_CERT" -noout -subject -issuer -dates

echo ""
echo "Key Usage Extensions:"
openssl x509 -in "$CA_CERT" -noout -text | grep -A1 "Key Usage" | head -4

echo ""
echo "Basic Constraints:"
openssl x509 -in "$CA_CERT" -noout -text | grep -A1 "Basic Constraints"

# Generate fingerprints
echo ""
echo "Certificate Fingerprints:"
echo "  SHA-256: $(openssl x509 -in "$CA_CERT" -noout -fingerprint -sha256 | cut -d= -f2)"
echo "  SHA-1:   $(openssl x509 -in "$CA_CERT" -noout -fingerprint -sha1 | cut -d= -f2)"

# Copy sign_server_cert.sh to output directory if it exists alongside this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/sign_server_cert.sh" ]; then
    cp "$SCRIPT_DIR/sign_server_cert.sh" "$OUTPUT_DIR/"
    chmod +x "$OUTPUT_DIR/sign_server_cert.sh"
    print_info "Copied sign_server_cert.sh to output directory"
fi

# Summary
echo ""
echo "=============================================="
echo "           CA Creation Complete              "
echo "=============================================="
echo ""
echo "Files created in $OUTPUT_DIR:"
echo "  ca.pem              - CA certificate (distribute this)"
echo "  ca.key              - CA private key (KEEP SECURE!)"
if [ -f "$OUTPUT_DIR/sign_server_cert.sh" ]; then
echo "  sign_server_cert.sh - Helper script to sign certs"
fi
echo ""
echo "To use this CA with SKIP server, copy ca.pem to a 'ca' subfolder in each SKIP server's certs directory:"
echo "  certs/ca/ca.pem"
echo "  certs2/ca/ca.pem"
echo "  ..."
echo ""
echo "Example: Create and sign a server certificate"
echo "  ./sign_server_cert.sh -c $OUTPUT_DIR/ca.pem -k $OUTPUT_DIR/ca.key skip1.cml.lab 'skip1.cml.lab,localhost' '10.89.0.2,127.0.0.1'"
echo ""
