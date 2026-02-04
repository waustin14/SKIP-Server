#!/bin/bash

# Default values
KEY_LEN=48
OUTPUT_FILE="psk.txt"
IDENTITY=""

# Function to display usage
usage() {
    echo "Usage: $0 -i <identity> [-l <key_length>] [-f <output_file>]"
    echo ""
    echo "Arguments:"
    echo "  -i  Identity string (Required)"
    echo "  -l  Key length in bytes (Optional, default: 48 bytes / 384 bits)"
    echo "  -f  Output file path (Optional, default: psk.txt)"
    exit 1
}

# Parse command line arguments
while getopts "i:l:f:h" opt; do
    case ${opt} in
        i)
            IDENTITY=$OPTARG
            ;;
        l)
            KEY_LEN=$OPTARG
            ;;
        f)
            OUTPUT_FILE=$OPTARG
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

# Check if Identity is provided
if [ -z "$IDENTITY" ]; then
    echo "Error: Identity argument (-i) is required."
    usage
fi

# Check if openssl is installed
if ! command -v openssl &> /dev/null; then
    echo "Error: openssl is not installed. Please install it to run this script."
    exit 1
fi

# Generate the random key
# openssl rand -hex <num> generates <num> bytes and outputs them as a hex string
HEX_PSK=$(openssl rand -hex "$KEY_LEN")

# Format the output string
OUTPUT_STRING="${IDENTITY}:${HEX_PSK}"

# Write to the specified file
echo "$OUTPUT_STRING" > "$OUTPUT_FILE"

# Confirmation message
echo "Success! PSK generated for identity '$IDENTITY'."
echo "Length: $KEY_LEN bytes"
echo "Output saved to: $OUTPUT_FILE"
