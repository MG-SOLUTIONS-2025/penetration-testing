#!/usr/bin/env bash
# Generate self-signed development certificates
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")/../certs" && pwd)"
mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/server.key" ]; then
    echo "Certificates already exist in $CERT_DIR"
    exit 0
fi

echo "Generating self-signed dev certificates..."
openssl req -x509 -nodes -days 365 \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -subj "/CN=localhost/O=PenTest Platform Dev" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/server.crt"

echo "Certificates generated in $CERT_DIR"
