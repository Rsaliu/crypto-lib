#!/bin/bash

# C : NG
# ST : LG
# O : BTGKS

set -e

# Generate CA Key
openssl genrsa -out ca.key.pem 2048

# Generate a self-signed CA certificate
openssl req -new -x509 -key ca.key.pem -out ca.cert.pem -days 365 -subj '/CN=BTGKS'

# Generate another key
openssl genrsa -out server.key.pem 2048

# Create a certificate-signing request
openssl req -new -key server.key.pem -out server.csr -config conf/openssl.conf

# Use the root key to sign the site certificate
openssl x509 -req -in server.csr -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial -out server.cert.pem -extensions v3_req -extfile conf/openssl.conf -days 365

# Generate another key
openssl genrsa -out default_client.key 2048

# Create a certificate-signing request
openssl req -new -key default_client.key -out default_client.csr -subj '/CN=SigIO'

# Use the root key to sign the site certificate
openssl x509 -req -in default_client.csr -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial -out default_client.cert -days 365
# Clean up the CSR, we don't need it anymore
rm -rf server.csr
rm -rf ca.cert.srl
