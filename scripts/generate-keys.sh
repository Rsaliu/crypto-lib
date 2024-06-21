#! /bin/bash

set -e

PRIVATE_KEY="keys/ec_private_key.pem"

PUBLIC_KEY="keys/ec_public_key.pem"

if [ -e "$PRIVATE_KEY" ] && [ -e "$PUBLIC_KEY"  ]; then
    echo "key files already exist"
else
    echo "generating new key files"
    # Generate ec private key
    openssl ecparam -name prime256v1 -genkey -noout -out "$PRIVATE_KEY" 

    # Generate ec public key private
    openssl ec -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"
fi
