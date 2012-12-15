#!/bin/sh

echo -e "\n\nThis script is only to be used to generate one off certificates"
echo -e "for dev and testing\n\n"

# Set up the CA environment
mkdir -p ca/newcerts
touch ca/index.txt
touch ca/index.txt.attr
echo 01000000 > ca/serial

# Generate the CA root key and cert
openssl req -config app-signing-openssl.cfg -newkey rsa:2048 -x509 \
    -days 3650 -set_serial 1 \
    -subj "/CN=Examplla Root CA 1/OU=Examplla CA/O=Examplla Corporation/L=Mountain View/ST=CA/C=US" \
    -extensions req-examplla-app-signing-root-ca-1 \
    -out examplla-app-signing-root-ca-1.crt \
    -keyout req-examplla-app-signing-root-ca-1.key

# Generate the signing key and request
openssl req -config app-signing-openssl.cfg -sha256 -newkey rsa:2048 -new \
    -subj "/CN=Examplla Marketplace App Signing 1/OU=Examplla Marketplace App Signing/O=Examplla Corporation/L=Mountain View/ST=CA/C=US" \
    -out examplla-marketplace-app-signing-1.req \
    -keyout examplla-marketplace-app-signing-1.key -nodes

# Sign the signing cert request with the CA key
openssl ca -config app-signing-openssl.cfg \
    -in examplla-marketplace-app-signing-1.req \
    -days 3650 -extensions req-examplla-marketplace-app-signing-1 \
    -out examplla-marketplace-app-signing-1.crt

# Create the "chainfile"
cat examplla-marketplace-app-signing-1.crt \
    examplla-app-signing-root-ca-1.crt \
    > examplla-marketplace-cert-chain.pem
