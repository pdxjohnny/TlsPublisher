#!/bin/bash
set -e

openssl req \
  -nodes \
  -x509 \
  -newkey rsa:4096 \
  -keyout server.pem \
  -out server.pem \
  -days 365 << EOF
US
Oregon
Portland
TlsPublisher
Examples
localhost
johnandersenpdx@gmail.com
EOF
# SslStream for Authenticate as server needs pkcs12 format
openssl pkcs12 -export -in server.pem -out server.pfx -passout pass:

echo -e "\nDone generating server certificate"
chmod 600 server.pem
