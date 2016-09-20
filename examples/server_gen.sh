#!/bin/bash
set -e
openssl req -nodes -x509 -newkey rsa:4096 -keyout server.pem -out server.pem -days 365 < server.pem.info
echo -e "\nDone generating server certificate"
chmod 600 server.pem
