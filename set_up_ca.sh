#!/bin/bash

ROOT_CA_CONFIG=$1
INTERMEDIATE_CA_CONFIG=$2
ROOT_SECRET=$3
NO_KEY="no_secret"
DIR=$PWD

SERVER_CERT_PATH="${PWD}/server.cert.pem"

echo "### generate API keys"
API_KEY=$(python3 api_key_generator.py -l 10)
API_AUTH=$(python3 api_key_generator.py -l 10)

echo "### setup environment"
touch .env
echo "# API Client ID:
CA_SERVER_CLIENT_AUTH=${API_AUTH}" >> .env

echo "# API Client key:
CA_SERVER_CLIENT_KEY=${API_KEY}" >> .env

echo "# CA Server Certificate path:
CA_SERVER_CERT_PATH=${SERVER_CERT_PATH}" >> .env


echo "### setup root ca directory"
mkdir root
cd root
mkdir certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial

echo "### set path in root.cnf and dump to openssl.cnf"
touch openssl.cnf
sed "s+#set_current_dir+${DIR}+" "${DIR}/${ROOT_CA_CONFIG}" > openssl.cnf

# TODO: is command line argument visible to other processes?
echo "### generate root key pair"
openssl genrsa -aes256 -passout pass:$ROOT_SECRET -out private/ca.key.pem 4096
chmod 400 private/ca.key.pem

# TODO: adjust path with DIR
openssl req -config openssl.cnf \
      -key private/ca.key.pem \
      -new -x509 -days 7300 -sha256 -extensions v3_ca \
      -passin pass:$ROOT_SECRET \
      -passout pass:$NO_KEY \
      -subj '/CN=Root CA/O=iMovies/C=CH/ST=Zurich/L=Zurich' \
      -out certs/ca.cert.pem

chmod 444 certs/ca.cert.pem

echo "### setup intermediate ca directory"
mkdir intermediate
cd intermediate
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber

cd ..
echo "### set path in intermediate.cnf and dump to openssl.cnf"
touch openssl.cnf
sed "s+#set_current_dir+${DIR}+" "${DIR}/${INTERMEDIATE_CA_CONFIG}" > intermediate/openssl.cnf

echo "### generate intermediate key pair"
openssl genrsa -aes256 \
      -passout pass:$NO_KEY \
      -out intermediate/private/intermediate.key.pem 4096

chmod 400 intermediate/private/intermediate.key.pem

openssl req -config intermediate/openssl.cnf -new -sha256 \
      -key intermediate/private/intermediate.key.pem \
      -passin pass:$NO_KEY \
      -passout pass:$NO_KEY \
      -subj '/CN=Intermediate CA/O=iMovies/C=CH/ST=Zurich/L=Zurich' \
      -out intermediate/csr/intermediate.csr.pem

echo "### sign intermediate certificate"
openssl ca -batch -config openssl.cnf -extensions v3_intermediate_ca \
      -days 3650 -notext -md sha256 \
      -in intermediate/csr/intermediate.csr.pem \
      -passin pass:$ROOT_SECRET \
      -out intermediate/certs/intermediate.cert.pem

chmod 444 intermediate/certs/intermediate.cert.pem

echo "### Verify chain of trust:"
openssl verify -CAfile certs/ca.cert.pem \
      intermediate/certs/intermediate.cert.pem

echo " ### Create certificate chain file"
cat intermediate/certs/intermediate.cert.pem \
      certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem

echo " ### Remove root key from server"
rm -f private/ca.key.pem