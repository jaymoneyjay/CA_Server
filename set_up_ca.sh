#!/bin/bash

ROOT_CA_CONFIG=$1
INTERMEDIATE_CA_CONFIG=$2
ROOT_SECRET=$3
DIR=$PWD

CA_SERVER_CERT_PATH="${PWD}/ca_server.cert.pem"
WEB_SERVER_CERT_PATH="${PWD}/web_server.cert.pem"


echo "### generate API keys"
API_KEY=$(python3 api_key_generator.py -l 10)
API_PASS=$(python3 api_key_generator.py -l 10)

echo "### setup environment"
# delete old keys
sed -i '' '/API_CLIENT_KEY=.*/d' .env
sed -i '' '/API_CLIENT_PASS=.*/d' .env

# write new keys
echo "API_CLIENT_KEY=${API_KEY}" >> .env
echo "API_CLIENT_PASS=${API_PASS}" >> .env


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

echo "### generate root key pair"
openssl genrsa -aes256 -passout pass:$ROOT_SECRET -out private/ca.key.pem 4096
chmod 400 private/ca.key.pem

openssl req -config openssl.cnf \
      -key private/ca.key.pem \
      -new -x509 -days 7300 -sha256 -extensions v3_ca \
      -passin pass:$ROOT_SECRET \
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
openssl genrsa -out intermediate/private/intermediate.key.pem 4096

chmod 400 intermediate/private/intermediate.key.pem

openssl req -config intermediate/openssl.cnf -new -sha256 \
      -key intermediate/private/intermediate.key.pem \
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

echo "### Create certificate chain file"
cat intermediate/certs/intermediate.cert.pem \
      certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem

echo "### Generate CA Server certificate"
# Generate key pair
openssl genrsa -out "${PWD}/ca_server.key.pem" 2048

# Generate certificate request
openssl req -config intermediate/openssl.cnf \
            -key "${PWD}/ca_server.key.pem"\
            -new -sha256 -subj '/CN=ca.imovies.ch/O=iMovies/C=CH/ST=Zurich/L=Zurich' \
            -out "${PWD}/ca_server.csr.pem"

# sign certificate
openssl ca -batch -config intermediate/openssl.cnf \
            -extensions server_cert -days 375 -notext -md sha256 \
            -in "${PWD}/ca_server.csr.pem" \
            -out "${PWD}/ca_server.cert.pem"

echo "### Generate Web Server certificate"
# Generate key pair
openssl genrsa -out "${PWD}/web_server.key.pem" 2048

# Generate certificate request
openssl req -config intermediate/openssl.cnf \
            -key "${PWD}/web_server.key.pem"\
            -new -sha256 -subj '/CN=imovies.ch/O=iMovies/C=CH/ST=Zurich/L=Zurich' \
            -out "${PWD}/web_server.csr.pem"

# sign certificate
openssl ca -batch -config intermediate/openssl.cnf \
            -extensions server_cert -days 375 -notext -md sha256 \
            -in "${PWD}/web_server.csr.pem" \
            -out "${PWD}/web_server.cert.pem"


echo " ### Remove root key from server"
rm -f private/ca.key.pem