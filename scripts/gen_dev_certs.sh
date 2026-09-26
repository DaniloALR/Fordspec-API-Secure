#!/usr/bin/env sh
set -eu
DIR="${1:-infra/certs}"
DIAS=365
mkdir -p "$DIR"
cd "$DIR"

gen() { openssl ecparam -name prime256v1 -genkey -noout -out "$1.key"; chmod 600 "$1.key"; }

gen ca
openssl req -x509 -new -key ca.key -sha256 -days $DIAS -subj "/O=FordSpec/CN=FordSpec Dev CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out ca.crt

FOLHA="basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer"

gen server
openssl req -new -key server.key -subj "/O=FordSpec/CN=mosquitto" -out server.csr
printf "%s\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:mosquitto,DNS:localhost,IP:127.0.0.1\n" "$FOLHA" > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days $DIAS -sha256 -extfile server.ext -out server.crt

for cn in ranger-demo-001 ingest-service; do
  gen "$cn"
  openssl req -new -key "$cn.key" -subj "/O=FordSpec/CN=$cn" -out "$cn.csr"
  printf "%s\nextendedKeyUsage=clientAuth\n" "$FOLHA" > client.ext
  openssl x509 -req -in "$cn.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days $DIAS -sha256 -extfile client.ext -out "$cn.crt"
done

touch index.txt
printf "[ca]\ndefault_ca=d\n[d]\ndatabase=index.txt\ncrlnumber=crlnumber\ndefault_md=sha256\ndefault_crl_days=30\n" > ca.cnf
echo 01 > crlnumber
openssl ca -config ca.cnf -gencrl -keyfile ca.key -cert ca.crt -out ca.crl

rm -f ./*.csr ./*.ext
echo "Certificados gerados em $DIR"
