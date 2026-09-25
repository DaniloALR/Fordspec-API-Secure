#!/usr/bin/env sh
# Gera uma CA de DESENVOLVIMENTO e certificados para broker, dispositivo e ingestão.
# Os arquivos vão para infra/certs/ (ignorado pelo git). Em produção use uma PKI
# gerenciada (ex.: AWS IoT / Azure IoT Hub / Vault PKI) com rotação automática.
set -eu
DIR="${1:-infra/certs}"
DIAS=365
mkdir -p "$DIR"
cd "$DIR"

gen() { openssl ecparam -name prime256v1 -genkey -noout -out "$1.key"; chmod 600 "$1.key"; }

# CA
gen ca
openssl req -x509 -new -key ca.key -sha256 -days $DIAS -subj "/O=FordSpec/CN=FordSpec Dev CA" -out ca.crt

# Broker (SAN para docker-compose e localhost)
gen server
openssl req -new -key server.key -subj "/O=FordSpec/CN=mosquitto" -out server.csr
printf "subjectAltName=DNS:mosquitto,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days $DIAS -sha256 -extfile server.ext -out server.crt

# Clientes (CN = identidade usada na ACL)
for cn in ranger-demo-001 ingest-service; do
  gen "$cn"
  openssl req -new -key "$cn.key" -subj "/O=FordSpec/CN=$cn" -out "$cn.csr"
  printf "extendedKeyUsage=clientAuth\n" > client.ext
  openssl x509 -req -in "$cn.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days $DIAS -sha256 -extfile client.ext -out "$cn.crt"
done

# CRL vazia (revogar dispositivo: openssl ca -revoke <cert> e regenerar a CRL)
touch index.txt
printf "[ca]\ndefault_ca=d\n[d]\ndatabase=index.txt\ncrlnumber=crlnumber\ndefault_md=sha256\ndefault_crl_days=30\n" > ca.cnf
echo 01 > crlnumber
openssl ca -config ca.cnf -gencrl -keyfile ca.key -cert ca.crt -out ca.crl

rm -f ./*.csr ./*.ext
echo "Certificados gerados em $DIR"
