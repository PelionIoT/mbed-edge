#!/bin/sh

set -ex

echo "1"

device_endpoint_name=${1}
organization_name=${2}

if [ -z "${device_endpoint_name}" ]; then
    echo "Device endpoint name is required"
    exit 1
fi
if [ -z "${organization_name}" ]; then
    echo "Organization name is required"
    exit 1
fi

cert_dir=.

cleanup () {
	rm -rf ${cert_dir}
}

_createRootPrivateKey() {
    openssl ecparam -out ${cert_dir}/CA_private.pem -name prime256v1 -genkey

}
_createRootCA() {
    (echo '[req]'; echo 'distinguished_name=dn'; echo 'prompt=no'; echo '[dn]'; echo 'CN=ROOOOT_CA_3'; echo '[ext]'; echo 'basicConstraints=CA:TRUE'; echo 'keyUsage = digitalSignature, keyCertSign, cRLSign') > ${cert_dir}/ca_config.cnf
    openssl req -key ${cert_dir}/CA_private.pem -new -sha256 -x509 -days 12775 -out ${cert_dir}/CA_cert.pem -config ${cert_dir}/ca_config.cnf -extensions ext
    openssl x509 -in ${cert_dir}/CA_cert.pem -outform der -out ${cert_dir}/CA_cert.der
}

# _createIntermediatePrivateKey() {
#     openssl ecparam -out ${cert_dir}/intermediate_key.pem -name prime256v1 -genkey

# _createIntermediateCA() {
# 	(cat ${cert_dir}/ca_config.cnf; echo 'C=US'; echo 'ST=Washington'; echo 'L=Seattle';echo 'O=AWS';echo "CN=${CN}_intermediate";) > ${cert_dir}/int.cnf
# 	openssl req -new -sha256 -key ${cert_dir}/intermediate_key.pem -out ${cert_dir}/intermediate_csr.pem  -config ${cert_dir}/int.cnf
# 	openssl x509 -sha256 -req -in ${cert_dir}/intermediate_csr.pem -out ${cert_dir}/intermediate_cert.pem -CA ${cert_dir}/root_cert.pem -CAkey ${cert_dir}/root_key.pem -days 7300 -extfile ${cert_dir}/ca_config.cnf -extensions ext -CAcreateserial
# }

_createDevicePrivateKey() {
    openssl ecparam -out ${cert_dir}/LwM2MDevicePrivateKey.pem -name prime256v1 -genkey
    openssl ec -in ${cert_dir}/LwM2MDevicePrivateKey.pem -out ${cert_dir}/LwM2MDevicePrivateKey.der -outform der
}

_createDeviceCertificate() {
    openssl req -key ${cert_dir}/LwM2MDevicePrivateKey.pem -new -sha256 -out ${cert_dir}/LwM2MDeviceCsr.pem -subj "/CN=${device_endpoint_name}/OU=${organization_name}/O=Izuma Networks"
    openssl x509 -req -in ${cert_dir}/LwM2MDeviceCsr.pem -sha256 -out ${cert_dir}/LwM2MDeviceCert.der -outform der -CA ${cert_dir}/CA_cert.pem -CAkey ${cert_dir}/CA_private.pem -CAcreateserial -days 365
    openssl x509 -inform der -in ${cert_dir}/LwM2MDeviceCert.der -out ${cert_dir}/LwM2MDeviceCert.pem
}

generate_self_signed_certs() {
    mkdir -p ${cert_dir}
    _createRootPrivateKey
    _createRootCA
    # _createIntermediatePrivateKey
    # _createIntermediateCA
    _createDevicePrivateKey
    _createDeviceCertificate
}

generate_self_signed_certs