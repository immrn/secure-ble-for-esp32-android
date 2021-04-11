#!/bin/bash

# Run this script in the directory secure-ble-for-esp32-android

# This script does the following:
#   1. generate all certifactes and their keys in the directory "certs"
#   2. copy bike key, bike cert and CA cert into ${esp_app_dir}/spiffs_image/crypto
#       - spiffs_image will be flashed on the ESP32
#   3. copy TODO certs and keys to android app

# Args:
#    Arg 1: path to the esp directory (esp dir contains the esp-idf dir)
#       - e.g.: if your esp dir is located at /home/USER/esp, then run ./gen_cert_chain /home/USER/esp

esp_app_dir="ble_spp_server" # TODO: adjust dir name
client_dir="ble_spp_client" # TODO: adjust dir name
certs_dir="certs"

# Check arg 1
if test "$1" = ''
then
    echo "missing argument: path to the esp directory"
    exit
fi

# remove last "/" if it exists
esp_path="$1"

if test "${1: -1}" = "/"
then
    esp_path=${1%?}
fi

# If dir $certs_dir doesn't exist, create it
if [ ! -d "$certs_dir" ]
then
    echo "making directory ${certs_dir}"
    mkdir $certs_dir
fi

cd $certs_dir

# Build the mbedtls-program paths
mbedtls_gen_key=${esp_path}/esp-idf/components/mbedtls/mbedtls/programs/pkey/gen_key
mbedtls_cert_write=${esp_path}/esp-idf/components/mbedtls/mbedtls/programs/x509/cert_write

# Generate all certs and keys into $certs_dir:
# 1. CA-Root:
$mbedtls_gen_key type=rsa rsa_keysize=4096 filename=ca.key format=pem
$mbedtls_cert_write selfsign=1 issuer_key=ca.key issuer_name=CN=fb_steigtum_ca,O=tubaf,C=de is_ca=1 max_pathlen=0 output_file=ca.crt
# 2. Backend-Server:
$mbedtls_gen_key type=rsa rsa_keysize=4096 filename=backend_srv.key format=pem
$mbedtls_cert_write issuer_crt=ca.crt subject_key=backend_srv.key subject_name=CN=fb_steigtum_backend_srv,O=tubaf,C=de output_file=backend_srv.crt
# 3. Backend-Subscription:
$mbedtls_gen_key type=rsa rsa_keysize=4096 filename=backend_subscript.key format=pem
$mbedtls_cert_write issuer_crt=ca.crt subject_key=backend_subscript.key subject_name=CN=fb_steigtum_backend_subscript,O=tubaf,C=de output_file=backend_subscript.crt
# 4. App-Client:
$mbedtls_gen_key type=rsa rsa_keysize=4096 filename=app_clt.key format=pem
$mbedtls_cert_write issuer_crt=ca.crt subject_key=app_clt.key subject_name=CN=fb_steigtum_app_clt,O=tubaf,C=de output_file=app_clt.crt
# 5. Fahrrad-µController-Server (optional ein eigenes Zertifikat *pro Fahrrad*):
$mbedtls_gen_key type=rsa rsa_keysize=4096 filename=bike_srv.key format=pem
$mbedtls_cert_write issuer_crt=ca.crt subject_key=bike_srv.key subject_name=CN=fb_steigtum_bike_srv,O=tubaf,C=de output_file=bike_srv.crt

cd ..

#Server
# If directory ${esp_app_dir}/spiffs_image/crypto doesn't exist, create it
if [ ! -d "${esp_app_dir}/spiffs_image/crypto" ]
then
    echo "making directory ${esp_app_dir}/spiffs_image/crypto"
    mkdir ${esp_app_dir}/spiffs_image && mkdir ${esp_app_dir}/spiffs_image/crypto
fi

# Copy bike key,bike cert and CA cert into the esp image dir:
echo "copying following files into ${esp_app_dir}/spiffs_image/crypto:"
echo -e "${certs_dir}/bike_srv.key\n${certs_dir}/bike_srv.crt\n${certs_dir}/ca.crt\n"
cp ${certs_dir}/bike_srv.key ${certs_dir}/bike_srv.crt ${certs_dir}/ca.crt ${esp_app_dir}/spiffs_image/crypto

#Client
# If directory ${client_dir}/spiffs_image/crypto doesn't exist, create it
if [ ! -d "${client_dir}/spiffs_image/crypto" ]
then
    echo "making directory ${client_dir}/spiffs_image/crypto"
    mkdir ${client_dir}/spiffs_image && mkdir ${client_dir}/spiffs_image/crypto
fi

# Copy TODO certs and keys to android app
echo "copying following files into ${client_dir}/spiffs_image/crypto:"
echo -e "${certs_dir}/app_clt.key\n${certs_dir}/app_clt.crt\n${certs_dir}/ca.crt\n${certs_dir}/backend_subscript.crt\n${certs_dir}/backend_subscript.key"
cp ${certs_dir}/app_clt.key ${certs_dir}/app_clt.crt ${certs_dir}/ca.crt ${certs_dir}/backend_subscript.crt ${certs_dir}/backend_subscript.key ${client_dir}/spiffs_image/crypto



exit