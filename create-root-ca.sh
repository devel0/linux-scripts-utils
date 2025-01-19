#!/bin/bash

exdir=$(dirname $(readlink -f "$0"))

if [ "$CERTPARAMS" == "" ]; then
    echo "set CERTPARAMS environment to a file containing cert parameters"
    echo
    echo "following an example:"
    echo
    cat $exdir/cert-parameters-example
    exit 1
fi

set -e # exit if errors

source $CERTPARAMS

rootcadir=~/sscerts

mkdir -p $rootcadir
chmod 700 $rootcadir

ROOT_CA_KEY=$rootcadir/${DOMAIN}_CA.key
ROOT_CA_CRT=$rootcadir/${DOMAIN}_CA.crt

# Create root CA & Private key

openssl req -x509 \
    -sha256 \
    -days $DURATION_DAYS \
    -nodes \
    -newkey rsa:2048 \
    -subj /CN=$DOMAIN/C=$COUNTRY/L=$CITY \
    -keyout $ROOT_CA_KEY \
    -out $ROOT_CA_CRT

echo "Generated $ROOT_CA_CRT"