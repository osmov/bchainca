#!/bin/bash

set -xe

sawadm keygen --force

mkdir -p /poet-shared/$validator || true

cp -a /etc/sawtooth/keys /poet-shared/$validator/

while [ ! -f /poet-shared/poet-enclave-measurement ]; do sleep 1; done
while [ ! -f /poet-shared/poet-enclave-basename ]; do sleep 1; done
while [ ! -f /poet-shared/poet.batch ]; do sleep 1; done

cp /poet-shared/poet.batch /

sawset genesis \
    -k /etc/sawtooth/keys/validator.priv \
    -o config-genesis.batch

sawtooth keygen --key-dir /poet-shared/ --force -q superuser

pem=$(cat /poet-shared/simulator_rk_pub.pem)

enc_mes=$(cat /poet-shared/poet-enclave-measurement)

enc_bn=$(cat /poet-shared/poet-enclave-basename)

su_pub_key=$(cat /poet-shared/superuser.pub)

sawset proposal create \
    -k /etc/sawtooth/keys/validator.priv \
    sawtooth.consensus.algorithm=poet \
    sawtooth.poet.report_public_key_pem="$pem"\
    sawtooth.poet.valid_enclave_measurements="$enc_mes" \
    sawtooth.poet.valid_enclave_basenames="$enc_bn" \
    sawtooth.identity.allowed_keys="$su_pub_key" \
    -o config.batch

sawset proposal create \
    -k /etc/sawtooth/keys/validator.priv \
        sawtooth.poet.target_wait_time=5 \
        sawtooth.poet.initial_wait_time=25 \
        sawtooth.publisher.max_batches_per_block=100 \
    -o poet-settings.batch

sawadm genesis \
    config-genesis.batch config.batch poet.batch poet-settings.batch

sawtooth-validator -v \
    --bind network:tcp://eth0:8800 \
    --bind component:tcp://eth0:4004 \
    --bind consensus:tcp://eth0:5050 \
    --peering dynamic \
    --endpoint tcp://$validator:8800 \
    --scheduler parallel \
    --network-auth trust
