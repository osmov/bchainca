#!/bin/bash

set -xe

sawadm keygen --force 

mkdir -p /poet-shared/${validator} || true

cp -a /etc/sawtooth/keys /poet-shared/${validator}/ 

sawtooth-validator -v \
    --bind network:tcp://eth0:8800 \
    --bind component:tcp://eth0:4004 \
    --bind consensus:tcp://eth0:5050 \
    --peering dynamic \
    --endpoint tcp://${validator}:8800 \
    --seeds tcp://${validator_seed}:8800 \
    --scheduler parallel \
    --network-auth trust
