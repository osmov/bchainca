#!/bin/bash

set -xe

while [ ! -f /poet-shared/${validator}/keys/validator.priv ]; do sleep 1; done 

cp -a /poet-shared/${validator}/keys /etc/sawtooth 

poet-engine -v -C tcp://${validator}:5050 --component tcp://${validator}:4004
