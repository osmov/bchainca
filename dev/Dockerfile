FROM ubuntu:16.04

RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 8AA7AF1F1091A5FD && \
    echo 'deb [arch=amd64] http://repo.sawtooth.me/ubuntu/bumper/stable xenial universe' >> /etc/apt/sources.list && \
    apt-get -q update && \
    apt-get install python3-sawtooth-sdk python3-cbor -q -y

