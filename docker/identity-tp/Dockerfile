FROM hyperledger/sawtooth-identity-tp:latest

RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 8AA7AF1F1091A5FD && \
    echo 'deb [arch=amd64] http://repo.sawtooth.me/ubuntu/bumper/stable xenial universe' >> /etc/apt/sources.list && \
    apt-get update

RUN apt-get install -y -q python3-sawtooth-sdk

CMD identity-tp -C tcp://${validator}:4004 -v

EXPOSE 4004

STOPSIGNAL SIGKILL

CMD identity-tp -C tcp://${validator}:4004 -vvv
