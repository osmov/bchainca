FROM hyperledger/sawtooth-rest-api:1.1

EXPOSE 8008

STOPSIGNAL SIGKILL

CMD bash -c "sawtooth-rest-api -vvv \
    --connect tcp://${validator}:4004 \
    --bind rest-api-${id}:8008"
