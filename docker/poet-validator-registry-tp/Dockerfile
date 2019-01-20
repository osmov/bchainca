FROM hyperledger/sawtooth-poet-validator-registry-tp:1.1

EXPOSE 4004

ENV PYTHONPATH=/project/sawtooth-core/consensus/poet/common

STOPSIGNAL SIGKILL

CMD poet-validator-registry-tp -vvv -C tcp://${validator}:4004
