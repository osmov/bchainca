FROM hyperledger/sawtooth-intkey-tp-python

EXPOSE 4004

STOPSIGNAL SIGKILL

CMD intkey-tp-python -C tcp://${validator}:4004 -vvv
