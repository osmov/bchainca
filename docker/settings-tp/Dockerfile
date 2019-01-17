FROM hyperledger/sawtooth-settings-tp:1.1

EXPOSE 4004

STOPSIGNAL SIGKILL

CMD settings-tp -C tcp://${validator}:4004 -v