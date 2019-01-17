FROM hyperledger/sawtooth-validator:1.1

EXPOSE 4004
EXPOSE 5050
EXPOSE 8800

ENV PYTHONPATH="/project/sawtooth-core/consensus/poet/common:\
        /project/sawtooth-core/consensus/poet/simulator:\
        /project/sawtooth-core/consensus/poet/core"

STOPSIGNAL SIGKILL

WORKDIR /
COPY start.sh /start.sh
