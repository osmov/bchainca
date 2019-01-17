FROM hyperledger/sawtooth-validator:1.1

EXPOSE 4004
EXPOSE 5050
EXPOSE 8800

STOPSIGNAL SIGKILL

ENV PYTHONPATH="/project/sawtooth-core/consensus/poet/common:\
        /project/sawtooth-core/consensus/poet/simulator:\
        /project/sawtooth-core/consensus/poet/core"

WORKDIR /
COPY start.sh /

CMD bash start.sh