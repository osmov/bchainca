import argparse
import csv
import datetime
import hashlib
import json
import logging
import sys
import time
import urllib.request
from _sha512 import sha512
from os import path
from random import uniform, randint
from urllib.error import HTTPError

from sawtooth_sdk.protobuf.batch_pb2 import BatchHeader, Batch, BatchList
from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader, Transaction
from sawtooth_signing import create_context, CryptoFactory

from lib.common import AbstractClient, DEFAULT_MONITORING_FOLDER, init_logger

LOGGER = logging.getLogger(__name__)


def _gen_io_payload():
    start_key_s = uniform(0, 20)
    start_key_w = uniform(0, 20)
    size_s = uniform(20, 50)
    size_w = uniform(20, 50)
    return [
        'write,{},{}'.format(start_key_w, size_w),
        'scan,{},{}'.format(start_key_s, size_s),
    ]


def _gen_kv_payload():
    key = uniform(0, 5000)
    value = uniform(0, 50)

    return [
        'put,{},{}'.format(key, value),
        'get,{},{}'.format(key, value),
    ]


def _gen_sb_payload():
    return [
        json.dumps({
            'action': 'send',
            'owner': 'ivan',
            'recipient': 'raven',
            'amount': str(uniform(0, 500000))
        }),
        json.dumps({
            'action': 'send',
            'owner': 'raven',
            'recipient': 'ivan',
            'amount': str(uniform(0, 500000))
        })
    ]


class SawtoothClient(AbstractClient):

    def __init__(self, publisher_node_url, server_node_url, load, benchmark):
        super().__init__(publisher_node_url, server_node_url, load, benchmark)

        context = create_context('secp256k1')
        private_key = context.new_random_private_key()
        self._signer = CryptoFactory(context).new_signer(private_key)

        self._load_txn = []

        date = datetime.date.today()
        logging_file_name = '{}-{}-benchmark-requests.csv'.format(str(date), benchmark)

        self._tx_state_log_file = path.join(DEFAULT_MONITORING_FOLDER, logging_file_name)

    def generate_load(self):
        init_tx = {
            'small-bank': lambda: json.dumps({
                'action': 'init',
            })
        }

        if self._benchmark in init_tx.keys():
            self._load_txn.append(init_tx[self._benchmark]())

        load_generators = {
            'do-nothing': lambda: ['nothing'],
            'cpu-heavy': lambda: [str(uniform(1, 9999999))],
            'io-heavy': _gen_io_payload,
            'kv-store': _gen_kv_payload,
            'small-bank': _gen_sb_payload,
        }

        while len(self._load_txn) < self._load:
            for tx in load_generators[self._benchmark]():
                self._load_txn.append(tx)

    def start_load(self):

        with open(self._tx_state_log_file, 'w+', newline='') as tx_log:
            writer = csv.writer(tx_log)
            writer.writerow(['time', 'status'])

            for payload in self._load_txn:
                batch_from_payload = self._generate_batch_from_payload(payload)
                status = self._send_transaction_batch(batch_from_payload)

                writer.writerow([
                    time.time(),
                    status
                ])
        LOGGER.debug('Finished the submission of events')

    def _generate_batch_from_payload(self, payload):

        payload_bytes = payload.encode('utf-8')

        prefix = hashlib.sha512(self._benchmark.encode('utf-8')).hexdigest()[0:6]

        txn_header_bytes = TransactionHeader(
            family_version='1.0',
            family_name=self._benchmark,
            inputs=[prefix],
            outputs=[prefix],
            nonce=str(randint(0, 10000000000)),
            signer_public_key=self._signer.get_public_key().as_hex(),
            batcher_public_key=self._signer.get_public_key().as_hex(),
            payload_sha512=sha512(payload_bytes).hexdigest()
        ).SerializeToString()

        signature = self._signer.sign(txn_header_bytes)

        txn = Transaction(
            header=txn_header_bytes,
            header_signature=signature,
            payload=payload_bytes
        )

        batch_header_bytes = BatchHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            transaction_ids=[txn.header_signature],
        ).SerializeToString()

        signature = self._signer.sign(batch_header_bytes)

        batch = Batch(
            header=batch_header_bytes,
            header_signature=signature,
            transactions=[txn]
        )

        return batch

    def _send_transaction_batch(self, batch):
        batch_list_bytes = BatchList(batches=[batch]).SerializeToString()
        try:
            request = urllib.request.Request(
                'http://{}:8008/batches'.format(self._server_node_url),
                batch_list_bytes,
                method='POST',
                headers={'Content-Type': 'application/octet-stream'})
            response = urllib.request.urlopen(request)

            LOGGER.debug('Received a response with status {}'
                         .format(response.status))
            status = response.status
        except HTTPError as e:
            LOGGER.debug('Could not send a request')
            status = e.code
        return status


def parse_args(args):
    parser = argparse.ArgumentParser()

    parser.add_argument('-v', '--verbose',
                        action='count',
                        default=3,
                        help='Increase level of output sent to stderr')

    parser.add_argument('-l', '--load',
                        help='Number of transactions to send',
                        default=4)

    parser.add_argument('-b', '--benchmark',
                        help='Name of the benchmark',
                        required=True)

    parser.add_argument('-p', '--publisher',
                        help='IP or domain of the publisher node',
                        default='localhost')

    parser.add_argument('-s', '--server',
                        help='IP or domain of the rest api of a server',
                        default='localhost')

    return parser.parse_args(args)


def main():
    try:
        opts = parse_args(sys.argv[1:])
        init_logger(opts.verbose)

        load = int(opts.load) or 10
        benchmark = opts.benchmark
        publisher = opts.publisher
        server = opts.server

        client = SawtoothClient(
            publisher_node_url=publisher,
            server_node_url=server,
            load=load,
            benchmark=benchmark
        )

        client.generate_load()

        client.start_load()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == '__main__':
    main()
