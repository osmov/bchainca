import hashlib
import base64
from base64 import b64encode
import time
import random
import requests
import yaml
import zmq

from sawtooth_signing import create_context
from sawtooth_signing import CryptoFactory
from sawtooth_signing import ParseError
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey

from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction
from sawtooth_sdk.protobuf.batch_pb2 import BatchList
from sawtooth_sdk.protobuf.batch_pb2 import BatchHeader
from sawtooth_sdk.protobuf.batch_pb2 import Batch
from sawtooth_sdk.protobuf.client_event_pb2 import ClientEventsSubscribeRequest, ClientEventsSubscribeResponse, \
    ClientEventsUnsubscribeRequest, ClientEventsUnsubscribeResponse
from sawtooth_sdk.protobuf.events_pb2 import EventSubscription, EventList
from sawtooth_sdk.protobuf.validator_pb2 import Message

from sawtooth_xo.xo_exceptions import XoException
import datetime

def _sha512(data):
    return hashlib.sha512(data).hexdigest()


def write_to_file(file_name:str, data: bytes):
    with open(file_name, "wb") as f:
        f.write(data)

class CaClient:
    def __init__(self, base_url, keyfile=None):

        self._base_url = base_url

        if keyfile is None:
            self._signer = None
            return

        try:
            with open(keyfile) as fd:
                private_key_str = fd.read().strip()
        except OSError as err:
            raise XoException(
                'Failed to read private key {}: {}'.format(
                    keyfile, str(err)))

        try:
            private_key = Secp256k1PrivateKey.from_hex(private_key_str)
        except ParseError as e:
            raise XoException(
                'Unable to load private key: {}'.format(str(e)))

        self._signer = CryptoFactory(create_context('secp256k1')) \
            .new_signer(private_key)

    def create(self, csr, wait=None, auth_user=None, auth_password=None):
        return self._send_ca_txn(
            "create",
            value=csr,
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password)

    def list_my(self, wait=None, auth_user=None, auth_password=None):
        return self._send_ca_txn(
            "list_my",
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password)

    def init(self, pkey, csr, wait=None, auth_user=None, auth_password=None):
        splitter = '|'
        return self._send_ca_txn(
            "init",
            value=pkey+splitter+csr,
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password)

    def simple(self, data, wait=None, auth_user=None, auth_password=None):
        return self._send_simple_txn(
            value=data,
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password)

    def get(self, serial: str, wait=None, auth_user=None, auth_password=None):
        return self._send_ca_txn(
            "get",
            value=serial,
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password)

    def status(self, serial: str, wait=None, auth_user=None, auth_password=None):
        return self._send_ca_txn(
            "status",
            value=serial,
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password)

    def revoke(self, serial: str, wait=None, auth_user=None, auth_password=None):
        return self._send_ca_txn(
            "revoke",
            value=serial,
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password)

    def approve(self, signer: str, wait=None, auth_user=None, auth_password=None):
        return self._send_ca_txn(
            "approve",
            value=signer,
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password)

    def list_approve(self, wait=None, auth_user=None, auth_password=None):
        return self._send_ca_txn(
            "list_approve",
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password)

    def _get_status(self, batch_id, wait, auth_user=None, auth_password=None):
        try:
            result = self._send_request(
                'batch_statuses?id={}&wait={}'.format(batch_id, wait),
                auth_user=auth_user,
                auth_password=auth_password)
            return yaml.safe_load(result)['data'][0]['status']
        except BaseException as err:
            raise XoException(err)

    def _get_prefix(self):
        return _sha512('ca_1'.encode('utf-8'))[:6]

    def _get_address(self, name):
        xo_prefix = self._get_prefix()
        game_address = _sha512(name.encode('utf-8'))[:64]
        return xo_prefix + game_address

    def _get_simple_address(self, data):
        prefix = hashlib.sha512('simple'.encode('utf-8')).hexdigest()[:6]
        address = hashlib.sha512(data.encode('utf-8')).hexdigest()[:64]
        return prefix + address

    def _send_request(self,
                      suffix,
                      data=None,
                      content_type=None,
                      name=None,
                      auth_user=None,
                      auth_password=None):
        if self._base_url.startswith("http://"):
            url = "{}/{}".format(self._base_url, suffix)
        else:
            url = "http://{}/{}".format(self._base_url, suffix)

        headers = {}
        if auth_user is not None:
            auth_string = "{}:{}".format(auth_user, auth_password)
            b64_string = b64encode(auth_string.encode()).decode()
            auth_header = 'Basic {}'.format(b64_string)
            headers['Authorization'] = auth_header

        if content_type is not None:
            headers['Content-Type'] = content_type

        try:
            if data is not None:
                result = requests.post(url, headers=headers, data=data)
            else:
                result = requests.get(url, headers=headers)

            if result.status_code == 404:
                raise XoException("No such game: {}".format(name))

            elif not result.ok:
                raise XoException("Error {}: {}".format(
                    result.status_code, result.reason))

        except requests.ConnectionError as err:
            raise XoException(
                'Failed to connect to {}: {}'.format(url, str(err)))

        except BaseException as err:
            raise XoException(err)

        return result.text

    def _send_ca_txn(self,
                     action,
                     value="",
                     wait=None,
                     auth_user=None,
                     auth_password=None):
        # Serialization is just a delimited utf-8 encoded string
        payload = "|".join([action, datetime.datetime.utcnow().isoformat(), str(value)]).encode('utf-8')

        # Construct the address
        address = self._get_prefix()
        header = TransactionHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            family_name="CA",
            family_version="1.0",
            inputs=[address],
            outputs=[address],
            dependencies=[],
            payload_sha512=_sha512(payload),
            batcher_public_key=self._signer.get_public_key().as_hex(),
            nonce=hex(random.randint(0, 2**64))
        ).SerializeToString()

        signature = self._signer.sign(header)

        transaction = Transaction(
            header=header,
            payload=payload,
            header_signature=signature
        )

        batch_list = self._create_batch_list([transaction])
        batch_id = batch_list.batches[0].header_signature

        if wait and wait > 0:
            wait_time = 0
            start_time = time.time()
            response = self._send_request(
                "batches", batch_list.SerializeToString(),
                'application/octet-stream',
                auth_user=auth_user,
                auth_password=auth_password)
            while wait_time < wait:
                status = self._get_status(
                    batch_id,
                    wait - int(wait_time),
                    auth_user=auth_user,
                    auth_password=auth_password)
                wait_time = time.time() - start_time

                if status != 'PENDING':
                    return response

            return response

        return self._send_request(
            "batches", batch_list.SerializeToString(),
            'application/octet-stream',
            auth_user=auth_user,
            auth_password=auth_password)

    def _send_simple_txn(self,
                         value="",
                         wait=None,
                         auth_user=None,
                         auth_password=None):
        # Serialization is just a delimited utf-8 encoded string
        payload = str(value).encode()

        # Construct the address
        address = self._get_simple_address('Simple Data Value 1')

        header = TransactionHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            family_name='SIMPLE',
            family_version="1.0",
            inputs=[address],
            outputs=[address],
            dependencies=[],
            payload_sha512=_sha512(payload),
            batcher_public_key=self._signer.get_public_key().as_hex(),
            nonce=hex(random.randint(0, 2**64))
        ).SerializeToString()

        signature = self._signer.sign(header)

        transaction = Transaction(
            header=header,
            payload=payload,
            header_signature=signature
        )

        batch_list = self._create_batch_list([transaction])
        batch_id = batch_list.batches[0].header_signature

        if wait and wait > 0:
            wait_time = 0
            start_time = time.time()
            response = self._send_request(
                "batches", batch_list.SerializeToString(),
                'application/octet-stream',
                auth_user=auth_user,
                auth_password=auth_password)
            while wait_time < wait:
                status = self._get_status(
                    batch_id,
                    wait - int(wait_time),
                    auth_user=auth_user,
                    auth_password=auth_password)
                wait_time = time.time() - start_time

                if status != 'PENDING':
                    return response

            return response

        return self._send_request(
            "batches", batch_list.SerializeToString(),
            'application/octet-stream',
            auth_user=auth_user,
            auth_password=auth_password)

    def _create_batch_list(self, transactions):
        transaction_signatures = [t.header_signature for t in transactions]

        header = BatchHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            transaction_ids=transaction_signatures
        ).SerializeToString()

        signature = self._signer.sign(header)

        batch = Batch(
            header=header,
            transactions=transactions,
            header_signature=signature)
        return BatchList(batches=[batch])

    def subscribe(self, event_name: str, is_write_to_file=False, file_name='certificate.pem'):
        subscription = EventSubscription(event_type="ca_1/{}".format(event_name))

        # Setup a connection to the validator
        ctx = zmq.Context()
        socket = ctx.socket(zmq.DEALER)
        socket.connect('tcp://127.0.0.1:4004')

        # Construct the request
        request = ClientEventsSubscribeRequest(
            subscriptions=[subscription]).SerializeToString()

        # Construct the message wrapper
        correlation_id = str(random.randrange(10000))   # This must be unique for all in-process requests
        msg = Message(
            correlation_id=correlation_id,
            message_type=Message.CLIENT_EVENTS_SUBSCRIBE_REQUEST,
            content=request)

        # Send the request
        print('subscribe to {} event'.format(event_name))
        socket.send_multipart([msg.SerializeToString()])

        # Receive the response
        resp = socket.recv_multipart()[-1]

        # Parse the message wrapper
        msg = Message()
        msg.ParseFromString(resp)

        # Validate the response type
        if msg.message_type != Message.CLIENT_EVENTS_SUBSCRIBE_RESPONSE:
            print("Unexpected message type")
            return ''

        # Parse the response
        response = ClientEventsSubscribeResponse()
        response.ParseFromString(msg.content)

        # Validate the response status
        if response.status != ClientEventsSubscribeResponse.OK:
            print("Subscription failed: {}".format(response.response_message))
            return ''

        resp = socket.recv_multipart()[-1]

        # Parse the message wrapper
        msg = Message()
        msg.ParseFromString(resp)

        # Validate the response type
        if msg.message_type != Message.CLIENT_EVENTS:
            print("Unexpected message type")
            return ''

        # Parse the response
        events = EventList()
        events.ParseFromString(msg.content)

        for event in events.events:
            print(event)
            if event.data is not None:
                if is_write_to_file:
                    write_to_file(file_name, event.data)
                else:
                    print(event.data)

        # Construct the request
        request = ClientEventsUnsubscribeRequest().SerializeToString()

        # Construct the message wrapper
        correlation_id = str(random.randrange(10000))  # This must be unique for all in-process requests
        msg = Message(
            correlation_id=correlation_id,
            message_type=Message.CLIENT_EVENTS_UNSUBSCRIBE_REQUEST,
            content=request)

        # Send the request
        socket.send_multipart([msg.SerializeToString()])

        # Receive the response
        resp = socket.recv_multipart()[-1]

        # Parse the message wrapper
        msg = Message()
        msg.ParseFromString(resp)

        # Validate the response type
        if msg.message_type != Message.CLIENT_EVENTS_UNSUBSCRIBE_RESPONSE:
            print("Unexpected message type")

        # Parse the response
        response = ClientEventsUnsubscribeResponse()
        response.ParseFromString(msg.content)

        # Validate the response status
        if response.status != ClientEventsUnsubscribeResponse.OK:
            print("Unsubscription failed: {}".format(response.response_message))

        # Close the connection to the validator
        socket.close()

        return file_name

