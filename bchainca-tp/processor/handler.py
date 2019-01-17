import logging

from sawtooth_sdk.processor.exceptions import InvalidTransaction, InternalError
from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.protobuf.processor_pb2 import TpProcessRequest

from processor.ApproveState import ApproveState
from processor.CaPayload import CaPayload
from processor.CaState import CaState

LOGGER = logging.getLogger(__name__)


class CAHandler(TransactionHandler):

    def __init__(self, namespace_prefix):
        self._namespace_prefix = namespace_prefix

    @property
    def family_name(self):
        return 'CA'

    @property
    def namespaces(self):
        return [self._namespace_prefix]

    @property
    def family_versions(self):
        return ['1.0']

    def apply(self, transaction: TpProcessRequest, context):

        header = transaction.header
        signer = header.signer_public_key
        try:
            state = CaState(context=context, namespace=self._namespace_prefix, timeout=2)
            astate = ApproveState(context=context, namespace=self._namespace_prefix, timeout=2)
            # state.check_CA_cert()
            payload = CaPayload(payload=transaction.payload)

            if payload.action == 'init':
                state.init_CA_cert(date=payload.date, nonce=int(header.nonce, 0), spkey=payload.value, signer=signer)
            elif payload.action == 'create':
                astate.add_csr_request(date=payload.date, nonce=int(header.nonce, 0), csr=payload.value, signer=signer)
            elif payload.action == 'list_approve':
                if state.admin == signer:
                    context.add_receipt_data(astate.get_list().encode())
            elif payload.action == 'approve':
                if state.admin == signer:
                    d, n, c = astate.approve(payload.value)

                    cert_bytes = state.create_certificate(date=d, nonce=n, csr=c)
                    event_name = "{}/create".format(self._namespace_prefix)
                    LOGGER.debug("fire event " + event_name)
                    context.add_event(event_name,
                                      {"serial": "{}".format(header.nonce)}.items(),
                                      cert_bytes)
                    LOGGER.debug("event {} fired".format(event_name))

            elif payload.action == 'get':
                cert_bytes = state.get_certificate(payload.serial)
                event_name = "{}/get".format(self._namespace_prefix)
                LOGGER.debug("fire event " + event_name)
                context.add_event(event_name,
                                  {"serial": "{}".format(payload.serial)}.items(),
                                  cert_bytes)
                LOGGER.debug("event {} fired".format(event_name))
            elif payload.action == 'revoke':
                state.revoke_certificate(payload.serial)
                event_name = "{}/revoke".format(self._namespace_prefix)
                LOGGER.debug("fire event " + event_name)
                context.add_event(event_name,
                                  {"serial": "{}".format(payload.serial)}.items())
                LOGGER.debug("event {} fired".format(event_name))
            elif payload.action == 'status':
                status = state.check_status(payload.serial)
                event_name = "{}/status".format(self._namespace_prefix)
                LOGGER.debug("fire event " + event_name)
                context.add_event(event_name,
                                  {"serial": "{}".format(payload.serial)}.items(),
                                  status.encode('utf-8'))
                LOGGER.debug("event {} fired".format(event_name))
            else:
                raise InvalidTransaction("Transaction payload type unknown.")
        except InternalError as er:
            raise InvalidTransaction(str(er)) from er
        except BaseException as ex:
            raise InvalidTransaction(str(ex)) from ex


def _display(msg):
    n = msg.count("\n")

    if n > 0:
        msg = msg.split("\n")
        length = max(len(line) for line in msg)
    else:
        length = len(msg)
        msg = [msg]

    LOGGER.debug("+" + (length + 2) * "-" + "+")
    for line in msg:
        LOGGER.debug("+ " + line.center(length) + " +")
    LOGGER.debug("+" + (length + 2) * "-" + "+")