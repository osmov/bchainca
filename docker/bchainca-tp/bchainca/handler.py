import logging

from sawtooth_sdk.processor.exceptions import InvalidTransaction, InternalError
from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.protobuf.processor_pb2 import TpProcessRequest

from ApproveState import ApproveState
from CaPayload import CaPayload
from CaState import CaState

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
        LOGGER.debug('[apply] init header and signer')
        header = transaction.header
        signer = header.signer_public_key
        try:
            LOGGER.debug('[apply] create CaState, ApproveState, CaPayload')
            state = CaState(context=context, namespace=self._namespace_prefix, timeout=2)
            astate = ApproveState(context=context, namespace=self._namespace_prefix, timeout=2)
            # state.check_CA_cert()
            payload = CaPayload(payload=transaction.payload)

            if payload.action == 'init':
                state.init_CA_cert(date=payload.date,
                                   nonce=int(header.nonce, 0),
                                   spkey=payload.value,
                                   csr=payload.csr,
                                   signer=signer)
            elif payload.action == 'create':
                astate.add_csr_request(date=payload.date, nonce=int(header.nonce, 0), csr=payload.value, signer=signer)
            elif payload.action == 'list_approve':
                if state.admin == signer:
                    t_bytes = astate.get_list().encode()
                    event_name = "{}/list_approve".format(self._namespace_prefix)
                    self._fire_event(context, event_name, {}, t_bytes)
            elif payload.action == 'list_my':
                lc = astate.get_my_certificate(signer).encode()
                event_name = "{}/list_my".format(self._namespace_prefix)
                self._fire_event(context,
                                 event_name,
                                 {"signer": "{}".format(signer)}.items(),
                                 lc)
            elif payload.action == 'approve':
                if state.admin == signer:
                    d, n, c = astate.approve(payload.serial)
                    cert_bytes, cert_serial = state.create_certificate(date=d, nonce=n, csr=c)
                    astate.save_certificate(payload.serial, cert_serial)

            elif payload.action == 'get':
                cert_bytes = state.get_certificate(payload.serial)
                event_name = "{}/get".format(self._namespace_prefix)
                self._fire_event(context,
                                 event_name,
                                 {"serial": "{}".format(payload.serial)}.items(),
                                 cert_bytes)
            elif payload.action == 'revoke':
                state.revoke_certificate(payload.serial)
                event_name = "{}/revoke".format(self._namespace_prefix)
                self._fire_event(context,
                                 event_name,
                                 {"serial": "{}".format(payload.serial)}.items())
            elif payload.action == 'status':
                status = state.check_status(payload.serial)
                event_name = "{}/status".format(self._namespace_prefix)
                self._fire_event(context,
                                 event_name,
                                 {"serial": "{}".format(payload.serial)}.items(),
                                 status.encode('utf-8'))
            else:
                raise InvalidTransaction("Transaction payload type unknown.")
        except InternalError as er:
            raise InvalidTransaction(str(er)) from er
        except BaseException as ex:
            raise InvalidTransaction(str(ex)) from ex

    def _fire_event(self, context, event_name, filters, data=None):
        LOGGER.debug("fire event " + event_name)
        context.add_event(event_name,
                          filters,
                          data)
        LOGGER.debug("event {} fired".format(event_name))

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
