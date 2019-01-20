import datetime
import json

from state import *
from state import _serialize, _deserialize


class ApproveItem:
    def __init__(self, date, nonce, csr, signer):
        self._date = date
        self._nonce = nonce
        self._csr = csr
        self._signer = signer

    @property
    def date(self):
        return self._date

    @property
    def nonce(self):
        return self._nonce

    @property
    def csr(self):
        return self._csr

    @property
    def signer(self):
        return self._signer

    def toJSON(self):
        return {'date': self._date.strftime("%Y-%m-%d %H:%M:%S"),
                'nonce': self._nonce,
                'signer': self._signer,
                'csr': self._csr.decode('utf-8')}


class ApproveState(State):
    def __init__(self, context, namespace, timeout):
        """Constructor.
        Args:
            context (sawtooth_sdk.processor.context.Context): Access to
                validator state from within the transaction processor.
            timeout (int): Timeout in seconds.
        """
        State.__init__(self, context, namespace, timeout)

    def add_csr_request(self, date: datetime.datetime, nonce: int, csr: bytes, signer):
        LOGGER.debug("[add_csr_request] Input data: [{}] => {}".format('date', date))
        LOGGER.debug("[add_csr_request] Input data: [{}] => {}".format('nonce', nonce))
        LOGGER.debug("[add_csr_request] Input data: [{}] => {}".format('csr', csr))
        app_list = self._load_entity_state('Approve')
        if app_list is None:
            app_list = {}
        else:
            app_list = _deserialize(app_list)
        app_list.update({signer: ApproveItem(date, nonce, csr, signer)})
        self._save_entity_state('Approve', _serialize(app_list))

    def get_list(self):
        LOGGER.debug("[get_list]")
        app_list = self._load_entity_state('Approve')
        if app_list is None:
            app_list = '{}'
        else:
            app_list = _deserialize(app_list)
        return json.dumps(app_list, default=lambda o: o.toJSON(), sort_keys=True, indent=4)

    def approve(self, signer):
        LOGGER.debug("[approve] Input data: [{}] => {}".format('signer', signer))
        app_list = self._load_entity_state('Approve')
        if app_list is None:
            app_list = {}
        else:
            app_list = _deserialize(app_list)

        if signer in app_list:
            d = app_list.pop(signer)
            self._save_entity_state('Approve', _serialize(app_list))
            return d.date, d.nonce, d.csr

    def save_certificate(self, signer, serial):
        LOGGER.debug("[save_certificate] Input data: [{}] => {}".format('signer', signer))
        LOGGER.debug("[save_certificate] Input data: [{}] => {}".format('serial', serial))
        cert_list = self._load_entity_state('Approved')
        if cert_list is None:
            cert_list = {}
        else:
            cert_list = _deserialize(cert_list)
        cert_list.update({signer: serial})
        self._save_entity_state('Approved', _serialize(cert_list))

    def get_my_certificate(self, signer):
        LOGGER.debug("[save_certificate] Input data: [{}] => {}".format('signer', signer))
        cert_list = self._load_entity_state('Approved')
        if cert_list is None:
            cert_list = {}
        else:
            cert_list = _deserialize(cert_list)
        return json.dumps(cert_list, default=lambda o: o.__dict__, sort_keys=True, indent=4)
