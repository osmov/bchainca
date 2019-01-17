import datetime
import json

from state import State, _serialize, _deserialize


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
        app_list = self._load_entity_state('Approve')
        if app_list is None:
            app_list = {}
        else:
            app_list = _deserialize(app_list)
        app_list.update({signer: ApproveItem(date, nonce, csr, signer)})
        self._save_entity_state('Approve', _serialize(app_list))

    def get_list(self):
        app_list = self._load_entity_state('Approve')
        if app_list is None:
            app_list = '{}'
        else:
            app_list = _deserialize(app_list)
        return json.dumps(app_list, default=lambda o: o.toJSON(), sort_keys=True, indent=4)

    def approve(self, signer):
        app_list = self._load_entity_state('Approve')
        if app_list is None:
            app_list = {}
        else:
            app_list = _deserialize(app_list)

        if signer in app_list:
            d = app_list.pop(signer)
            self._save_entity_state('Approve', _serialize(app_list))
            return d.date, d.nonce, d.csr
