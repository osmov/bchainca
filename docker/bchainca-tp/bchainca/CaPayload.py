import datetime
import dateutil.parser

from sawtooth_sdk.processor.exceptions import InvalidTransaction


class CaPayload(object):

    def __init__(self, payload):
        t = payload.decode().split("|")

        action = t[0]

        if action not in ('create','init', 'get', 'list_approve', 'list_my', 'approve', 'revoke', 'status'):
            raise InvalidTransaction('Invalid action: {}'.format(action))

        if action == 'init':
            self._value = t[2].encode('utf-8')
            self._csr = t[3].encode('utf-8')
        elif action == 'create':
            self._value = t[2].encode('utf-8')
        else:
            self._serial = t[2]

        self._action = action
        self._date = dateutil.parser.parse(t[1])

    @property
    def action(self):
        return self._action

    @property
    def value(self):
        return self._value

    @property
    def csr(self):
        return self._csr

    @property
    def date(self):
        return self._date

    @property
    def serial(self):
        return self._serial
