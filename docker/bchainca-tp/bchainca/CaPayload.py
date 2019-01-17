import datetime
import dateutil.parser

from sawtooth_sdk.processor.exceptions import InvalidTransaction


class CaPayload(object):

    def __init__(self, payload):
        action, date, _ = payload.decode().split("|")

        if action not in ('create','init', 'get', 'list_approve', 'approve', 'revoke', 'status'):
            raise InvalidTransaction('Invalid action: {}'.format(action))

        if action in ('create', 'init'):
            self._value = _.encode('utf-8')
        else:
            self._serial = _

        self._action = action
        self._date = dateutil.parser.parse(date)

    @property
    def action(self):
        return self._action

    @property
    def value(self):
        return self._value

    @property
    def date(self):
        return self._date

    @property
    def serial(self):
        return self._serial
