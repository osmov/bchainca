import hashlib
import pickle
import logging
import inspect

LOGGER = logging.getLogger(__name__)


def _serialize(obj):
    return pickle.dumps(obj)


def _deserialize(data):
    return pickle.loads(data)


class State:
    def __init__(self, context, namespace, timeout):
        """Constructor.
        Args:
            context (sawtooth_sdk.processor.context.Context): Access to
                validator state from within the transaction processor.
            timeout (int): Timeout in seconds.
        """

        self._context = context
        self._address_cache = {}
        self._timeout = int(timeout)
        self._namespace = namespace
        t = self._load_entity_state('CA_Admin')
        if t is not None:
            self._admin = t.decode('utf-8')
        else:
            self._admin = ''

    @property
    def admin(self):
        return self._admin

    def set_admin(self, value):
        self._admin = value
        self._save_entity_state('CA_Admin', value.encode('utf-8'))

    def _save_entity_state(self, entity, data):
        LOGGER.debug("[{} Write data: [{}] => {}".format(inspect.stack()[1].function, entity, data))
        address = self._generate_address(entity);
        self._address_cache[address] = data
        self._context.set_state(
            {address: data},
            timeout=self._timeout)

    def _load_entity_state(self, entity):
        address = self._generate_address(entity)
        LOGGER.debug("[{} Read data: [{}] => {}".format(inspect.stack()[1].function, entity, address))
        data = None
        if address in self._address_cache:
            if self._address_cache[address]:
                data = self._address_cache[address]
        else:
            state_entries = self._context.get_state(
                [address],
                timeout=self._timeout)
            if state_entries:
                self._address_cache[address] = state_entries[0].data
                data = state_entries[0].data
            else:
                self._address_cache[address] = None
        return data

    def _generate_address(self, entity):
        try:
            return hashlib.sha512(self._namespace.encode('utf-8')).hexdigest()[:6] + \
                   hashlib.sha512(entity).hexdigest()[:64]
        except TypeError:
            return hashlib.sha512(self._namespace.encode('utf-8')).hexdigest()[:6] + \
                   hashlib.sha512(entity.encode('utf-8')).hexdigest()[:64]