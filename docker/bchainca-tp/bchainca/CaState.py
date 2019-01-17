import datetime
import hashlib
import pickle
import logging

from sawtooth_sdk.processor.exceptions import InternalError
from certgen import *

LOGGER = logging.getLogger(__name__)

def _serialize(obj):
    return pickle.dumps(obj)


def _deserialize(data):
    return pickle.loads(data)


class Certificate:
    def __init__(self,
                 state,
                 valid_till_timestamp,
                 revoke_timestamp,
                 serial_number,
                 certificate_string,
                 subject_name):
        """Constructor.
        Args:
            state (str): Certificate state. 'Valid' or 'Revoked'.
            valid_till_timestamp (int): Certificate valid till timestamp.
            revoke_timestamp (int): Certificate revoke timestamp.
            serial_number (str): Certificate serial number.
            certificate_string (str): Certificate string representation.
            subject_name (str): Certificate subject name.
        """

        self._state = state
        self._valid_till_timestamp = valid_till_timestamp
        self._revoke_timestamp = revoke_timestamp
        self._serial_number = serial_number
        self._certificate_string = certificate_string
        self._subject_name = subject_name

    @classmethod
    def from_cert(cls, state, cert):
        return cls(state=state,
                   valid_till_timestamp=cert.not_valid_after.timestamp(),
                   revoke_timestamp=0,
                   serial_number=cert.serial_number,
                   certificate_string=serialize_certificate(cert),
                   subject_name=cert.subject)

    @property
    def state(self):
        """Certificate state.
        :return: str, 'Valid' or 'Revoked'.
        """
        return self._state

    @property
    def valid_till_timestamp(self):
        """Certificate valid till timestamp.
        :return: int, timestamp.
        """
        return self._valid_till_timestamp

    @property
    def revoke_timestamp(self):
        """Certificate revoke timestamp.
        :return: int, timestamp.
        """
        return self._revoke_timestamp

    @property
    def serial_number(self):
        """Certificate serial number.
        :return: str, serial number.
        """
        return self._serial_number

    @property
    def certificate_string(self):
        """Certificate string representation.
        :return: str, Certificate string representation.
        """
        return self._certificate_string

    @property
    def subject_name(self):
        """Certificate subject name.
        :return: str, Certificate subject name.
        """
        return self._subject_name

    def revoke(self):
        self._state = 'Revoked'


class CaState:
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

    def _generate_address(self, entity):
        try:
            return hashlib.sha512(self._namespace.encode('utf-8')).hexdigest()[:6] + \
                   hashlib.sha512(entity).hexdigest()[:64]
        except TypeError:
            return hashlib.sha512(self._namespace.encode('utf-8')).hexdigest()[:6] + \
                   hashlib.sha512(entity.encode('utf-8')).hexdigest()[:64]

    def init_CA_cert(self, date, nonce: int, spkey):
        cert = self._load_entity_state('CA_Root')
        LOGGER.debug("Input data: [{}] => {}".format('pkey', spkey))
        if cert is None:
            pkey = deserialize_pkey(spkey, b'passw')
            # pkey = create_key_pair();
            csr = create_cert_request(pkey,
                                      C=u'RU',
                                      ST=u'Innopolis',
                                      L=u'Innopolis',
                                      O=u'SNE',
                                      CN=u'demo CA',
                                      emailAddress=u'test@test.xxx')
            cert = create_certificate(
                request=csr,
                issuer_cert=csr,
                issuer_key=pkey,
                not_before=date,
                not_after=date + datetime.timedelta(days=10),
                serial=nonce)
            # data = serialize_pkey(pkey, b'passw')
            LOGGER.debug("Write data: [{}] => {}".format('CA_PKey', spkey))
            self._save_entity_state('CA_PKey', spkey)
            data = serialize_certificate(cert)
            LOGGER.debug("Write data: [{}] => {}".format('CA_Root', data))
            self._save_entity_state('CA_Root', data)

    def _load_CA_cert(self):
        data = self._load_entity_state('CA_Root')
        if data is None:
            raise InternalError("CA Root certificate not found. Init first")
        return deserialize_certificate(data)

    def _load_CA_pkey(self):
        data = self._load_entity_state('CA_PKey')
        if data is None:
            raise InternalError("CA keys not found. Init first")
        return deserialize_pkey(data, b'passw')

    def _save_entity_state(self, entity, data):
        address = self._generate_address(entity);
        self._address_cache[address] = data
        self._context.set_state(
            {address: data},
            timeout=self._timeout)

    def _load_entity_state(self, entity):
        address = self._generate_address(entity);
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

    def create_certificate(self, date: datetime.datetime, nonce: int, csr: bytes):
        ca_cert = self._load_CA_cert()
        ca_pkey = self._load_CA_pkey()
        cert = create_certificate(
            request=x509.load_pem_x509_csr(csr, default_backend()),
            issuer_cert=ca_cert,
            issuer_key=ca_pkey,
            not_before=date,
            not_after=date + datetime.timedelta(minutes=10),
            serial=nonce)
        obj = Certificate.from_cert(state='Valid', cert=cert)
        # self._save_entity_state(entity=cert.fingerprint(hashes.SHA256()),
        #                         data=_serialize(obj))
        self._save_entity_state(entity=str(cert.serial_number),
                                data=_serialize(obj))
        return obj.certificate_string

    def get_certificate(self, serial: str):
        obj = _deserialize(self._load_entity_state(entity=serial))
        return obj.certificate_string

    def revoke_certificate(self, serial: str):
        obj = _deserialize(self._load_entity_state(entity=serial))
        obj.revoke()
        # self._save_entity_state(entity=obj.fingerprint,
        #                         data=_serialize(obj))
        self._save_entity_state(entity=str(obj.serial_number),
                                data=_serialize(obj))

    def check_status(self, serial: str):
        obj = _deserialize(self._load_entity_state(entity=serial))
        return obj.state
