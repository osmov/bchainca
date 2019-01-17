import datetime
import logging

from sawtooth_sdk.processor.exceptions import InternalError

from processor.state import *
from processor.certgen import *
from processor.state import _serialize, _deserialize

LOGGER = logging.getLogger(__name__)


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


class CaState(State):
    def __init__(self, context, namespace, timeout):
        """Constructor.
        Args:
            context (sawtooth_sdk.processor.context.Context): Access to
                validator state from within the transaction processor.
            timeout (int): Timeout in seconds.
        """
        State.__init__(self, context, namespace, timeout)

    def init_CA_cert(self, date, nonce: int, spkey, signer):
        cert = self._load_entity_state('CA_Root')
        LOGGER.debug("Input data: [{}] => {}".format('pkey', spkey))
        if cert is None:
            pkey = deserialize_pkey(spkey, b'passw')
            # pkey = create_key_pair();
            csr = create_cert_request(pkey,
                                      C=u'RU',
                                      ST=u'Moscow',
                                      L=u'Moscow',
                                      O=u'CWT',
                                      CN=u'demo CA',
                                      emailAddress=u'admin@cwryptoworkplace.io')
            cert = create_certificate(
                request=csr,
                issuer_cert=csr,
                issuer_key=pkey,
                not_before=date,
                not_after=date + datetime.timedelta(days=10),
                serial=nonce)
            obj = Certificate.from_cert(state='Valid', cert=cert)
            # data = serialize_pkey(pkey, b'passw')
            LOGGER.debug("Write data: [{}] => {}".format('CA_PKey', spkey))
            self._save_entity_state('CA_PKey', spkey)
            data = _serialize(obj)
            LOGGER.debug("Write data: [{}] => {}".format('CA_Root', data))
            self._save_entity_state('CA_Root', data)
            self.set_admin(signer)

    def _load_CA_cert(self):
        data = self._load_entity_state('CA_Root')
        if data is None:
            raise InternalError("CA Root certificate not found. Init first")
        data = _deserialize(data)
        return deserialize_certificate(data.certificate_string)

    def _load_CA_pkey(self):
        data = self._load_entity_state('CA_PKey')
        if data is None:
            raise InternalError("CA keys not found. Init first")
        return deserialize_pkey(data, b'passw')

    def create_certificate(self, date: datetime.datetime, nonce: int, csr: bytes):
        ca_cert = self._load_CA_cert()
        ca_pkey = self._load_CA_pkey()
        cert = create_certificate(
            request=x509.load_pem_x509_csr(csr, default_backend()),
            issuer_cert=ca_cert,
            issuer_key=ca_pkey,
            not_before=date,
            not_after=date + datetime.timedelta(minutes=1),
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
