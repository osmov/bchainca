"""
Certificate generation module.
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


def create_key_pair(key_size=2048):
    """
    Create a public/private key pair.
    Arguments: type - Key type, must be one of TYPE_RSA and TYPE_DSA
               bits - Number of bits to use in the key
    Returns:   The public/private key pair in a PKey object
    """

    pkey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return pkey


def create_cert_request(pkey, **name):
    """
    Create a certificate request.
    Arguments: pkey   - The key to associate with the request
               **name - The name of the subject of the request, possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
    Returns:   The certificate request in an X509Req object
    """

    csr = x509.CertificateSigningRequestBuilder()\
        .subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, name['C'] if 'C' in name else 'N/A'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, name['ST'] if 'ST' in name else 'N/A'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, name['L'] if 'L' in name else 'N/A'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, name['O'] if 'O' in name else 'N/A'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, name['OU'] if 'OU' in name else 'N/A'),
            x509.NameAttribute(NameOID.COMMON_NAME, name['CN'] if 'CN' in name else 'N/A'),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, name['emailAddress'] if 'emailAddress' in name else 'N/A'),
            ])).sign(pkey, hashes.SHA256(), default_backend())

    return csr


def create_certificate(request, issuer_cert, issuer_key, not_before, not_after, serial=x509.random_serial_number()):
    """
    Generate a certificate given a certificate request.
    Arguments: req        - Certificate request to use
               issuer_cert - The certificate of the issuer
               issuer_key  - The private key of the issuer
               not_before  - Timestamp (relative to now) when the certificate
                            starts being valid
               not_after   - Timestamp (relative to now) when the certificate
                            stops being valid
               serial     - Serial number for the certificate. Default value x509.random_serial_number()
    Returns:   The signed certificate in an X509 object
    """
    cert = x509.CertificateBuilder()\
        .subject_name(request.subject)\
        .issuer_name(issuer_cert.subject)\
        .public_key(request.public_key())\
        .serial_number(serial)\
        .not_valid_before(not_before)\
        .not_valid_after(not_after)\
        .sign(issuer_key, hashes.SHA256(), default_backend())
    return cert


def serialize_certificate(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def deserialize_certificate(data):
    return x509.load_pem_x509_certificate(data, default_backend())


def deserialize_pkey(data, passphrase):
    return serialization.load_pem_private_key(data=data, password=passphrase, backend=default_backend())
