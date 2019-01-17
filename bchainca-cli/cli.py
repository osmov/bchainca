from __future__ import print_function

import argparse
import getpass
import hashlib
import logging
import os
import traceback
import sys
import pkg_resources
import zmq

from colorlog import ColoredFormatter
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


from client import CaClient
from CaException import CaException


DISTRIBUTION_NAME = 'sawtooth-ca'


DEFAULT_URL = 'http://127.0.0.1:8008'


def create_console_handler(verbose_level):
    clog = logging.StreamHandler()
    formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s %(levelname)-8s%(module)s]%(reset)s "
        "%(white)s%(message)s",
        datefmt="%H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red',
        })

    clog.setFormatter(formatter)

    if verbose_level == 0:
        clog.setLevel(logging.WARN)
    elif verbose_level == 1:
        clog.setLevel(logging.INFO)
    else:
        clog.setLevel(logging.DEBUG)

    return clog


def setup_loggers(verbose_level):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(create_console_handler(verbose_level))


def add_create_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'create',
        help='Creates a new xo game',
        description='Sends a transaction to start an xo game with the '
        'identifier <name>. This transaction will fail if the specified '
        'game already exists.',
        parents=[parent_parser])

    parser.add_argument(
        'name',
        type=str,
        help='unique identifier for the new game')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--disable-client-validation',
        action='store_true',
        default=False,
        help='disable client validation')

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for game to commit')


def add_get_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'get',
        help='Get certificate by serial number',
        description='Get certificate by serial number',
        parents=[parent_parser])

    parser.add_argument(
        'serial',
        type=str,
        help='unique identifier for the new game')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--disable-client-validation',
        action='store_true',
        default=False,
        help='disable client validation')

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for game to commit')


def add_list_approve_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'list_approve',
        help='Get certificate status by serial number',
        description='Get certificate status by serial number',
        parents=[parent_parser])

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
             'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
             'is using Basic Auth')

    parser.add_argument(
        '--disable-client-validation',
        action='store_true',
        default=False,
        help='disable client validation')

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for game to commit')


def add_approve_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'approve',
        help='Get certificate status by serial number',
        description='Get certificate status by serial number',
        parents=[parent_parser])

    parser.add_argument(
        'signer',
        type=str,
        help='unique identifier for the new game')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--disable-client-validation',
        action='store_true',
        default=False,
        help='disable client validation')

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for game to commit')


def add_status_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'status',
        help='Get certificate status by serial number',
        description='Get certificate status by serial number',
        parents=[parent_parser])

    parser.add_argument(
        'serial',
        type=str,
        help='unique identifier for the new game')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--disable-client-validation',
        action='store_true',
        default=False,
        help='disable client validation')

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for game to commit')


def add_revoke_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'revoke',
        help='Revoke certificate by serial number',
        description='Revoke certificate by serial number',
        parents=[parent_parser])

    parser.add_argument(
        'serial',
        type=str,
        help='unique identifier for the new game')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
             'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
             'is using Basic Auth')

    parser.add_argument(
        '--disable-client-validation',
        action='store_true',
        default=False,
        help='disable client validation')

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for game to commit')


def add_simple_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'simple',
        help='Creates a new simple transaction',
        description='Send simple transaction',
        parents=[parent_parser])

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--disable-client-validation',
        action='store_true',
        default=False,
        help='disable client validation')

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for game to commit')


def add_init_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'init',
        help='Init CA transaction',
        description='Send Init CA transaction',
        parents=[parent_parser])

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--disable-client-validation',
        action='store_true',
        default=False,
        help='disable client validation')

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for game to commit')


def add_list_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'list',
        help='Displays information for all xo games',
        description='Displays information for all xo games in state, showing '
        'the players, the game state, and the board for each game.',
        parents=[parent_parser])

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')


def add_show_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'show',
        help='Displays information about an xo game',
        description='Displays the xo game <name>, showing the players, '
        'the game state, and the board',
        parents=[parent_parser])

    parser.add_argument(
        'name',
        type=str,
        help='identifier for the game')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')


def add_take_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'take',
        help='Takes a space in an xo game',
        description='Sends a transaction to take a square in the xo game '
        'with the identifier <name>. This transaction will fail if the '
        'specified game does not exist.',
        parents=[parent_parser])

    parser.add_argument(
        'name',
        type=str,
        help='identifier for the game')

    parser.add_argument(
        'space',
        type=int,
        help='number of the square to take (1-9); the upper-left space is '
        '1, and the lower-right space is 9')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for take transaction '
        'to commit')


def add_delete_parser(subparsers, parent_parser):
    parser = subparsers.add_parser('delete', parents=[parent_parser])

    parser.add_argument(
        'name',
        type=str,
        help='name of the game to be deleted')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for delete transaction to commit')


def create_parent_parser(prog_name):
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)
    parent_parser.add_argument(
        '-v', '--verbose',
        action='count',
        help='enable more verbose output')

    try:
        version = pkg_resources.get_distribution(DISTRIBUTION_NAME).version
    except pkg_resources.DistributionNotFound:
        version = 'UNKNOWN'

    parent_parser.add_argument(
        '-V', '--version',
        action='version',
        version=(DISTRIBUTION_NAME + ' (Hyperledger Sawtooth) version {}')
        .format(version),
        help='display version information')

    return parent_parser


def create_parser(prog_name):
    parent_parser = create_parent_parser(prog_name)

    parser = argparse.ArgumentParser(
        description='Provides subcommands to play tic-tac-toe (also known as '
        'Noughts and Crosses) by sending XO transactions.',
        parents=[parent_parser])

    subparsers = parser.add_subparsers(title='subcommands', dest='command')

    subparsers.required = True

    add_create_parser(subparsers, parent_parser)
    add_simple_parser(subparsers, parent_parser)
    add_init_parser(subparsers, parent_parser)
    add_get_parser(subparsers, parent_parser)
    add_list_approve_parser(subparsers, parent_parser)
    add_approve_parser(subparsers, parent_parser)
    add_revoke_parser(subparsers, parent_parser)
    add_status_parser(subparsers, parent_parser)
    add_list_parser(subparsers, parent_parser)
    add_show_parser(subparsers, parent_parser)
    add_take_parser(subparsers, parent_parser)
    add_delete_parser(subparsers, parent_parser)

    return parser


# def do_list(args):
#     url = _get_url(args)
#     auth_user, auth_password = _get_auth_info(args)
#
#     client = XoClient(base_url=url, keyfile=None)
#
#     game_list = [
#         game.split(',')
#         for games in client.list(auth_user=auth_user,
#                                  auth_password=auth_password)
#         for game in games.decode().split('|')
#     ]
#
#     if game_list is not None:
#         fmt = "%-15s %-15.15s %-15.15s %-9s %s"
#         print(fmt % ('GAME', 'PLAYER 1', 'PLAYER 2', 'BOARD', 'STATE'))
#         for game_data in game_list:
#
#             name, board, game_state, player1, player2 = game_data
#
#             print(fmt % (name, player1[:6], player2[:6], board, game_state))
#     else:
#         raise XoException("Could not retrieve game listing.")
#
#
# def do_show(args):
#     name = args.name
#
#     url = _get_url(args)
#     auth_user, auth_password = _get_auth_info(args)
#
#     client = XoClient(base_url=url, keyfile=None)
#
#     data = client.show(name, auth_user=auth_user, auth_password=auth_password)
#
#     if data is not None:
#
#         board_str, game_state, player1, player2 = {
#             name: (board, state, player_1, player_2)
#             for name, board, state, player_1, player_2 in [
#                 game.split(',')
#                 for game in data.decode().split('|')
#             ]
#         }[name]
#
#         board = list(board_str.replace("-", " "))
#
#         print("GAME:     : {}".format(name))
#         print("PLAYER 1  : {}".format(player1[:6]))
#         print("PLAYER 2  : {}".format(player2[:6]))
#         print("STATE     : {}".format(game_state))
#         print("")
#         print("  {} | {} | {}".format(board[0], board[1], board[2]))
#         print(" ---|---|---")
#         print("  {} | {} | {}".format(board[3], board[4], board[5]))
#         print(" ---|---|---")
#         print("  {} | {} | {}".format(board[6], board[7], board[8]))
#         print("")
#
#     else:
#         raise XoException("Game not found: {}".format(name))

def do_simple(args):
    url = _get_url(args)
    keyfile = _get_keyfile(args)
    auth_user, auth_password = _get_auth_info(args)

    client = CaClient(base_url=url, keyfile=keyfile)

    if args.wait and args.wait > 0:
        response = client.simple(
            'Test data', wait=args.wait,
            auth_user=auth_user,
            auth_password=auth_password)
    else:
        response = client.simple(
            'Test data', auth_user=auth_user,
            auth_password=auth_password)

    print("Response: {}".format(response))


def do_create(args):
    name = args.name
    pkey = create_key_pair()
    csr = create_cert_request(pkey,
                              C=u'RU',
                              ST=u'Moscow',
                              L=u'Moscow',
                              O=u'CWT',
                              CN=name,
                              emailAddress=name)

    csr = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    url = _get_url(args)
    keyfile = _get_keyfile(args)
    auth_user, auth_password = _get_auth_info(args)

    client = CaClient(base_url=url, keyfile=keyfile)

    if args.wait and args.wait > 0:
        response = client.create(
            csr, wait=args.wait,
            auth_user=auth_user,
            auth_password=auth_password)
    else:
        response = client.create(
            csr, auth_user=auth_user,
            auth_password=auth_password)

    print("Response: {}".format(response))

    # client.subscribe('create', is_write_to_file=True)


def do_get(args):
    serial = args.serial
    url = _get_url(args)
    keyfile = _get_keyfile(args)
    auth_user, auth_password = _get_auth_info(args)

    client = CaClient(base_url=url, keyfile=keyfile)

    if args.wait and args.wait > 0:
        response = client.get(
            serial, wait=args.wait,
            auth_user=auth_user,
            auth_password=auth_password)
    else:
        response = client.get(
            serial, auth_user=auth_user,
            auth_password=auth_password)

    print("Response: {}".format(response))

    client.subscribe('get', is_write_to_file=True, file_name="cert_{}.pem".format(serial))


def do_revoke(args):
    serial = args.serial
    url = _get_url(args)
    keyfile = _get_keyfile(args)
    auth_user, auth_password = _get_auth_info(args)

    client = CaClient(base_url=url, keyfile=keyfile)

    if args.wait and args.wait > 0:
        response = client.revoke(
            serial, wait=args.wait,
            auth_user=auth_user,
            auth_password=auth_password)
    else:
        response = client.revoke(
            serial, auth_user=auth_user,
            auth_password=auth_password)

    print("Response: {}".format(response))

    client.subscribe('revoke')


def do_status(args):
    serial = args.serial
    url = _get_url(args)
    keyfile = _get_keyfile(args)
    auth_user, auth_password = _get_auth_info(args)

    client = CaClient(base_url=url, keyfile=keyfile)

    if args.wait and args.wait > 0:
        response = client.status(
            serial, wait=args.wait,
            auth_user=auth_user,
            auth_password=auth_password)
    else:
        response = client.status(
            serial, auth_user=auth_user,
            auth_password=auth_password)

    print("Response: {}".format(response))

    client.subscribe('status')


def do_approve(args):
    signer = args.signer
    url = _get_url(args)
    keyfile = _get_keyfile(args)
    auth_user, auth_password = _get_auth_info(args)

    client = CaClient(base_url=url, keyfile=keyfile)

    if args.wait and args.wait > 0:
        response = client.approve(
            signer, wait=args.wait,
            auth_user=auth_user,
            auth_password=auth_password)
    else:
        response = client.approve(
            signer, auth_user=auth_user,
            auth_password=auth_password)

    print("Response: {}".format(response))

    client.subscribe('create', is_write_to_file=True)


def do_list_approve(args):
    url = _get_url(args)
    keyfile = _get_keyfile(args)
    auth_user, auth_password = _get_auth_info(args)

    client = CaClient(base_url=url, keyfile=keyfile)

    if args.wait and args.wait > 0:
        response = client.list_approve(
            wait=args.wait,
            auth_user=auth_user,
            auth_password=auth_password)
    else:
        response = client.list_approve(
            auth_user=auth_user,
            auth_password=auth_password)

    print("Response: {}".format(response))

    client.subscribe('list_approve')


def do_init(args):
    # name = args.name
    pkey = create_key_pair()

    data = pkey.private_bytes(
         encoding=serialization.Encoding.PEM,
         format=serialization.PrivateFormat.TraditionalOpenSSL,
         encryption_algorithm=serialization.BestAvailableEncryption(b'passw'),
     ).decode('utf-8')

    csr = create_cert_request(pkey,
                              C=u'RU',
                              ST=u'Moscow',
                              L=u'Moscow',
                              O=u'CWT',
                              CN=u'demo CA',
                              emailAddress=u'admin@cwryptoworkplace.io')

    csr = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    url = _get_url(args)
    keyfile = _get_keyfile(args)
    auth_user, auth_password = _get_auth_info(args)

    client = CaClient(base_url=url, keyfile=keyfile)

    if args.wait and args.wait > 0:
        response = client.init(
            data, csr, wait=args.wait,
            auth_user=auth_user,
            auth_password=auth_password)
    else:
        response = client.init(
            data, csr, auth_user=auth_user,
            auth_password=auth_password)

    print("Response: {}".format(response))


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

# def do_take(args):
#     name = args.name
#     space = args.space
#
#     url = _get_url(args)
#     keyfile = _get_keyfile(args)
#     auth_user, auth_password = _get_auth_info(args)
#
#     client = XoClient(base_url=url, keyfile=keyfile)
#
#     if args.wait and args.wait > 0:
#         response = client.take(
#             name, space, wait=args.wait,
#             auth_user=auth_user,
#             auth_password=auth_password)
#     else:
#         response = client.take(
#             name, space,
#             auth_user=auth_user,
#             auth_password=auth_password)
#
#     print("Response: {}".format(response))
#
#
# def do_delete(args):
#     name = args.name
#
#     url = _get_url(args)
#     keyfile = _get_keyfile(args)
#     auth_user, auth_password = _get_auth_info(args)
#
#     client = XoClient(base_url=url, keyfile=keyfile)
#
#     if args.wait and args.wait > 0:
#         response = client.delete(
#             name, wait=args.wait,
#             auth_user=auth_user,
#             auth_password=auth_password)
#     else:
#         response = client.delete(
#             name, auth_user=auth_user,
#             auth_password=auth_password)
#
#     print("Response: {}".format(response))


def _get_url(args):
    return DEFAULT_URL if args.url is None else args.url


def _get_keyfile(args):
    username = getpass.getuser() if args.username is None else args.username
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")

    return '{}/{}.priv'.format(key_dir, username)


def _get_auth_info(args):
    auth_user = args.auth_user
    auth_password = args.auth_password
    if auth_user is not None and auth_password is None:
        auth_password = getpass.getpass(prompt="Auth Password: ")

    return auth_user, auth_password


def main(prog_name=os.path.basename(sys.argv[0]), args=None):
    if args is None:
        args = sys.argv[1:]
    parser = create_parser(prog_name)
    args = parser.parse_args(args)

    if args.verbose is None:
        verbose_level = 0
    else:
        verbose_level = args.verbose

    setup_loggers(verbose_level=verbose_level)

    if args.command == 'create':
        do_create(args)
    elif args.command == 'simple':
        do_simple(args)
    elif args.command == 'init':
        do_init(args)
    elif args.command == 'get':
        do_get(args)
    elif args.command == 'revoke':
        do_revoke(args)
    elif args.command == 'status':
        do_status(args)
    elif args.command == 'list_approve':
        do_list_approve(args)
    elif args.command == 'approve':
        do_approve(args)
    # elif args.command == 'take':
    #     do_take(args)
    # elif args.command == 'delete':
    #     do_delete(args)
    else:
        raise CaException("invalid command: {}".format(args.command))


def main_wrapper():
    try:
        main()
    except CaException as err:
        print("Error: {}".format(err), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main_wrapper()
