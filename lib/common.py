import logging
from abc import ABC, abstractmethod

DEFAULT_MONITORING_FOLDER = 'logs'
TEMPLATE_NODE_ID = 'TAG'
TEMPLATE_NODE_NETWORK_NAME = 'NET'
EVENT_SUFFIX = 'event'


class SubscriberError(Exception):
    pass


class AbstractClient(ABC):
    """
    Abstract class for Blockchain Client
    """

    @abstractmethod
    def __init__(self, publisher_node_url, server_node_url, load, benchmark):
        self._publisher_node_url = publisher_node_url
        self._server_node_url = server_node_url
        self._load = int(load)
        self._benchmark = benchmark

    @abstractmethod
    def generate_load(self):
        pass

    # @abstractmethod
    # def subscribe(self):
    #     pass

    @abstractmethod
    def start_load(self):
        pass


def init_logger(level):
    logger = logging.getLogger()

    handler = logging.StreamHandler()

    formatter = logging.Formatter(
        fmt='[ %(asctime)s ] :: %(levelname)5s :: ( %(module)s ) -- %(message)s')
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    if level == 1:
        logger.setLevel(logging.INFO)
    elif level > 1:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARN)
