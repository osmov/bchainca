import argparse
import logging
import sys

from sawtooth_client import SawtoothClient
from lib.common import init_logger, SubscriberError
from docker_monitor import DockerMonitor
from docker_starter import DockerStarter

LOGGER = logging.getLogger(__name__)


def main():
    try:
        opts = parse_args(sys.argv[1:])
        init_logger(opts.verbose)

        LOGGER.info('Starting Service...')

        node_count = int(opts.node_count)
        node_template = opts.node_template
        boot_node = opts.boot_node
        docker_starter = DockerStarter(node_count, node_template, boot_node)

        services = docker_starter.generate_nodes()
        docker_starter.start_services()

        benchmark = opts.benchmark

        monitor = DockerMonitor(services, benchmark)
        monitor.start()

        publisher_url = opts.publisher_url
        server_node_url = opts.server_node_url
        load = opts.load
        client = SawtoothClient(publisher_url, server_node_url, load, benchmark)

        client.subscribe()
        client.generate_load()
        client.start_load()

    except (KeyboardInterrupt, SubscriberError):
        sys.exit(0)


def parse_args(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose',
                        action='count',
                        default=0,
                        help='Increase level of output sent to stderr')

    parser.add_argument('--node_count',
                        help='Number of nodes in the network',
                        default=4)

    parser.add_argument('--node_template',
                        help='Docker compose template of the standard nodes',
                        default='tcp://localhost:4004')

    parser.add_argument('--boot_node',
                        help='Docker compose of the Boot if any',
                        default=None)

    parser.add_argument('--publisher_url',
                        help='Url with port of the Publisher',
                        default='tcp://localhost:4004')

    parser.add_argument('--server_node_url',
                        help='Url with port of the Server node for the client',
                        default='tcp://localhost:8008')

    parser.add_argument('--load',
                        help='Number of transactions sent to the network',
                        default=0)

    parser.add_argument('--benchmark',
                        help='Name of the benchmark',
                        default='do-nothing')

    return parser.parse_args(args)


if __name__ == '__main__':
    main()
