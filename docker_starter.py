import argparse
import logging
import os
import sys

from lib.common import init_logger, TEMPLATE_NODE_ID, TEMPLATE_NODE_NETWORK_NAME

LOGGER = logging.getLogger(__name__)


def _generate_docker_compose(node_template, i):
    with open(node_template, 'r') as template_file:
        template = template_file.read()

        docker_compose_directory = os.path.basename(os.getcwd())

        node_file_content = template \
            .replace(TEMPLATE_NODE_ID, str(i)) \
            .replace(TEMPLATE_NODE_NETWORK_NAME, docker_compose_directory)

        base, ext = node_template.split('.')
        node_file_name = base + '-' + str(i) + '.' + ext

        with open(node_file_name, 'w+') as node_file:
            node_file.write(node_file_content)

        return node_file_name


def _docker_up(docker_file):
    LOGGER.info('Starting the node {}'.format(docker_file))
    os.system('docker-compose -f {} up -d --build'.format(docker_file))


class DockerStarter:

    def __init__(self, node_count, node_template, boot_node=None):
        self._node_count = int(node_count)
        self._node_template = node_template
        self._boot_node = boot_node
        self._services = {}

    def start_services(self):
        if self._boot_node is not None:
            _docker_up(self._boot_node)

        for service, docker_file in self._services.items():
            LOGGER.info('Starting the {}'.format(service))
            _docker_up(docker_file)

    def generate_nodes(self):
        # TODO return list of container names for monitor
        LOGGER.info('Generating docker compose file for {} nodes'.format(self._node_count))

        for i in range(self._node_count):
            file = _generate_docker_compose(self._node_template, i)
            self._services['node-' + str(i)] = file


def parse_args(args):
    parser = argparse.ArgumentParser()

    parser.add_argument('-v', '--verbose',
                        action='count',
                        default=0,
                        help='Increase level of output sent to stderr')

    parser.add_argument('-c', '--node_count',
                        help='Number of nodes in the network',
                        default=4)

    parser.add_argument('-t', '--node_template',
                        help='Docker compose template of the standard nodes',
                        required=True)

    parser.add_argument('-b', '--boot_node',
                        help='Docker compose of the Boot if any',
                        default=None)

    return parser.parse_args(args)


def main():
    try:
        opts = parse_args(sys.argv[1:])
        init_logger(opts.verbose)

        LOGGER.info('Starting The Docker Starter...')

        node_count = int(opts.node_count)
        node_template = opts.node_template
        boot_node = opts.boot_node
        docker_starter_instance = DockerStarter(node_count, node_template, boot_node)

        docker_starter_instance.generate_nodes()
        docker_starter_instance.start_services()

    except KeyboardInterrupt:
        LOGGER.info('Stopping The Docker Starter...')
        sys.exit(0)
    pass


if __name__ == '__main__':
    main()
