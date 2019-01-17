import argparse
import csv
import datetime
import json
import logging
import sys
import time
from os import path, makedirs
from threading import Thread

from lib.common import DEFAULT_MONITORING_FOLDER, init_logger
from lib.domonit.ids import Ids
from lib.domonit.inspect import Inspect
from lib.domonit.stats import Stats

LOGGER = logging.getLogger(__name__)


def _make_logging_file_name(benchmark):
    if not path.exists(DEFAULT_MONITORING_FOLDER):
        LOGGER.info('Logs directory not found, creating "{}"'.format(DEFAULT_MONITORING_FOLDER))
        makedirs(DEFAULT_MONITORING_FOLDER)

    date = datetime.date.today()
    logging_file_name = '{}-{}-benchmark-results.csv'.format(str(date), benchmark)

    return path.join(DEFAULT_MONITORING_FOLDER, logging_file_name)


def _calculate_cpu_percent(stat: Stats):
    cpu_count = len(json.loads(stat.percpu_percpu_usage()))

    cpu_percent = 0.0

    cpu_delta = float(stat.cpu_stats_total_usage()) - float(stat.percpu_total_usage())

    system_delta = float(stat.cpu_stats_system_cpu_usage()) - float(stat.percpu_system_cpu_usage())

    if system_delta > 0.0:
        cpu_percent = cpu_delta / system_delta * 100.0 * cpu_count

    return cpu_percent


class DockerMonitor(Thread):

    def stop(self) -> None:
        self._running = False

    def start(self) -> None:
        self._start_time_millis = time.time()
        super().start()

    def __init__(self, services=None, benchmark='do-nothing', interval=5):
        super().__init__()
        if services is None:
            services = []

        self._services = services
        self._interval = interval
        self._start_time_millis = 0
        self.logging_path = _make_logging_file_name(benchmark)
        self._running = False

    def _map_services_to_container(self) -> dict:

        ids = Ids()
        result_ids = {}
        temp_services = self._services.copy()

        monitor_all = len(self._services) == 0

        for c_id in ids.ids():
            ins = Inspect(c_id)
            name = ins.name()[1:]  # removing the '/' from the start
            LOGGER.debug('Found service {} up'.format(name))

            if monitor_all or name in temp_services:

                if name in temp_services:
                    temp_services.remove(name)

                result_ids[name] = {
                    'id': c_id,
                }

        if len(temp_services) != 0:
            LOGGER.error('{} Services were not found'.format(len(temp_services)))

        return result_ids

    def run(self) -> None:

        LOGGER.info('Writing logs on "{}"'.format(self.logging_path))

        with open(self.logging_path, 'w+', newline='') as logging_file:

            writer = csv.writer(logging_file)
            writer.writerow(['service', 'time', 'cpu_usage_percentage', 'memory_total_usage'])

            container_ids = self._map_services_to_container()

            if len(container_ids.keys()) == 0:
                LOGGER.error('No Containers were found')
                return

            LOGGER.info('Starting the logging')

            self._running = True
            while self._running:

                for service, container in container_ids.items():
                    container['stats'] = Stats(container['id'])
                    row = [
                        service,
                        time.time(),
                        _calculate_cpu_percent(container['stats']),
                        int(container['stats'].memory_stats_usage())
                    ]
                    writer.writerow(row)

                time.sleep(self._interval)


def parse_args(args):
    parser = argparse.ArgumentParser()

    parser.add_argument('-v', '--verbose',
                        action='count',
                        default=0,
                        help='Increase level of output sent to stderr')

    parser.add_argument('-i', '--interval',
                        help='Interval of measures in seconds',
                        default=5)

    parser.add_argument('-s', '--services',
                        help='Services to monitor separated by spaces',
                        nargs='+', )

    parser.add_argument('-b', '--benchmark',
                        help='Name of the test')

    return parser.parse_args(args)


def main():
    try:
        opts = parse_args(sys.argv[1:])
        init_logger(opts.verbose)

        LOGGER.info('Starting The Docker Monitor...')

        services = opts.services or []
        benchmark = opts.benchmark or 'do-nothing'
        interval = int(opts.interval)

        dom = DockerMonitor(services, benchmark, interval)
        dom.run()

    except (KeyboardInterrupt, KeyError) as e:
        LOGGER.info('Stopping the Docker Monitor')
        LOGGER.debug(e)
        sys.exit(0)
    pass


if __name__ == '__main__':
    main()
