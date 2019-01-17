import argparse
import csv
import datetime
import logging
import sys
import time
from os import path

from sawtooth_sdk.messaging.stream import Stream
from sawtooth_sdk.protobuf.client_event_pb2 import ClientEventsSubscribeRequest, ClientEventsSubscribeResponse
from sawtooth_sdk.protobuf.events_pb2 import EventSubscription, EventList
from sawtooth_sdk.protobuf.validator_pb2 import Message

from lib.common import init_logger, EVENT_SUFFIX, DEFAULT_MONITORING_FOLDER, SubscriberError

LOGGER = logging.getLogger(__name__)


class SawtoothSubscriber:

    def __init__(self, url, benchmark, expected_event_count):
        self._event = '{}-{}'.format(benchmark, EVENT_SUFFIX)
        self._url = url
        self.counter = 0
        self._is_active = False
        self._expected_event_count = expected_event_count
        self._stream = Stream('tcp://{}:4004'.format(self._url))

        date = datetime.date.today()
        logging_file_name = '{}-{}-benchmark-events.csv'.format(str(date), benchmark)

        self._event_log_file = path.join(DEFAULT_MONITORING_FOLDER, logging_file_name)

    def subscribe_to_event(self):

        LOGGER.info("Subscribing to event {}".format(self._event))

        done_sub = EventSubscription(event_type=self._event)
        request = ClientEventsSubscribeRequest(subscriptions=[done_sub])

        response_future = self._stream.send(
            Message.CLIENT_EVENTS_SUBSCRIBE_REQUEST,
            request.SerializeToString()
        )

        sub_response = ClientEventsSubscribeResponse()
        sub_response.ParseFromString(response_future.result().content)

        if sub_response.status == ClientEventsSubscribeResponse.OK:
            self._is_active = True
            LOGGER.info('Subscription with response {}'.format(sub_response.status))
        else:
            LOGGER.error('Could not Subscribe to event')
            raise SubscriberError()

    def stop_subscription(self):
        self._is_active = False

    def run(self) -> None:
        if not self._is_active:
            LOGGER.error('Subscriber is inactive, Quitting...')
            return

        LOGGER.info('Starting the logging on {}'.format(self._event_log_file))

        with open(self._event_log_file, 'w+', newline='') as log_file:
            writer = csv.writer(log_file)
            writer.writerow(['time', 'events_received'])

            while self._is_active:

                LOGGER.debug('Waiting for events')

                message_future = self._stream.receive()

                event_list = EventList()
                event_list.ParseFromString(message_future.result().content)

                LOGGER.debug('Received {} event(s)'.format(len(event_list.events)))

                writer.writerow([
                    time.time(),
                    len(event_list.events)
                ])

                self.counter += len(event_list.events)
                if self.counter == self._expected_event_count:
                    self._is_active = False

        LOGGER.debug('Existing subscription loop')


def parse_args(args):
    parser = argparse.ArgumentParser()

    parser.add_argument('-v', '--verbose',
                        action='count',
                        default=3,
                        help='Increase level of output sent to stderr')

    parser.add_argument('-l', '--load',
                        help='Number of transactions to send',
                        default=4)

    parser.add_argument('-b', '--benchmark',
                        help='Name of the benchmark',
                        required=True)

    parser.add_argument('-p', '--publisher',
                        help='IP or domain of the publisher node',
                        default='localhost')

    return parser.parse_args(args)


def main():
    try:
        opts = parse_args(sys.argv[1:])
        init_logger(opts.verbose)

        load = int(opts.load) or 10
        benchmark = opts.benchmark
        publisher = opts.publisher

        subscriber = SawtoothSubscriber(publisher, benchmark, load)
        subscriber.subscribe_to_event()
        subscriber.run()

    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == '__main__':
    main()
