import sys
import argparse

from sawtooth_sdk.processor.core import TransactionProcessor
from sawtooth_sdk.processor.log import init_console_logging
from sawtooth_sdk.processor.log import log_configuration
from sawtooth_sdk.processor.config import get_log_dir
from handler import CAHandler


def parse_args(args):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(
        '-C', '--connect',
        default='tcp://localhost:4004',
        help='Endpoint for the validator connection')

    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=1,
        help='Increase output sent to stderr')

    return parser.parse_args(args)

def main():
    if args is None:
        args = sys.argv[1:]
    opts = parse_args(args)
    processor = None

    try:
        # In docker, the url would be the validator's container name with
        # port 4004
        processor = TransactionProcessor(url=opts.connect)

        log_dir = get_log_dir()
        # use the transaction processor zmq identity for filename
        log_configuration(
            log_dir=log_dir,
            name="ca-bc-" + str(processor.zmq_id)[2:-1])

        init_console_logging(verbose_level=2)

        handler = CAHandler('ca_1')
        processor.add_handler(handler)
        processor.start()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print("Error: {}".format(e), file=sys.stderr)
    finally:
        if processor is not None:
            processor.stop()


if __name__ == "__main__":
    main()
