import sys

from sawtooth_sdk.processor.core import TransactionProcessor
from sawtooth_sdk.processor.log import init_console_logging
from sawtooth_sdk.processor.log import log_configuration
from sawtooth_sdk.processor.config import get_log_dir
from processor.handler import CAHandler


def main():
    try:
        # In docker, the url would be the validator's container name with
        # port 4004
        processor = TransactionProcessor(url='tcp://127.0.0.1:4004')

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
