import logging
import app
from util import loggingFactory, get_singleton
_getLogger=loggingFactory('app.__main__')


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(name)-15s %(message)s')
    logger=_getLogger()

    logger.debug("starting the server")
    get_singleton('stormpathApp').app.run(threaded=True)
