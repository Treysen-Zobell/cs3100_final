import logging
import sys
import coloredlogs
from logging.handlers import RotatingFileHandler

from app.utils.environment import LOG_LEVEL, LOG_FILE


def create_logger(name):
    logger = logging.Logger(name=name)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Stream
    coloredlogs.install(
        LOG_LEVEL,
        logger=logger,
        stream=sys.stdout,
        isatty=True,
        formatter=formatter,
    )

    # File
    handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=5 * 1024 * 1024,
        backupCount=2,
        encoding=None,
        delay=False,
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger
