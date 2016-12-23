# encoding=utf-8
from __future__ import division, absolute_import, with_statement, print_function
import logging

DEFAULT_LOGGER_NAME = 'SYS'


def initialize():
    import os
    import sys
    import logging.handlers
    from utils import setting, num, strings

    conf = setting.conf.get("system")

    _fmt = '[%(asctime)s %(levelname)s %(name)s] %(message)s'
    _formatter = logging.Formatter(_fmt)
    _logger = logging.getLogger()
    _log_level = num.safe_int(conf.get("log_level"), logging.NOTSET)

    # stream logger
    if conf.get("log_stdout"):
        _stream_handler = logging.StreamHandler(sys.stdout)
        _stream_handler.setFormatter(_formatter)
        _stream_handler.setLevel(_log_level)
        _logger.addHandler(_stream_handler)

    # file logger
    if conf.get("log_file"):
        if strings.is_blank(conf.get("log_file_path")):
            path = os.path.join(os.path.dirname(__file__), "..", conf.get("project_name") + ".log")
        else:
            path = conf.get("log_file_path")
        _file_handler = logging.handlers.TimedRotatingFileHandler(path, when='d', backupCount=5, encoding="utf-8")
        _file_handler.setFormatter(_formatter)
        _file_handler.setLevel(_log_level)
        _logger.addHandler(_file_handler)

    _logger.setLevel(_log_level)


def critical(msg, name=DEFAULT_LOGGER_NAME):
    logging.getLogger(name).critical(msg)


def error(msg, name=DEFAULT_LOGGER_NAME):
    logging.getLogger(name).error(msg)


def warning(msg, name=DEFAULT_LOGGER_NAME):
    logging.getLogger(name).warning(msg)


def info(msg, name=DEFAULT_LOGGER_NAME):
    logging.getLogger(name).info(msg)


def debug(msg, name=DEFAULT_LOGGER_NAME):
    logging.getLogger(name).debug(msg)


def error_traceback(name=DEFAULT_LOGGER_NAME):
    import traceback
    format_exc = traceback.format_exc()
    error(format_exc, name)
    return format_exc
