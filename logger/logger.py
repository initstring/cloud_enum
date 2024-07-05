"""
JSON logger
"""

import datetime
from distutils.log import Log
import json

TRACE = 0
DEBUG = 1
INFO = 2
WARNING = 3
ERROR = 4


class Logger:
    def __init__(self, level):
        self._level = self.__level_int(level)
        self._extra_data = {}

    def new(self):
        return Logger(self.__level_str(self._level))

    def extra(self, key=None, value=None, map=None):
        if map:
            self._extra_data.update(map)
        elif key and value:
            self._extra_data[key] = value
        return self

    def trace(self, msg):
        self.__log(TRACE, msg)

    def debug(self, msg):
        self.__log(DEBUG, msg)

    def info(self, msg):
        self.__log(INFO, msg)

    def warning(self, msg):
        self.__log(WARNING, msg)

    def error(self, msg):
        self.__log(ERROR, msg)

    def __log(self, level, msg):
        if self._level > level:
            return
        entry = {
            'time': datetime.datetime.now().isoformat(),
            'level': self.__level_str(level),
            'message': msg
        }
        entry.update(self._extra_data)
        print(json.dumps(entry))

    def __level_str(self, level):
        if level == TRACE:
            return "TRACE"
        if level == DEBUG:
            return "DEBUG"
        if level == INFO:
            return "INFO"
        if level == WARNING:
            return "WARNING"
        if level == ERROR:
            return "ERROR"
        return "INFO"

    def __level_int(self, level):
        if level == "TRACE":
            return TRACE
        if level == "DEBUG":
            return DEBUG
        if level == "INFO":
            return INFO
        if level == "WARNING":
            return WARNING
        if level == "ERROR":
            return ERROR
        return INFO
