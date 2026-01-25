from enum import Enum


class MessageTypes(Enum):
    SUCCESS = 0
    FAILURE = 1
    MESSAGE = 2
    STATUS_CODE = 3
    COMPRESSED_MSG = 4
    CACHED_LOGIN = 5
    STD_LOGIN = 6