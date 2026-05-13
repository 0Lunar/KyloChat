from enum import Enum


class MessageTypes(Enum):
    """ Enum for managing custom MimeTypes """
    SUCCESS = 0
    FAILURE = 1
    MESSAGE = 2
    STATUS_CODE = 3
    COMPRESSED_MSG = 4
    CACHED_LOGIN = 5
    STD_LOGIN = 6
    IMAGE = 7
    COMPRESSED_IMAGE = 8