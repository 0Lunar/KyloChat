class EncodingError(Exception):
    """BAse exception for encoding errors"""
    def __init__(self, *args: object) -> None:
        super().__init__(*args)
        

class DecodingError(Exception):
    """Base exception for decoding errors"""
    def __init__(self, *args: object) -> None:
        super().__init__(*args)
        
        
class SecurityError(Exception):
    """Base exception for security errors"""
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class ClientDisconnected(Exception):
    """Raised when client disconnects"""
    def __init__(self, *args: object) -> None:
        super().__init__(*args)
        
        
class ParameterError(Exception):
    """Base exception for parameter errors"""
    def __init__(self, *args: object) -> None:
        super().__init__(*args)