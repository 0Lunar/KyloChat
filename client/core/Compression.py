import zlib
import psutil


class Compressor(object):
    def __init__(self, level: int = zlib.Z_DEFAULT_COMPRESSION) -> None:
        self._compressor = zlib.compressobj(level=zlib.Z_DEFAULT_COMPRESSION)
        
    def compress(self, data: bytes) -> bytes:
        return self._compressor.compress(data)
    
    def flush(self, data: bytes) -> bytes:
        return self._compressor.flush(zlib.Z_SYNC_FLUSH)
    
    def close(self) -> bytes:
        return self._compressor.flush(zlib.Z_FINISH)
    
    
class Decompressor(object):
    def __init__(self) -> None:
        self._decompressor = zlib.decompressobj()
        
    def decompress(self, data: bytes) -> bytes:
        return self._decompressor.decompress(data)