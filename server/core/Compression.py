import zlib


class Compressor(object):
    """ Class to handle data compression with `zlib` """
    def __init__(self, level: int = zlib.Z_DEFAULT_COMPRESSION) -> None:
        self._compressor = zlib.compressobj(level=zlib.Z_DEFAULT_COMPRESSION)
        
    def compress(self, data: bytes) -> bytes:
        """
        Compresses the data
        
        Args:
            data: the data to compress
        
        Returns:
            compressed: the compressed data
        """
        return self._compressor.compress(data)
    
    def flush(self) -> bytes:
        """
        Returns the missing compressed data
        
        Returns:
            data: the missing compressed data
        """
        return self._compressor.flush(zlib.Z_SYNC_FLUSH)
    
    def close(self) -> bytes:
        """ Closes the compression flow """
        return self._compressor.flush(zlib.Z_FINISH)
    
    
class Decompressor(object):
    """ Class to handle data decompression with `zlib` """
    def __init__(self) -> None:
        self._decompressor = zlib.decompressobj()
        
    def decompress(self, data: bytes) -> bytes:
        """
        Decompress the data
        
        Returns:
            data: the decompressed data
        """
        return self._decompressor.decompress(data)