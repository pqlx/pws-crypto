from typing import Optional

class Hash:
    """Abstract hash class. Only for inheritance"""

    def __init__(self, first: Optional[bytes]=None):
        self.delta: bool = False
        self_digest: Optional[bytes] = None
        
        self._plaintext: Optional[bytes] = None

        if first:
            self.update(first)

    
    def update(self, data: bytes):
        self._update(data)
        self.delta = True

    def _update(self, data: bytes):
        if not self._plaintext:
            self._plaintext = data
        else:
            self._plaintext += data
    
    def clear():
        self._digest = None
        self.delta = True
    
    def compute_digest(self):
        raise NotImplementedError("Abstract class provides no compute_digest functionality")

    @property
    def digest(self) -> Optional[bytes]:
        if self.delta:
            self._digest = self.compute_digest()
            self.delta = False
        
        return self._digest

    @property
    def hexdigest(self) -> Optional[str]:
        digest = self.digest

        return digest.hex()
