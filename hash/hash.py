from typing import Optional

class Hash:
    """Abstract hash class. Only for inheritance"""

    def __init__(self, first=Optional[bytes]):
        self.delta: bool = False
        self_digest: Optional[bytes] = None
        
        if first:
            self.update(first)

    
    def update(self, data: bytes):
        self._update(data)
        self.delta = True

    def _update(self, data):
        raise NotImplementedError("Abstract method has no functionality")

    @property
    def digest(self) -> Optional[bytes]:
        if self.delta:
            self._digest = self.compute_digest()
            self.delta = False
        
        return self._digest

    @property
    def hexdigest():
        digest = self.digest

        return digest.hex()
