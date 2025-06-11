import hashlib
import hmac
from typing import Optional

class HKDF_SHA256:
    """Custom implementation of HKDF (RFC 5869) using HMAC-SHA256."""

    def __init__(self, salt: Optional[bytes], ikm: bytes):
        """
        Initialize the HKDF context.
        :param salt: Optional salt value (a non-secret random value); if not provided, it is set to a string of HashLen zeros.
        :param ikm: Input keying material.
        """
        self._hash_len = hashlib.sha256().digest_size
        if salt is None:
            salt = b'\x00' * self._hash_len
        self._prk = self._extract(salt, ikm)

    def _extract(self, salt: bytes, ikm: bytes) -> bytes:
        """
        HKDF-Extract(salt, IKM) -> PRK
        PRK = HMAC-Hash(salt, IKM)
        """
        return hmac.new(salt, ikm, hashlib.sha256).digest()

    def expand(self, info: Optional[bytes], length: int) -> bytes:
        """
        HKDF-Expand(PRK, info, L) -> OKM
        :param info: Optional context and application specific information (can be zero-length).
        :param length: Length of output keying material in bytes.
        :return: Output keying material (OKM) of 'length' bytes.
        """
        if info is None:
            info = b''
        n = (length + self._hash_len - 1) // self._hash_len
        if n > 255:
            raise ValueError("Cannot expand to more than 255 * HashLen bytes")
        okm = b''
        t = b''
        for i in range(1, n + 1):
            t = hmac.new(self._prk, t + info + bytes([i]), hashlib.sha256).digest()
            okm += t
        return okm[:length]
