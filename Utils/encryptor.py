from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from typing import Optional, Union


class Encryptor:
    """Handles the all needed encryption/decryption logic utilizing Python pycryptodome library."""

    def __init__(self, debug_mode: bool) -> None:
        self.debug_mode = debug_mode

    @staticmethod
    def generate_bytes_stream(size: Optional[int] = 16) -> bytes:
        """Returns a generated bytes stream of a given size."""
        return get_random_bytes(size)

    @staticmethod
    def hash_password(value: Union[str, bytes]) -> bytes:
        """Returns SAH256 digest of a given string."""
        if isinstance(value, str):
            value = value.encode()
        return SHA256.new(value).digest()

    def encrypt(self, value: Union[bytes, str], encryption_key: bytes, iv: bytes) -> bytes:
        """Returns a padded encrypted value."""
        if isinstance(value, str):
            value = value.encode()
        cipher = AES.new(key=encryption_key, mode=AES.MODE_CBC, iv=iv)
        padded_data = pad(value, AES.block_size)
        encrypted = cipher.encrypt(padded_data)

        # For dev mode:
        if self.debug_mode:
            print(f"Encrypted --> Plain Value: {value}, Encrypted Value: {encrypted}")

        return encrypted

    def decrypt(self, encrypted_value: bytes, decryption_key: bytes, iv: bytes) -> bytes:
        """Returns a decrypted unpadded value."""
        cipher = AES.new(decryption_key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted_value), AES.block_size)

        # For dev mode:
        if self.debug_mode:
            print(f"Decrypted --> Encrypted Value: {encrypted_value}, Decrypted Value: {decrypted}")

        return decrypted

