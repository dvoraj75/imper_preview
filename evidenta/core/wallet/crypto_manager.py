import base64

from django.contrib.auth.hashers import PBKDF2PasswordHasher

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from app_settings import settings


class CryptoManager:

    KEY_LENGTH = settings.WALLET_KEY_LEN

    def __init__(self):
        self.hasher = PBKDF2PasswordHasher()

    def _create_password(self, password: str, salt: str) -> bytes:
        """
        Creates AES key for encrypting and decrypting stored secret.

        Password is created from first at least 16 bytes (if using AES-128) and at most 32 bytes (AES-256)
        of generated hash.
        """
        secret = settings.WALLET_SECRET_KEY + password
        return base64.b64decode(self.hasher.encode(secret, salt).split("$")[-1])[: self.KEY_LENGTH]

    def encrypt_data(self, decrypted_data: str, password: str, salt: str) -> tuple[str, str]:
        """
        Encrypts data and returns nonce and encrypted data encoded in base64.
        """
        data_password = self._create_password(password, salt)
        encrypter = AES.new(data_password, AES.MODE_GCM)
        encrypted_data = encrypter.encrypt(pad(decrypted_data.encode(), encrypter.block_size))

        return base64.b64encode(encrypted_data).decode(), base64.b64encode(encrypter.nonce).decode()

    def decrypt_data(self, encrypted_data: str, password: str, salt: str, nonce: str) -> str:
        """
        :param: encrypted_data Encrypted data in Base64 format
        :param: password User password hash
        :param: salt Wallet salt
        :param: nonce Wallet record nonce encoded in Base64 format

        :return: Decrypted secret
        """
        data_password = self._create_password(password, salt)
        decrypter = AES.new(data_password, AES.MODE_GCM, nonce=base64.b64decode(nonce))
        return unpad(decrypter.decrypt(base64.b64decode(encrypted_data)), decrypter.block_size).decode()

    def generate_salt(self) -> str:
        return self.hasher.salt()
