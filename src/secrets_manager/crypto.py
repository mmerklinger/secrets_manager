import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_000_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


def encrypt(key: bytes, data: bytes) -> bytes:
    fernet = Fernet(key)
    return fernet.encrypt(data)


def decrypt(key: bytes, data: bytes) -> bytes:
    fernet = Fernet(key)
    try:
        data = fernet.decrypt(data)
    except InvalidToken:
        raise ValueError("InvalidPassword")
    return data
