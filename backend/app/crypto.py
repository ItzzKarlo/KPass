import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet

load_dotenv()

FERNET_KEY = os.getenv("FERNET_KEY")

if not FERNET_KEY:
    raise RuntimeError("FERNET_KEY is missing from .env")

fernet = Fernet(FERNET_KEY.encode())


def encrypt_text(text: str) -> str:
    return fernet.encrypt(text.encode()).decode()


def decrypt_text(encrypted_text: str) -> str:
    return fernet.decrypt(encrypted_text.encode()).decode()