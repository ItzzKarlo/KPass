import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from .database import get_db
from .models import User

load_dotenv()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))
MASTER_TOKEN_EXPIRE_MINUTES = int(os.getenv("MASTER_TOKEN_EXPIRE_MINUTES", "30"))

if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY is missing from the environment")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    to_encode = data.copy()
    expires = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expires})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_master_token(user_id: int) -> str:
    return create_access_token(
        {"sub": str(user_id), "scope": "master"},
        expires_minutes=MASTER_TOKEN_EXPIRE_MINUTES
    )


def verify_master_token(token: str, user_id: int) -> bool:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return False

    return payload.get("sub") == str(user_id) and payload.get("scope") == "master"


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid login token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_error
    except JWTError:
        raise credentials_error

    user = db.query(User).filter(User.id == int(user_id)).first()

    if not user:
        raise credentials_error

    return user
