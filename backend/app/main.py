from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from .database import Base, DATABASE_URL, engine, get_db
from .models import User, PasswordEntry
from .schemas import (
    PasswordCreate,
    PasswordOut,
    PasswordUpdate,
    UserLogin,
    UserOut,
    UserRegister,
)
from .auth import hash_password, verify_password, create_access_token, get_current_user
from .crypto import encrypt_text, decrypt_text


def ensure_sqlite_schema():
    if not DATABASE_URL.startswith("sqlite"):
        return

    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return

    user_columns = {column["name"] for column in inspector.get_columns("users")}
    statements = []

    if "two_factor_enabled" not in user_columns:
        statements.append("ALTER TABLE users ADD COLUMN two_factor_enabled BOOLEAN NOT NULL DEFAULT 0")
    if "two_factor_secret" not in user_columns:
        statements.append("ALTER TABLE users ADD COLUMN two_factor_secret VARCHAR")

    if statements:
        with engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))


Base.metadata.create_all(bind=engine)
ensure_sqlite_schema()

app = FastAPI(title="KPass API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {"status": "ok", "app": "KPass"}


@app.post("/api/auth/register")
def register(data: UserRegister, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(
        (User.email == data.email) | (User.username == data.username)
    ).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="Email or username already exists")

    user = User(
        email=data.email,
        username=data.username,
        hashed_password=hash_password(data.password)
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {"message": "User registered successfully"}


@app.post("/api/auth/login")
def login(data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()

    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token({"sub": str(user.id)})

    return {
        "access_token": token,
        "token_type": "bearer"
    }


@app.get("/api/auth/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/api/vault", response_model=list[PasswordOut])
def get_vault(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    entries = db.query(PasswordEntry).filter(
        PasswordEntry.user_id == current_user.id
    ).all()

    return [
        PasswordOut(
            id=entry.id,
            website_url=entry.website_url,
            website_name=entry.website_name,
            website_email=entry.website_email,
            website_username=entry.website_username,
            website_password=decrypt_text(entry.encrypted_password)
        )
        for entry in entries
    ]


@app.post("/api/vault")
def add_password(
    data: PasswordCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    entry = PasswordEntry(
        website_url=data.website_url,
        website_name=data.website_name,
        website_email=data.website_email,
        website_username=data.website_username,
        encrypted_password=encrypt_text(data.website_password),
        user_id=current_user.id
    )

    db.add(entry)
    db.commit()

    return {"message": "Password saved successfully"}


@app.put("/api/vault/{entry_id}", response_model=PasswordOut)
def update_password(
    entry_id: int,
    data: PasswordUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    entry = db.query(PasswordEntry).filter(
        PasswordEntry.id == entry_id,
        PasswordEntry.user_id == current_user.id
    ).first()

    if not entry:
        raise HTTPException(status_code=404, detail="Password entry not found")

    entry.website_url = data.website_url
    entry.website_name = data.website_name
    entry.website_email = data.website_email
    entry.website_username = data.website_username
    entry.encrypted_password = encrypt_text(data.website_password)

    db.commit()
    db.refresh(entry)

    return PasswordOut(
        id=entry.id,
        website_url=entry.website_url,
        website_name=entry.website_name,
        website_email=entry.website_email,
        website_username=entry.website_username,
        website_password=decrypt_text(entry.encrypted_password)
    )


@app.delete("/api/vault/{entry_id}")
def delete_password(
    entry_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    entry = db.query(PasswordEntry).filter(
        PasswordEntry.id == entry_id,
        PasswordEntry.user_id == current_user.id
    ).first()

    if not entry:
        raise HTTPException(status_code=404, detail="Password entry not found")

    db.delete(entry)
    db.commit()

    return {"message": "Password deleted successfully"}
