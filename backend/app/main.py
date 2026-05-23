from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from .database import Base, DATABASE_URL, engine, get_db
from .models import User, PasswordEntry
from .schemas import (
    AccountDelete,
    MasterReset,
    PasswordCreate,
    PasswordChange,
    PasswordOut,
    PasswordReveal,
    PasswordSecretOut,
    PasswordUpdate,
    MasterSetup,
    MasterUnlock,
    MasterUnlockOut,
    UserLogin,
    UserOut,
    UserRegister,
)
from .auth import (
    create_access_token,
    create_master_token,
    get_current_user,
    hash_password,
    verify_master_token,
    verify_password,
)
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
    if "master_password_hash" not in user_columns:
        statements.append("ALTER TABLE users ADD COLUMN master_password_hash VARCHAR")

    entry_columns = set()
    if "password_entries" in inspector.get_table_names():
        entry_columns = {column["name"] for column in inspector.get_columns("password_entries")}

    if entry_columns and "section" not in entry_columns:
        statements.append("ALTER TABLE password_entries ADD COLUMN section VARCHAR NOT NULL DEFAULT 'Private'")

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

    if data.password == data.master_password:
        raise HTTPException(status_code=400, detail="Master password must be different from login password")

    user = User(
        email=data.email,
        username=data.username,
        hashed_password=hash_password(data.password),
        master_password_hash=hash_password(data.master_password)
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
    return UserOut(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        two_factor_enabled=current_user.two_factor_enabled,
        has_master_password=bool(current_user.master_password_hash)
    )


@app.post("/api/auth/master/unlock", response_model=MasterUnlockOut)
def unlock_master(
    data: MasterUnlock,
    current_user: User = Depends(get_current_user)
):
    if not current_user.master_password_hash:
        raise HTTPException(status_code=403, detail="Master password is not configured for this account")

    if not verify_password(data.master_password, current_user.master_password_hash):
        raise HTTPException(status_code=401, detail="Invalid master password")

    return MasterUnlockOut(master_token=create_master_token(current_user.id))


@app.post("/api/auth/master/setup")
def setup_master(
    data: MasterSetup,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.master_password_hash:
        raise HTTPException(status_code=400, detail="Master password is already configured")

    if not verify_password(data.login_password, current_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid login password")

    if data.login_password == data.master_password:
        raise HTTPException(status_code=400, detail="Master password must be different from login password")

    current_user.master_password_hash = hash_password(data.master_password)
    db.commit()

    return {"message": "Master password configured"}


@app.post("/api/auth/password/change")
def change_password(
    data: PasswordChange,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not verify_password(data.current_password, current_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid current password")

    if current_user.master_password_hash and verify_password(data.new_password, current_user.master_password_hash):
        raise HTTPException(status_code=400, detail="Login password must be different from master password")

    current_user.hashed_password = hash_password(data.new_password)
    db.commit()

    return {"message": "Password changed"}


@app.post("/api/auth/master/reset")
def reset_master_password(
    data: MasterReset,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not verify_password(data.login_password, current_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid login password")

    if data.login_password == data.new_master_password:
        raise HTTPException(status_code=400, detail="Master password must be different from login password")

    current_user.master_password_hash = hash_password(data.new_master_password)
    db.commit()

    return {"message": "Master password reset"}


@app.delete("/api/auth/account")
def delete_account(
    data: AccountDelete,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not verify_password(data.login_password, current_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid login password")

    db.query(PasswordEntry).filter(PasswordEntry.user_id == current_user.id).delete()
    db.delete(current_user)
    db.commit()

    return {"message": "Account deleted"}


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
            section=entry.section
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
        section=data.section.strip() or "Private",
        user_id=current_user.id
    )

    db.add(entry)
    db.commit()

    return {"message": "Password saved successfully"}


@app.delete("/api/vault")
def delete_all_passwords(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    deleted = db.query(PasswordEntry).filter(PasswordEntry.user_id == current_user.id).delete()
    db.commit()

    return {"message": "Stored data deleted", "deleted": deleted}


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
    entry.section = data.section.strip() or "Private"

    db.commit()
    db.refresh(entry)

    return PasswordOut(
        id=entry.id,
        website_url=entry.website_url,
        website_name=entry.website_name,
        website_email=entry.website_email,
        website_username=entry.website_username,
        section=entry.section
    )


@app.post("/api/vault/{entry_id}/reveal", response_model=PasswordSecretOut)
def reveal_password(
    entry_id: int,
    data: PasswordReveal,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not verify_master_token(data.master_token, current_user.id):
        raise HTTPException(status_code=401, detail="Master password unlock required")

    entry = db.query(PasswordEntry).filter(
        PasswordEntry.id == entry_id,
        PasswordEntry.user_id == current_user.id
    ).first()

    if not entry:
        raise HTTPException(status_code=404, detail="Password entry not found")

    return PasswordSecretOut(website_password=decrypt_text(entry.encrypted_password))


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
