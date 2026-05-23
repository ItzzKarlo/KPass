from pydantic import BaseModel, EmailStr
from typing import Optional


class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str
    master_password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    email: EmailStr
    username: str
    two_factor_enabled: bool
    has_master_password: bool

    class Config:
        from_attributes = True


class MasterUnlock(BaseModel):
    master_password: str


class MasterSetup(BaseModel):
    login_password: str
    master_password: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class MasterReset(BaseModel):
    login_password: str
    new_master_password: str


class AccountDelete(BaseModel):
    login_password: str


class MasterUnlockOut(BaseModel):
    master_token: str


class PasswordCreate(BaseModel):
    website_url: Optional[str] = None
    website_name: str
    website_email: Optional[str] = None
    website_username: Optional[str] = None
    website_password: str
    section: str = "Private"


class PasswordUpdate(PasswordCreate):
    pass


class PasswordOut(BaseModel):
    id: int
    website_url: Optional[str]
    website_name: str
    website_email: Optional[str]
    website_username: Optional[str]
    section: str

    class Config:
        from_attributes = True


class PasswordReveal(BaseModel):
    master_token: str


class PasswordSecretOut(BaseModel):
    website_password: str

    class Config:
        from_attributes = True
