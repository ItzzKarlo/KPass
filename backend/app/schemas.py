from pydantic import BaseModel, EmailStr
from typing import Optional


class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class PasswordCreate(BaseModel):
    website_url: Optional[str] = None
    website_name: str
    website_email: Optional[str] = None
    website_username: Optional[str] = None
    website_password: str


class PasswordOut(BaseModel):
    id: int
    website_url: Optional[str]
    website_name: str
    website_email: Optional[str]
    website_username: Optional[str]
    website_password: str

    class Config:
        from_attributes = True