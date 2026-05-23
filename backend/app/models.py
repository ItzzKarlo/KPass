from sqlalchemy import Boolean, Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime

from .database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    two_factor_enabled = Column(Boolean, default=False, nullable=False)
    two_factor_secret = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    passwords = relationship("PasswordEntry", back_populates="owner")
    
class PasswordEntry(Base):
    __tablename__ = "password_entries"
    
    id = Column(Integer, primary_key=True, index=True)
    website_url = Column(String, nullable=True)
    website_name = Column(String, nullable=False)
    website_email = Column(String, nullable=True)
    website_username = Column(String, nullable=True)
    encrypted_password = Column(String, nullable=False)
    
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    owner = relationship("User", back_populates="passwords")
    
