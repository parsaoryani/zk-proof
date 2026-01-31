"""Authentication and authorization utilities."""

import jwt
import os
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import secrets

# JWT configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "your-secret-key-change-in-production-12345")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24


def hash_password(password: str) -> str:
    """
    Hash a password using SHA-256 with salt.
    For production, consider using bcrypt or argon2.
    """
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}${pwd_hash.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    try:
        salt, pwd_hash = hashed_password.split('$')
        new_hash = hashlib.pbkdf2_hmac('sha256', plain_password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return hmac.compare_digest(new_hash.hex(), pwd_hash)
    except (ValueError, AttributeError):
        return False


def create_access_token(user_id: int, username: str, role: str, 
                       expires_delta: Optional[timedelta] = None) -> tuple[str, datetime]:
    """
    Create a JWT access token.
    
    Returns:
        tuple: (token, expiry_datetime)
    """
    if expires_delta is None:
        expires_delta = timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    
    expire = datetime.utcnow() + expires_delta
    
    to_encode = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": expire,
        "iat": datetime.utcnow()
    }
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, expire


def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify and decode a JWT access token.
    
    Returns:
        Dictionary with token payload if valid, None if invalid/expired
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def generate_random_token(length: int = 64) -> str:
    """Generate a random token for sessions."""
    return secrets.token_urlsafe(length)
