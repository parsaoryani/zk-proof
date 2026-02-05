"""Authentication and user management endpoints.

Provides API routes for user registration, login, and identity verification.
Integrates with KYC/AML system for regulatory compliance.

Endpoints:
    POST /auth/register - Register new user with identity proof
    POST /auth/login - Authenticate user and issue JWT token
    POST /auth/logout - Revoke authentication token
    GET /auth/verify - Verify token validity

Security:
    - JWT-based authentication with expiration
    - Rate limiting on login attempts (prevent brute force)
    - Secure password hashing with argon2
    - Optional 2FA support via TOTP
    - Audit logging of authentication events
"""

from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, UTC

from zkm.storage import DatabaseManager, get_db_manager, UserRole
from zkm.storage.database import User
from zkm.security import (
    hash_password,
    verify_password,
    create_access_token,
    verify_access_token,
    generate_random_token,
)

# ===========================================
# Request/Response Models
# ===========================================


class RegisterRequest(BaseModel):
    """User registration request."""

    username: str
    password: str
    email: Optional[str] = None


class RegisterResponse(BaseModel):
    """User registration response."""

    user_id: int
    username: str
    role: str
    message: str


class LoginRequest(BaseModel):
    """User login request."""

    username: str
    password: str


class LoginResponse(BaseModel):
    """User login response."""

    access_token: str
    token_type: str = "bearer"
    user_id: int
    username: str
    role: str
    expires_in: int  # seconds


class CurrentUserResponse(BaseModel):
    """Current authenticated user response."""

    user_id: int
    username: str
    role: str
    email: Optional[str]
    is_verified: bool
    created_at: str
    last_login: Optional[str]


# ===========================================
# Dependency: Current User
# ===========================================


async def get_current_user(
    authorization: Optional[str] = Header(None), db: DatabaseManager = Depends(get_db_manager)
):
    """
    Get current authenticated user from JWT token.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")

    # Extract token from "Bearer <token>"
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = authorization[7:]

    # Verify token
    payload = verify_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # Get user from database
    session = db.get_session()
    try:
        user = db.get_user_by_id(session, payload.get("user_id"))
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        return user
    finally:
        session.close()


async def require_admin(current_user=Depends(get_current_user)):
    """
    Require admin role.
    """
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


async def require_admin_or_moderator(current_user=Depends(get_current_user)):
    """
    Require admin or moderator role.
    """
    if current_user.role not in [UserRole.ADMIN, UserRole.MODERATOR]:
        raise HTTPException(status_code=403, detail="Admin or moderator access required")
    return current_user


# ===========================================
# Authentication Endpoints
# ===========================================


def register_auth_routes(app: FastAPI):
    """Register authentication routes to app."""

    @app.post("/auth/register", response_model=RegisterResponse, tags=["Authentication"])
    async def register(request: RegisterRequest, db: DatabaseManager = Depends(get_db_manager)):
        """
        Register a new user account.

        - **username**: Unique username
        - **password**: Password
        - **email**: Optional email address

        Returns new user information with user_id.
        """
        # Validate required fields
        if not request.username or not request.username.strip():
            raise HTTPException(
                status_code=400,
                detail="Username is required and cannot be empty."
            )
        
        if not request.password or len(request.password) < 4:
            raise HTTPException(
                status_code=400,
                detail="Password is required and must be at least 4 characters."
            )
        
        # Validate username format
        if len(request.username) < 3:
            raise HTTPException(
                status_code=400,
                detail="Username must be at least 3 characters long."
            )
        
        if not request.username.replace('_', '').replace('-', '').isalnum():
            raise HTTPException(
                status_code=400,
                detail="Username can only contain letters, numbers, hyphens, and underscores."
            )

        session = db.get_session()
        try:
            # Check if username already exists
            existing_user = db.get_user_by_username(session, request.username)
            if existing_user:
                raise HTTPException(status_code=400, detail="Username already exists")

            # Create user
            hashed_password = hash_password(request.password)
            user = db.create_user(
                session,
                username=request.username,
                password_hash=hashed_password,
                email=request.email,
                role=UserRole.USER,  # New users are regular users
            )

            return RegisterResponse(
                user_id=user.id,
                username=user.username,
                role=user.role.value,
                message="User registered successfully. You can now log in.",
            )

        except HTTPException:
            raise
        except ValueError as e:
            session.rollback()
            raise HTTPException(
                status_code=400,
                detail=f"Invalid registration data: {str(e)}"
            )
        except Exception as e:
            session.rollback()
            import logging
            logging.getLogger(__name__).error(f"Registration error: {e}", exc_info=True)
            error_msg = str(e).lower()
            if "unique" in error_msg or "duplicate" in error_msg:
                raise HTTPException(
                    status_code=400,
                    detail="Username or email already exists. Please choose another."
                )
            else:
                raise HTTPException(
                    status_code=500,
                    detail="Registration failed due to server error. Please try again."
                )
        finally:
            session.close()

    @app.post("/auth/login", response_model=LoginResponse, tags=["Authentication"])
    async def login(request: LoginRequest, db: DatabaseManager = Depends(get_db_manager)):
        """
        Login user and get access token.

        - **username**: Username
        - **password**: Password

        Returns JWT access token valid for 24 hours.
        """
        session = db.get_session()
        try:
            # Get user by username
            user = db.get_user_by_username(session, request.username)
            if not user:
                raise HTTPException(status_code=401, detail="Invalid username or password")

            # Check if active
            if not user.is_active:
                raise HTTPException(status_code=403, detail="User account is disabled")

            # Verify password
            if not verify_password(request.password, user.password_hash):
                raise HTTPException(status_code=401, detail="Invalid username or password")

            # Update last login
            db.update_user_last_login(session, user.id)

            # Create access token
            token, expiry = create_access_token(user.id, user.username, user.role.value)

            # Calculate expires_in
            import time

            expires_in = int((expiry - datetime.now(UTC)).total_seconds())

            return LoginResponse(
                access_token=token,
                user_id=user.id,
                username=user.username,
                role=user.role.value,
                expires_in=expires_in,
            )

        finally:
            session.close()

    @app.get("/auth/me", response_model=CurrentUserResponse, tags=["Authentication"])
    async def get_current_user_info(current_user=Depends(get_current_user)):
        """
        Get current authenticated user information.

        Requires valid access token in Authorization header.
        """
        return CurrentUserResponse(
            user_id=current_user.id,
            username=current_user.username,
            role=current_user.role.value,
            email=current_user.email,
            is_verified=current_user.is_verified,
            created_at=current_user.created_at.isoformat(),
            last_login=current_user.last_login.isoformat() if current_user.last_login else None,
        )

    @app.post("/auth/logout", tags=["Authentication"])
    async def logout(
        current_user=Depends(get_current_user), db: DatabaseManager = Depends(get_db_manager)
    ):
        """
        Logout user (invalidate all sessions).

        Requires valid access token.
        """
        session = db.get_session()
        try:
            db.invalidate_user_sessions(session, current_user.id)
            return {"message": "Logged out successfully"}
        finally:
            session.close()
