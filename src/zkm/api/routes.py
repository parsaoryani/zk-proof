"""REST API endpoints for ZK-Mixer system."""

import logging
from enum import Enum
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, ValidationError
from typing import Optional, List, Any
from datetime import datetime
from sqlalchemy import text

from zkm.core.mixer import ZKMixer
from zkm.core.zkproof import WithdrawalProof
from zkm.storage import DatabaseManager, get_db_manager, UserRole, TransactionStatus
from zkm.models.schemas import (
    DepositRequest,
    DepositResponse,
    WithdrawalRequest,
    WithdrawalResponse,
    AuditRequest,
    AuditResponse,
    MixerStateResponse,
    MixerStatistics as MixerStatsModel,
)
from zkm.security import verify_access_token
from zkm.exceptions import (
    DoubleSpendError,
    WithdrawalError,
    InvalidProofError,
)

# Configure logging
logger = logging.getLogger(__name__)

# Global mixer instance
mixer = ZKMixer(merkle_tree_height=32)


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field(..., description="Service status")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    version: str = "1.0.0"


class TransactionListResponse(BaseModel):
    """List of recent transactions."""

    transactions: List[dict] = Field(..., description="Recent transactions")
    total_count: int = Field(..., description="Total transaction count")


class ErrorResponse(BaseModel):
    """Error response."""

    error: str = Field(..., description="Error message")
    code: str = Field(..., description="Error code")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


# Initialize FastAPI
app = FastAPI(
    title="ZK-Mixer REST API",
    description="Privacy-preserving cryptocurrency mixer with regulatory compliance",
    version="1.0.0",
)

# Register authentication routes
from zkm.api.auth_routes import register_auth_routes
register_auth_routes(app)

# Add CORS middleware to allow frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (can be restricted to specific domains in production)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Custom exception handler for validation errors - convert 422 to 400
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Convert Pydantic validation errors (422) to 400 Bad Request."""
    errors = exc.errors()
    error_messages = []
    
    for error in errors:
        field = " -> ".join(str(loc) for loc in error["loc"])
        msg = error["msg"]
        error_messages.append(f"{field}: {msg}")
    
    detail = "; ".join(error_messages)
    return JSONResponse(
        status_code=400,
        content={"detail": detail}
    )


# Dependency for database
def get_db() -> DatabaseManager:
    """Get database manager."""
    return get_db_manager()


async def get_current_user(
    authorization: Optional[str] = Header(None), db: DatabaseManager = Depends(get_db)
):
    """Get current authenticated user from JWT token."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = authorization[7:]
    payload = verify_access_token(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    session = db.get_session()
    try:
        user = db.get_user_by_id(session, payload.get("user_id"))
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        return user
    finally:
        session.close()


async def require_admin(current_user=Depends(get_current_user)):
    """Require admin role."""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


async def require_admin_or_moderator(current_user=Depends(get_current_user)):
    """Require admin or moderator role."""
    if current_user.role not in [UserRole.ADMIN, UserRole.MODERATOR]:
        raise HTTPException(status_code=403, detail="Admin or moderator access required")
    return current_user


# ============================================================================
# Health & System Endpoints
# ============================================================================


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Check service health and status."""
    return HealthResponse(status="operational")


@app.get("/state", tags=["System"])
async def get_state():
    """Get current mixer state."""
    state = mixer.get_mixer_state()
    return {
        "num_commitments": state.num_commitments,
        "num_nullifiers": state.num_nullifiers,
        "merkle_root": state.merkle_root.hex(),
        "tree_height": state.tree_height,
    }


@app.get("/statistics", tags=["System"])
async def get_statistics(
    authorization: Optional[str] = Header(None),
    db: DatabaseManager = Depends(get_db)
):
    """Get mixer statistics from database."""
    session = db.get_session()
    try:
        # Get statistics from DATABASE, not memory
        transactions = db.get_recent_transactions(session, limit=10000)  # Get all

        total_deposits = sum(1 for tx in transactions if tx.tx_type.value == "deposit")
        total_withdrawals = sum(1 for tx in transactions if tx.tx_type.value == "withdrawal")
        total_volume = sum(tx.amount for tx in transactions if tx.tx_type.value == "deposit")
        
        # Get total system balance
        total_balance = db.get_total_balance(session)
        
        # Get user balance if authenticated
        user_balance = 0.0
        if authorization and authorization.startswith("Bearer "):
            try:
                token = authorization.replace("Bearer ", "")
                from zkm.security.auth import verify_access_token
                payload = verify_access_token(token)
                user_id = payload.get("user_id")
                if user_id:
                    user_balance = db.get_user_balance(session, user_id)
            except:
                pass  # Not authenticated or invalid token

        # Get mixer in-memory stats for other data
        mixer_stats = mixer.get_statistics()

        return {
            "total_deposits": total_deposits,
            "total_withdrawals": total_withdrawals,
            "total_volume": float(total_volume),
            "total_balance": total_balance,  # Total balance across all users
            "user_balance": user_balance,  # Current user's balance
            "num_commitments": mixer_stats.get("num_commitments", 0),
            "num_nullifiers": mixer_stats.get("num_nullifiers", 0),
            "audited_transactions": mixer_stats.get("audited_transactions", 0),
            "uptime_hours": mixer_stats.get("uptime_hours", 0),
            "merkle_root": mixer_stats.get("merkle_root", ""),
        }
    finally:
        session.close()


# ============================================================================
# Deposit Endpoints
# ============================================================================


@app.post("/deposit", tags=["Deposit"])
async def deposit(
    request: DepositRequest,
    authorization: Optional[str] = Header(None),
    db: DatabaseManager = Depends(get_db),
):
    """
    Create a private deposit.

    - **identity**: User identifier (email)
    - **amount**: Deposit amount in currency units

    Returns deposit receipt with commitment and merkle root.
    """
    try:
        if request.amount <= 0:
            raise HTTPException(status_code=400, detail="Amount must be positive")

        # Get user_id if authenticated, otherwise use None (anonymous)
        user_id = None
        if authorization and authorization.startswith("Bearer "):
            try:
                token = authorization.replace("Bearer ", "")
                from zkm.security.auth import verify_access_token

                payload = verify_access_token(token)
                user_id = payload.get("user_id")
            except:
                pass  # Anonymous deposit if token invalid

        # Create deposit
        receipt = mixer.deposit(request.identity, request.amount)

        # Get encrypted identity from mixer's deposits
        encrypted_identity = None
        for leaf_idx, dep_info in mixer.deposits.items():
            if dep_info.get("deposit_hash") == receipt.deposit_hash:
                encrypted_identity_hex = dep_info.get("encrypted_identity")
                if encrypted_identity_hex:
                    encrypted_identity = bytes.fromhex(encrypted_identity_hex)
                break

        # Store in database
        session = db.get_session()
        try:
            # For anonymous deposits, use admin user (id=1) as default
            if user_id is None:
                # Get anonymous user if exists, otherwise use admin
                anon_user = db.get_user_by_username(session, "anonymous")
                user_id = anon_user.id if anon_user else 1

            db.add_transaction(
                session,
                transaction_hash=receipt.deposit_hash,
                tx_type="deposit",
                amount=abs(request.amount),  # Ensure positive amount for deposits
                user_id=user_id,
                status="confirmed",
            )
            
            # Update user balance - add deposit amount
            db.update_user_balance(session, user_id, abs(request.amount))

            # Also store commitment with encrypted identity for later audit
            # Only store if we have valid commitment data
            try:
                if receipt.commitment and receipt.commitment_index >= 0:
                    db.add_commitment(
                        session,
                        commitment_hash=receipt.commitment,
                        commitment_index=receipt.commitment_index,
                        transaction_hash=receipt.deposit_hash,
                        merkle_root=receipt.merkle_root,
                        encrypted_secret=b"",  # Not used for now
                        encrypted_randomness=b"",  # Not used for now
                        amount=abs(request.amount),
                        encrypted_identity=encrypted_identity,
                    )
            except Exception as e:
                # Log but don't fail the deposit if commitment storage fails
                logger.warning(f"Failed to store commitment: {e}")
        finally:
            session.close()

        return {
            "commitment": receipt.commitment.hex(),
            "commitment_index": receipt.commitment_index,
            "merkle_root": receipt.merkle_root.hex(),
            "deposit_hash": receipt.deposit_hash,
            "timestamp": datetime.now().isoformat(),
        }

    except ValueError as e:
        error_msg = str(e)
        if "amount" in error_msg.lower() or "positive" in error_msg.lower():
            raise HTTPException(
                status_code=400,
                detail="Invalid amount. Please enter a positive number."
            )
        raise HTTPException(status_code=400, detail=f"Invalid input: {error_msg}")
    except Exception as e:
        logger.error(f"Deposit error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Deposit failed: {str(e)}")


# ============================================================================
# Withdrawal Endpoints
# ============================================================================


@app.post("/withdraw", tags=["Withdrawal"])
async def withdraw(
    request: WithdrawalRequest,
    authorization: Optional[str] = Header(None),
    db: DatabaseManager = Depends(get_db),
):
    """
    Withdraw coin anonymously.

    Provide complete withdrawal proof with:
    - **nullifier**: Double-spend prevention token
    - **merkle_path**: Merkle tree authentication path
    - **leaf_index**: Position in tree
    - **identity_encryption_proof**: Proof of valid encryption
    - **encrypted_identity**: Encrypted user identity

    Returns withdrawal receipt if valid.
    """
    try:
        # Get user_id if authenticated, otherwise use None (anonymous)
        user_id = None
        if authorization and authorization.startswith("Bearer "):
            try:
                token = authorization.replace("Bearer ", "")
                from zkm.security.auth import verify_access_token

                payload = verify_access_token(token)
                user_id = payload.get("user_id")
            except:
                pass  # Anonymous withdrawal if token invalid

        # Reconstruct proof from request
        from zkm.utils.hash import sha256, hash_concatenate

        nullifier = bytes.fromhex(request.nullifier)
        merkle_path = [bytes.fromhex(h) for h in request.merkle_path]
        identity_encryption_proof = bytes.fromhex(request.identity_encryption_proof)
        encrypted_identity = bytes.fromhex(request.encrypted_identity)

        # Compute proof hash (same as in ZKProofSystem.generate_withdrawal_proof)
        proof_components = hash_concatenate(
            nullifier,
            b"".join(merkle_path),
            request.leaf_index.to_bytes(8, "big"),
            identity_encryption_proof,
            encrypted_identity,
            request.timestamp.isoformat().encode("utf-8"),
        )
        proof_hash = sha256(proof_components)

        proof = WithdrawalProof(
            nullifier=nullifier,
            merkle_path=merkle_path,
            leaf_index=request.leaf_index,
            identity_encryption_proof=identity_encryption_proof,
            encrypted_identity=encrypted_identity,
            timestamp=request.timestamp,
            proof_hash=proof_hash,
        )

        # Process withdrawal
        receipt = mixer.withdraw(proof)

        # Get withdrawal amount from request (frontend provides this for balance tracking)
        withdrawal_amount = abs(request.withdrawal_amount) if request.withdrawal_amount else 0

        # Store in database
        session = db.get_session()
        try:
            # For anonymous withdrawals, use admin user (id=1) as default
            if user_id is None:
                anon_user = db.get_user_by_username(session, "anonymous")
                user_id = anon_user.id if anon_user else 1

            db.add_transaction(
                session,
                transaction_hash=receipt.transaction_hash,
                tx_type="withdrawal",
                amount=withdrawal_amount,
                user_id=user_id,
                status="confirmed",
            )
            
            # Update user balance - subtract withdrawal amount
            db.update_user_balance(session, user_id, -abs(withdrawal_amount))
        finally:
            session.close()

        return {
            "transaction_hash": receipt.transaction_hash,
            "status": receipt.status,
            "timestamp": (
                receipt.timestamp.isoformat()
                if isinstance(receipt.timestamp, datetime)
                else receipt.timestamp
            ),
        }

    except ValueError as e:
        # Invalid hex format for commitment/nullifier/etc
        error_msg = str(e)
        if "non-hexadecimal" in error_msg.lower() or "invalid literal" in error_msg.lower():
            raise HTTPException(
                status_code=422, 
                detail="Invalid commitment format. Expected hexadecimal string."
            )
        raise HTTPException(status_code=400, detail=f"Invalid input: {error_msg}")
    except DoubleSpendError as e:
        raise HTTPException(
            status_code=409, 
            detail=f"Double-spend detected: This commitment has already been withdrawn. {str(e)}"
        )
    except WithdrawalError as e:
        error_msg = str(e).lower()
        if "double-spend" in error_msg:
            raise HTTPException(
                status_code=409,
                detail="Double-spend detected: This commitment has already been withdrawn."
            )
        elif "proof" in error_msg and "failed" in error_msg:
            raise HTTPException(
                status_code=400,
                detail="Invalid withdrawal proof. The commitment may not exist or proof is incorrect."
            )
        elif "merkle" in error_msg:
            raise HTTPException(
                status_code=400,
                detail="Merkle tree verification failed. Commitment not found in tree."
            )
        else:
            raise HTTPException(status_code=400, detail=f"Withdrawal failed: {str(e)}")
    except InvalidProofError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid proof: {str(e)}"
        )
    except Exception as e:
        # Generic fallback
        logger.error(f"Unexpected withdrawal error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, 
            detail=f"Withdrawal failed due to unexpected error: {str(e)}"
        )


# ============================================================================
# Admin Endpoints
# ============================================================================


@app.get("/admin/auditor-key", tags=["Admin"])
async def get_auditor_key(current_user=Depends(require_admin)):
    """
    Get the system auditor's private key (ADMIN ONLY).
    Required for decrypting deposit transactions during audit operations.

    **Admin Only** - Requires valid authentication token with admin role

    Returns:
        - auditor_private_key: RSA private key in PEM format
        - auditor_public_key: RSA public key in PEM format
    """
    try:
        # Get the private and public keys from the mixer's auditor instance
        private_key_pem = mixer.auditor.private_key
        public_key_pem = mixer.auditor.public_key

        # Convert bytes to string if needed
        private_key_str = (
            private_key_pem.decode() if isinstance(private_key_pem, bytes) else private_key_pem
        )
        public_key_str = (
            public_key_pem.decode() if isinstance(public_key_pem, bytes) else public_key_pem
        )

        return {
            "auditor_private_key": private_key_str,
            "auditor_public_key": public_key_str,
            "note": "Keep the private key secure. This key is required to decrypt deposit identities.",
            "admin": current_user.username,
            "timestamp": datetime.now().isoformat(),
        }
    except AttributeError as e:
        logger.error(f"Auditor key attribute error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Auditor key not properly initialized. Please contact administrator."
        )
    except Exception as e:
        logger.error(f"Failed to retrieve auditor key: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve auditor key due to server error."
        )


# ============================================================================
# Audit Endpoints (Restricted)
# ============================================================================


@app.post("/audit", tags=["Audit"])
async def audit_transaction(
    request: AuditRequest,
    db: DatabaseManager = Depends(get_db),
    current_user=Depends(require_admin_or_moderator),
):
    """
    Audit specific transaction (regulatory compliance).

    **ADMIN/MODERATOR ONLY** - Requires valid authentication token

    Requires auditor private key. Decrypts identity for compliance review.

    - **transaction_hash**: Transaction to audit
    - **auditor_private_key**: RSA private key (PEM format)

    Returns decrypted identity (audit only!).
    """
    import logging

    logger = logging.getLogger(__name__)

    try:
        logger.info(f"Audit request for transaction: {request.transaction_hash}")
        logger.info(f"Auditor: {current_user.username} (ID: {current_user.id})")

        if not request.auditor_private_key:
            raise HTTPException(status_code=403, detail="Auditor key required")

        if not request.transaction_hash or not request.transaction_hash.strip():
            raise HTTPException(status_code=400, detail="Transaction hash required")

        tx_hash = request.transaction_hash.strip()

        # Verify transaction exists in database before attempting audit
        session = db.get_session()
        try:
            # Try exact match first
            db_tx = db.get_transaction(session, tx_hash)

            # If not found, try case-insensitive search
            if not db_tx:
                logger.warning(f"Exact match not found. Trying case-insensitive: {tx_hash}")
                from zkm.storage.database import Transaction

                all_txs = session.query(Transaction).all()
                for t in all_txs:
                    if t.transaction_hash and t.transaction_hash.lower() == tx_hash.lower():
                        db_tx = t
                        logger.info(f"Found via case-insensitive: {t.transaction_hash}")
                        tx_hash = t.transaction_hash  # Update to use actual stored hash
                        break

            if not db_tx:
                logger.warning(f"Transaction not found: {tx_hash}")
                from zkm.storage.database import Transaction

                sample_txs = [t.transaction_hash for t in session.query(Transaction).limit(3).all()]
                logger.warning(f"Sample transactions in DB: {sample_txs}")
                raise HTTPException(
                    status_code=404,
                    detail=f"Transaction not found: {tx_hash}. Check transaction hash format.",
                )

            logger.info(
                f"Found transaction in DB: type={db_tx.tx_type.value}, status={db_tx.status.value if hasattr(db_tx.status, 'value') else db_tx.status}"
            )

            # Validate it's a DEPOSIT transaction (case-insensitive)
            tx_type_value = (
                db_tx.tx_type.value if hasattr(db_tx.tx_type, "value") else str(db_tx.tx_type)
            )
            if tx_type_value.lower() != "deposit":
                logger.warning(f"Attempted audit on non-deposit transaction: {tx_type_value}")
                raise HTTPException(
                    status_code=400,
                    detail=f"Cannot audit {tx_type_value} transaction. Only DEPOSIT transactions can be audited.",
                )
        finally:
            session.close()

        # Perform audit
        auditor_key = (
            request.auditor_private_key.encode()
            if isinstance(request.auditor_private_key, str)
            else request.auditor_private_key
        )
        logger.info(f"Attempting to audit transaction: {tx_hash}")

        # Get encrypted identity from database OR mixer memory
        session = db.get_session()
        try:
            commitment = db.get_commitment_by_transaction(session, tx_hash)
            encrypted_identity_bytes = None

            # Try database first
            if commitment and commitment.encrypted_identity:
                if isinstance(commitment.encrypted_identity, bytes):
                    encrypted_identity_bytes = commitment.encrypted_identity
                else:
                    encrypted_identity_bytes = bytes.fromhex(commitment.encrypted_identity)
                logger.info(f"Found encrypted identity in database")
            else:
                # Fall back to mixer memory
                logger.info(f"Commitment not in DB, checking mixer memory...")
                for leaf_idx, dep_info in mixer.deposits.items():
                    if dep_info.get("deposit_hash") == tx_hash:
                        encrypted_identity_hex = dep_info.get("encrypted_identity")
                        if encrypted_identity_hex:
                            encrypted_identity_bytes = (
                                bytes.fromhex(encrypted_identity_hex)
                                if isinstance(encrypted_identity_hex, str)
                                else encrypted_identity_hex
                            )
                            logger.info(f"Found encrypted identity in mixer memory")
                        break

            if not encrypted_identity_bytes:
                logger.warning(f"No encrypted identity found for: {tx_hash}")
                raise HTTPException(
                    status_code=404,
                    detail=f"Cannot audit transaction. Encrypted identity not found. Deposit may have been created before audit feature was enabled.",
                )

            logger.info(f"Attempting decryption with provided key...")

            # Decrypt identity
            from zkm.core.auditor import Auditor

            try:
                auditor = Auditor(private_key=auditor_key)
                decrypted_identity = auditor.decrypt_identity(encrypted_identity_bytes)
                logger.info(f"✓ Successfully decrypted identity: {decrypted_identity}")
            except Exception as decrypt_error:
                logger.error(f"Decryption failed: {str(decrypt_error)}")
                raise HTTPException(
                    status_code=422,
                    detail=f"Failed to decrypt. Invalid private key: {str(decrypt_error)}",
                )

            # Create audit result
            audit_result = type(
                "AuditResult",
                (),
                {
                    "transaction_hash": tx_hash,
                    "decrypted_identity": decrypted_identity,
                    "audit_timestamp": datetime.now(),
                },
            )()
        finally:
            session.close()

        # Store audit record with current user as auditor
        session = db.get_session()
        try:
            db.add_audit_record(
                session,
                audit_hash=audit_result.transaction_hash,
                transaction_hash=tx_hash,
                auditor_id=current_user.id,  # Track which admin audited this
                decrypted_identity=audit_result.decrypted_identity,
                auditor_note=request.auditor_note,
            )
            db.update_transaction_status(session, tx_hash, TransactionStatus.AUDITED)
            logger.info(f"✓ Audit record created for transaction: {tx_hash}")
        finally:
            session.close()

        return {
            "decrypted_identity": audit_result.decrypted_identity,
            "transaction_hash": audit_result.transaction_hash,
            "audited_by": current_user.username,
            "audit_timestamp": (
                audit_result.audit_timestamp.isoformat()
                if isinstance(audit_result.audit_timestamp, datetime)
                else audit_result.audit_timestamp
            ),
        }

    except HTTPException:
        # Re-raise HTTPException as-is (these are intentional API errors)
        raise
    except ValueError as e:
        logger.error(f"Audit validation error: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail=f"Invalid audit data: {str(e)}"
        )
    except KeyError as e:
        logger.error(f"Missing audit data: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail=f"Missing required audit information: {str(e)}"
        )
    except Exception as e:
        # Log the full exception for debugging
        logger.error(f"Unexpected error during audit of {request.transaction_hash}: {str(e)}", exc_info=True)
        # Provide detailed error message for debugging
        raise HTTPException(
            status_code=500,
            detail=f"Audit failed: {str(e)}"
        )


# ============================================================================
# Transaction History Endpoints
# ============================================================================
# Frontend Compatibility Endpoints
# ============================================================================


@app.get("/stats", tags=["Frontend"])
async def get_stats(db: DatabaseManager = Depends(get_db)):
    """
    Get dashboard statistics (frontend compatibility endpoint).
    Provides aggregated stats for the dashboard display.
    """
    session = db.get_session()
    try:
        transactions = db.get_recent_transactions(session, limit=10000)
        
        total_deposits = sum(1 for tx in transactions if tx.tx_type.value == "deposit")
        total_withdrawals = sum(1 for tx in transactions if tx.tx_type.value == "withdrawal")
        total_balance = sum(
            tx.amount for tx in transactions if tx.tx_type.value == "deposit"
        ) - sum(tx.amount for tx in transactions if tx.tx_type.value == "withdrawal")
        
        active_transactions = sum(
            1 for tx in transactions 
            if tx.status.value in ["pending", "processing"]
        )
        
        return {
            "total_balance": float(total_balance),
            "total_deposits": total_deposits,
            "total_withdrawals": total_withdrawals,
            "active_transactions": active_transactions,
            "total_transactions": len(transactions),
        }
    finally:
        session.close()


@app.get("/user/balance", tags=["Frontend"])
async def get_user_balance(
    current_user=Depends(get_current_user),
    db: DatabaseManager = Depends(get_db)
):
    """
    Get authenticated user's current balance.
    """
    session = db.get_session()
    try:
        balance = db.get_user_balance(session, current_user.id)
        return {
            "balance": float(balance),
            "user_id": current_user.id,
            "username": current_user.username
        }
    finally:
        session.close()


@app.get("/transactions/my", tags=["Frontend"])
async def get_my_transactions(
    current_user=Depends(get_current_user),
    limit: int = 20,
    db: DatabaseManager = Depends(get_db)
):
    """
    Get authenticated user's transactions (frontend compatibility endpoint).
    Returns only transactions belonging to the current user.
    """
    session = db.get_session()
    try:
        transactions = db.get_recent_transactions(session, limit=limit)
        
        # Filter to only user's transactions and add commitment data
        user_transactions = []
        for tx in transactions:
            if str(tx.user_id) == str(current_user.id):
                tx_dict = {
                    "id": tx.id,
                    "tx_hash": tx.transaction_hash,
                    "transaction_hash": tx.transaction_hash,
                    "type": tx.tx_type.value if hasattr(tx.tx_type, "value") else str(tx.tx_type),
                    "tx_type": tx.tx_type.value if hasattr(tx.tx_type, "value") else str(tx.tx_type),
                    "amount": float(tx.amount),
                    "status": tx.status.value if hasattr(tx.status, "value") else str(tx.status),
                    "timestamp": (
                        tx.timestamp.isoformat()
                        if isinstance(tx.timestamp, datetime)
                        else tx.timestamp
                    ),
                }
                
                # If this is a deposit, try to get the commitment
                if (tx.tx_type.value if hasattr(tx.tx_type, "value") else str(tx.tx_type)) == "deposit":
                    commitment = db.get_commitment_by_transaction(session, tx.transaction_hash)
                    if commitment and commitment.commitment_hash:
                        tx_dict["commitment"] = commitment.commitment_hash.hex()
                        
                user_transactions.append(tx_dict)
        
        return user_transactions
    finally:
        session.close()


# ============================================================================


@app.get("/transactions", response_model=TransactionListResponse, tags=["History"])
async def get_recent_transactions(limit: int = 10, db: DatabaseManager = Depends(get_db)):
    """Get recent transactions from ledger."""
    session = db.get_session()
    try:
        transactions = db.get_recent_transactions(session, limit=limit)
        count = db.get_transaction_count(session)

        # Build transaction list with commitment data
        transaction_list = []
        for tx in transactions:
            tx_dict = {
                "id": tx.id,
                "transaction_hash": tx.transaction_hash,
                "user_id": tx.user_id,
                "tx_type": (
                    tx.tx_type.value if hasattr(tx.tx_type, "value") else str(tx.tx_type)
                ),
                "amount": tx.amount,
                "status": tx.status.value if hasattr(tx.status, "value") else str(tx.status),
                "timestamp": (
                    tx.timestamp.isoformat()
                    if isinstance(tx.timestamp, datetime)
                    else tx.timestamp
                ),
            }
            
            # If this is a deposit, try to get the commitment
            if (tx.tx_type.value if hasattr(tx.tx_type, "value") else str(tx.tx_type)) == "deposit":
                commitment = db.get_commitment_by_transaction(session, tx.transaction_hash)
                if commitment and commitment.commitment_hash:
                    tx_dict["commitment"] = commitment.commitment_hash.hex()
                    
            transaction_list.append(tx_dict)

        return TransactionListResponse(
            transactions=transaction_list,
            total_count=count,
        )
    finally:
        session.close()


@app.get("/transactions/{transaction_hash}", tags=["History"])
async def get_transaction(transaction_hash: str, db: DatabaseManager = Depends(get_db)):
    """Get specific transaction details."""
    session = db.get_session()
    try:
        tx = mixer.get_transaction(transaction_hash)
        if not tx:
            raise HTTPException(status_code=404, detail="Transaction not found")

        return {
            "transaction_hash": transaction_hash,
            "tx_type": tx.get("type", "unknown"),
            "amount": tx.get("amount", 0),
            "status": tx.get("status", "unknown"),
            "timestamp": (
                tx["timestamp"].isoformat() if isinstance(tx.get("timestamp"), datetime) else str(tx.get("timestamp"))
            ),
        }
    finally:
        session.close()


# ============================================================================
# Error Handlers
# ============================================================================


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.detail,
            code="HTTP_ERROR",
        ).dict(),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions."""
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error=f"Internal server error: {str(exc)}",
            code="INTERNAL_ERROR",
        ).dict(),
    )


# ============================================================================
# Startup and Shutdown
# ============================================================================


@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    global mixer

    # Initialize database
    db = get_db_manager()
    db.create_tables()

    # Create default admin user if doesn't exist
    session = db.get_session()
    try:
        admin = db.get_user_by_username(session, "admin")
        if not admin:
            from zkm.security import hash_password

            hashed_pwd = hash_password("admin")
            db.create_user(session, "admin", hashed_pwd, UserRole.ADMIN, "admin@zkmixer.local")
            print("✓ Default admin user created (username: admin, password: admin)")
    finally:
        session.close()


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown."""
    pass


# ============================================================================
# Root Endpoint
# ============================================================================


@app.get("/", tags=["System"])
async def root():
    """API documentation root."""
    return {
        "name": "ZK-Mixer REST API",
        "version": "1.0.0",
        "description": "Privacy-preserving cryptocurrency mixer with regulatory compliance",
        "endpoints": {
            "health": "/health",
            "state": "/state",
            "statistics": "/statistics",
            "deposit": "POST /deposit",
            "withdraw": "POST /withdraw",
            "audit": "POST /audit",
            "transactions": "GET /transactions",
            "transaction": "GET /transactions/{hash}",
            "docs": "/docs",
            "openapi": "/openapi.json",
        },
    }


class DatabaseQueryRequest(BaseModel):
    """Database query request."""
    query: str = Field(..., description="SQL query to execute (SELECT only)")


class DatabaseQueryResponse(BaseModel):
    """Database query response."""
    results: List[dict] = Field(..., description="Query results")
    row_count: int = Field(..., description="Number of rows returned")


@app.post("/database/query", response_model=DatabaseQueryResponse, tags=["Admin"])
async def execute_database_query(
    request: DatabaseQueryRequest,
    db: DatabaseManager = Depends(get_db_manager)
):
    """Execute a read-only database query (admin only)."""
    # Validate query is read-only
    query = request.query.strip().upper()
    if not query.startswith('SELECT'):
        raise HTTPException(
            status_code=400,
            detail="Only SELECT queries are allowed"
        )
    
    # Prevent dangerous operations
    forbidden_keywords = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'ALTER', 'TRUNCATE', 'CREATE']
    if any(keyword in query for keyword in forbidden_keywords):
        raise HTTPException(
            status_code=400,
            detail="Query contains forbidden operations"
        )
    
    try:
        session = db.get_session()
        try:
            # Execute query using SQLAlchemy text()
            result = session.execute(text(request.query))

            def _serialize_value(value: Any) -> Any:
                if isinstance(value, (bytes, bytearray, memoryview)):
                    return bytes(value).hex()
                if isinstance(value, datetime):
                    return value.isoformat()
                if isinstance(value, Enum):
                    return value.value
                return value

            # Convert to list of dictionaries
            rows: List[dict] = []
            for row in result:
                # Handle both Row objects and tuples
                if hasattr(row, "_mapping"):
                    rows.append({k: _serialize_value(v) for k, v in row._mapping.items()})
                else:
                    # For simple tuples, create dict with column names
                    rows.append({col: _serialize_value(val) for col, val in zip(result.keys(), row)})

            return DatabaseQueryResponse(
                results=rows,
                row_count=len(rows)
            )
        finally:
            session.close()
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Query execution failed: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
