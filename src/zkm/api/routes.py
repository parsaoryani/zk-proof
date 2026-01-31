"""REST API endpoints for ZK-Mixer system."""

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

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


# Add CORS middleware to allow frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (can be restricted to specific domains in production)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Dependency for database
def get_db() -> DatabaseManager:
    """Get database manager."""
    return get_db_manager()


async def get_current_user(authorization: Optional[str] = Header(None), db: DatabaseManager = Depends(get_db)):
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


async def require_admin(current_user = Depends(get_current_user)):
    """Require admin role."""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


async def require_admin_or_moderator(current_user = Depends(get_current_user)):
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
async def get_statistics(db: DatabaseManager = Depends(get_db)):
    """Get mixer statistics from database."""
    session = db.get_session()
    try:
        # Get statistics from DATABASE, not memory
        transactions = db.get_recent_transactions(session, limit=10000)  # Get all
        
        total_deposits = sum(1 for tx in transactions if tx.tx_type.value == "deposit")
        total_withdrawals = sum(1 for tx in transactions if tx.tx_type.value == "withdrawal")
        total_volume = sum(tx.amount for tx in transactions if tx.tx_type.value == "deposit")
        
        # Get mixer in-memory stats for other data
        mixer_stats = mixer.get_statistics()
        
        return {
            "total_deposits": total_deposits,
            "total_withdrawals": total_withdrawals,
            "total_volume": float(total_volume),
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
async def deposit(request: DepositRequest, authorization: Optional[str] = Header(None), db: DatabaseManager = Depends(get_db)):
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
                amount=request.amount,
                user_id=user_id,
                status="confirmed"
            )
            
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
                        encrypted_secret=b'',  # Not used for now
                        encrypted_randomness=b'',  # Not used for now
                        amount=request.amount,
                        encrypted_identity=encrypted_identity
                    )
            except Exception as e:
                # Log but don't fail the deposit if commitment storage fails
                import logging
                logging.getLogger(__name__).warning(f"Failed to store commitment: {e}")
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
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Deposit failed: {str(e)}")


# ============================================================================
# Withdrawal Endpoints
# ============================================================================

@app.post("/withdraw", tags=["Withdrawal"])
async def withdraw(request: WithdrawalRequest, authorization: Optional[str] = Header(None), db: DatabaseManager = Depends(get_db)):
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
            request.leaf_index.to_bytes(8, 'big'),
            identity_encryption_proof,
            encrypted_identity,
            request.timestamp.isoformat().encode('utf-8')
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
        withdrawal_amount = request.withdrawal_amount or 0
        
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
                status="confirmed"
            )
        finally:
            session.close()
        
        return {
            "transaction_hash": receipt.transaction_hash,
            "status": receipt.status,
            "timestamp": receipt.timestamp.isoformat() if isinstance(receipt.timestamp, datetime) else receipt.timestamp,
        }
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Withdrawal failed: {str(e)}")


# ============================================================================
# Admin Endpoints
# ============================================================================

@app.get("/admin/auditor-key", tags=["Admin"])
async def get_auditor_key(current_user = Depends(require_admin)):
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
        private_key_str = private_key_pem.decode() if isinstance(private_key_pem, bytes) else private_key_pem
        public_key_str = public_key_pem.decode() if isinstance(public_key_pem, bytes) else public_key_pem
        
        return {
            "auditor_private_key": private_key_str,
            "auditor_public_key": public_key_str,
            "note": "Keep the private key secure. This key is required to decrypt deposit identities.",
            "admin": current_user.username,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve auditor key: {str(e)}")


# ============================================================================
# Audit Endpoints (Restricted)
# ============================================================================

@app.post("/audit", tags=["Audit"])
async def audit_transaction(request: AuditRequest, db: DatabaseManager = Depends(get_db), 
                           current_user = Depends(require_admin_or_moderator)):
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
                raise HTTPException(status_code=404, detail=f"Transaction not found: {tx_hash}. Check transaction hash format.")
            
            logger.info(f"Found transaction: type={db_tx.tx_type.value}, status={db_tx.status.value if hasattr(db_tx.status, 'value') else db_tx.status}")
            
            # Validate it's a DEPOSIT transaction (case-insensitive)
            tx_type_value = db_tx.tx_type.value if hasattr(db_tx.tx_type, 'value') else str(db_tx.tx_type)
            if tx_type_value.lower() != "deposit":
                logger.warning(f"Attempted audit on non-deposit: {tx_type_value}")
                raise HTTPException(
                    status_code=400, 
                    detail=f"Cannot audit {tx_type_value} transaction. Only DEPOSIT transactions can be audited."
                )
            
            logger.info(f"Found transaction in DB: type={db_tx.tx_type.value}, status={db_tx.status.value if hasattr(db_tx.status, 'value') else db_tx.status}")
            
            # Validate it's a DEPOSIT transaction (case-insensitive)
            tx_type_value = db_tx.tx_type.value if hasattr(db_tx.tx_type, 'value') else str(db_tx.tx_type)
            if tx_type_value.lower() != "deposit":
                logger.warning(f"Attempted audit on non-deposit transaction: {tx_type_value}")
                raise HTTPException(
                    status_code=400, 
                    detail=f"Cannot audit {tx_type_value} transaction. Only DEPOSIT transactions can be audited."
                )
        finally:
            session.close()
        
        # Perform audit
        auditor_key = request.auditor_private_key.encode() if isinstance(request.auditor_private_key, str) else request.auditor_private_key
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
                            encrypted_identity_bytes = bytes.fromhex(encrypted_identity_hex) if isinstance(encrypted_identity_hex, str) else encrypted_identity_hex
                            logger.info(f"Found encrypted identity in mixer memory")
                        break
            
            if not encrypted_identity_bytes:
                logger.warning(f"No encrypted identity found for: {tx_hash}")
                raise HTTPException(
                    status_code=404, 
                    detail=f"Cannot audit transaction. Encrypted identity not found. Deposit may have been created before audit feature was enabled."
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
                    detail=f"Failed to decrypt. Invalid private key: {str(decrypt_error)}"
                )
            
            # Create audit result
            audit_result = type('AuditResult', (), {
                'transaction_hash': tx_hash,
                'decrypted_identity': decrypted_identity,
                'audit_timestamp': datetime.now(),
            })()
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
            "audit_timestamp": audit_result.audit_timestamp.isoformat() if isinstance(audit_result.audit_timestamp, datetime) else audit_result.audit_timestamp,
        }
    
    except HTTPException:
        raise
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Audit failed for {request.transaction_hash}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=400, detail=f"Audit failed: {str(e)}")


# ============================================================================
# Transaction History Endpoints
# ============================================================================

@app.get("/transactions", response_model=TransactionListResponse, tags=["History"])
async def get_recent_transactions(limit: int = 10, db: DatabaseManager = Depends(get_db)):
    """Get recent transactions from ledger."""
    session = db.get_session()
    try:
        transactions = db.get_recent_transactions(session, limit=limit)
        count = db.get_transaction_count(session)
        
        return TransactionListResponse(
            transactions=[
                {
                    "id": tx.id,
                    "transaction_hash": tx.transaction_hash,
                    "user_id": tx.user_id,
                    "tx_type": tx.tx_type.value if hasattr(tx.tx_type, 'value') else str(tx.tx_type),
                    "amount": tx.amount,
                    "status": tx.status.value if hasattr(tx.status, 'value') else str(tx.status),
                    "timestamp": tx.timestamp.isoformat() if isinstance(tx.timestamp, datetime) else tx.timestamp,
                }
                for tx in transactions
            ],
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
            "transaction_hash": tx.transaction_hash,
            "tx_type": tx.tx_type.value if hasattr(tx.tx_type, 'value') else str(tx.tx_type),
            "amount": tx.amount,
            "status": tx.status.value if hasattr(tx.status, 'value') else str(tx.status),
            "timestamp": tx.timestamp.isoformat() if isinstance(tx.timestamp, datetime) else tx.timestamp,
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
    
    # Register auth routes
    from zkm.api.auth_routes import register_auth_routes
    register_auth_routes(app)
    
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
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
