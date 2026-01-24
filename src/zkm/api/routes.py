"""REST API endpoints for ZK-Mixer system."""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

from zkm.core.mixer import ZKMixer
from zkm.core.zkproof import WithdrawalProof
from zkm.storage import DatabaseManager, get_db_manager
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


# Global mixer instance
mixer = ZKMixer(merkle_tree_height=32)


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(..., description="Service status")
    timestamp: datetime = Field(default_factory=datetime.now)
    version: str = "1.0.0"


class TransactionListResponse(BaseModel):
    """List of recent transactions."""
    transactions: List[dict] = Field(..., description="Recent transactions")
    total_count: int = Field(..., description="Total transaction count")


class ErrorResponse(BaseModel):
    """Error response."""
    error: str = Field(..., description="Error message")
    code: str = Field(..., description="Error code")
    timestamp: datetime = Field(default_factory=datetime.now)


# Initialize FastAPI
app = FastAPI(
    title="ZK-Mixer REST API",
    description="Privacy-preserving cryptocurrency mixer with regulatory compliance",
    version="1.0.0",
)


# Dependency for database
def get_db() -> DatabaseManager:
    """Get database manager."""
    return get_db_manager()


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
async def get_statistics():
    """Get mixer statistics."""
    stats = mixer.get_statistics()
    return {
        "total_deposits": stats.get("total_deposits", 0),
        "total_withdrawals": stats.get("total_withdrawals", 0),
        "total_volume": stats.get("total_volume", 0.0),
        "num_commitments": stats.get("num_commitments", 0),
        "num_nullifiers": stats.get("num_nullifiers", 0),
        "audited_transactions": stats.get("audited_transactions", 0),
        "uptime_hours": stats.get("uptime_hours", 0),
        "merkle_root": stats.get("merkle_root", ""),
    }


# ============================================================================
# Deposit Endpoints
# ============================================================================

@app.post("/deposit", tags=["Deposit"])
async def deposit(request: DepositRequest, db: DatabaseManager = Depends(get_db)):
    """
    Create a private deposit.
    
    - **identity**: User identifier (email)
    - **amount**: Deposit amount in currency units
    
    Returns deposit receipt with commitment and merkle root.
    """
    try:
        if request.amount <= 0:
            raise HTTPException(status_code=400, detail="Amount must be positive")
        
        # Create deposit
        receipt = mixer.deposit(request.identity, request.amount)
        
        # Store in database
        session = db.get_session()
        try:
            db.add_transaction(
                session,
                transaction_hash=receipt.deposit_hash,
                tx_type="deposit",
                amount=request.amount,
                status="confirmed"
            )
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
async def withdraw(request: WithdrawalRequest, db: DatabaseManager = Depends(get_db)):
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
        # Reconstruct proof from request
        proof = WithdrawalProof(
            nullifier=bytes.fromhex(request.nullifier),
            merkle_path=[bytes.fromhex(h) for h in request.merkle_path],
            leaf_index=request.leaf_index,
            identity_encryption_proof=bytes.fromhex(request.identity_encryption_proof),
            encrypted_identity=bytes.fromhex(request.encrypted_identity),
            timestamp=request.timestamp,
            proof_hash=bytes.fromhex(request.proof_hash),
        )
        
        # Process withdrawal
        receipt = mixer.withdraw(proof)
        
        # Store in database
        session = db.get_session()
        try:
            db.add_transaction(
                session,
                transaction_hash=receipt.transaction_hash,
                tx_type="withdrawal",
                amount=0.0,  # Don't store amount for privacy
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
# Audit Endpoints (Restricted)
# ============================================================================

@app.post("/audit", tags=["Audit"])
async def audit_transaction(request: AuditRequest, db: DatabaseManager = Depends(get_db)):
    """
    Audit specific transaction (regulatory compliance).
    
    Requires auditor private key. Decrypts identity for compliance review.
    
    - **transaction_hash**: Transaction to audit
    - **auditor_private_key**: RSA private key (PEM format)
    
    Returns decrypted identity (audit only!).
    """
    try:
        if not request.auditor_private_key:
            raise HTTPException(status_code=403, detail="Auditor key required")
        
        # Perform audit
        auditor_key = request.auditor_private_key.encode() if isinstance(request.auditor_private_key, str) else request.auditor_private_key
        audit_result = mixer.audit_transaction(request.transaction_hash, auditor_key)
        
        # Store audit record
        session = db.get_session()
        try:
            db.add_audit_record(
                session,
                audit_hash=audit_result.transaction_hash,
                transaction_hash=request.transaction_hash,
                decrypted_identity=audit_result.decrypted_identity,
                auditor_note=request.auditor_note,
            )
            db.update_transaction_status(session, request.transaction_hash, "audited")
        finally:
            session.close()
        
        return {
            "decrypted_identity": audit_result.decrypted_identity,
            "transaction_hash": audit_result.transaction_hash,
            "audit_timestamp": audit_result.audit_timestamp.isoformat() if isinstance(audit_result.audit_timestamp, datetime) else audit_result.audit_timestamp,
        }
    
    except Exception as e:
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
                    "transaction_hash": tx.transaction_hash,
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
    db = get_db_manager()
    db.create_tables()


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
