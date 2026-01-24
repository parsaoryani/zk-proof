"""Tests for REST API endpoints."""

import pytest
from fastapi.testclient import TestClient
import os
import tempfile

from zkm.api.routes import app
from zkm.storage import reset_db_manager, get_db_manager


@pytest.fixture
def client():
    """Create test client."""
    # Reset database for tests
    reset_db_manager()
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db_url = f"sqlite:///{path}"
    get_db_manager(db_url)
    
    yield TestClient(app)
    
    # Cleanup
    if os.path.exists(path):
        os.unlink(path)


class TestHealthEndpoints:
    """Test health and system endpoints."""
    
    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "operational"
    
    def test_root_endpoint(self, client):
        """Test root endpoint."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "endpoints" in data
        assert "version" in data
    
    def test_state_endpoint(self, client):
        """Test get state endpoint."""
        response = client.get("/state")
        assert response.status_code == 200
        data = response.json()
        assert "num_commitments" in data
        assert "num_nullifiers" in data
        assert "merkle_root" in data
    
    def test_statistics_endpoint(self, client):
        """Test statistics endpoint."""
        response = client.get("/statistics")
        assert response.status_code == 200
        data = response.json()
        assert "total_deposits" in data
        assert "total_withdrawals" in data
        assert "total_volume" in data


class TestDepositEndpoint:
    """Test deposit endpoint."""
    
    def test_valid_deposit(self, client):
        """Test valid deposit."""
        payload = {
            "identity": "alice@example.com",
            "amount": 1000.0,
        }
        response = client.post("/deposit", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "commitment" in data
        assert "commitment_index" in data
        assert "merkle_root" in data
        assert "deposit_hash" in data
    
    def test_invalid_amount(self, client):
        """Test deposit with invalid amount."""
        payload = {
            "identity": "bob@example.com",
            "amount": -100.0,
        }
        response = client.post("/deposit", json=payload)
        assert response.status_code == 400
    
    def test_zero_amount(self, client):
        """Test deposit with zero amount."""
        payload = {
            "identity": "charlie@example.com",
            "amount": 0.0,
        }
        response = client.post("/deposit", json=payload)
        assert response.status_code == 400
    
    def test_multiple_deposits(self, client):
        """Test multiple deposits."""
        for i in range(5):
            payload = {
                "identity": f"user{i}@example.com",
                "amount": 1000.0,
            }
            response = client.post("/deposit", json=payload)
            assert response.status_code == 200
        
        # Check state shows 5 commitments
        state_response = client.get("/state")
        assert state_response.status_code == 200
        state = state_response.json()
        assert state["num_commitments"] == 5


class TestWithdrawalEndpoint:
    """Test withdrawal endpoint."""
    
    def test_withdrawal_requires_proof(self, client):
        """Test that withdrawal requires valid proof."""
        payload = {
            "nullifier": "00" * 32,
            "merkle_path": ["00" * 32] * 8,
            "leaf_index": 0,
            "identity_encryption_proof": "00" * 32,
            "encrypted_identity": "00" * 256,
            "proof_hash": "00" * 32,
        }
        response = client.post("/withdraw", json=payload)
        # Should fail because proof is invalid
        assert response.status_code in [400, 500]


class TestAuditEndpoint:
    """Test audit endpoint."""
    
    def test_audit_requires_key(self, client):
        """Test that audit requires auditor key."""
        # First create a deposit
        deposit_payload = {
            "identity": "alice@example.com",
            "amount": 1000.0,
        }
        deposit_response = client.post("/deposit", json=deposit_payload)
        assert deposit_response.status_code == 200
        deposit_data = deposit_response.json()
        
        # Try to audit without proper key
        audit_payload = {
            "transaction_hash": deposit_data["deposit_hash"],
            "auditor_private_key": "invalid_key",
        }
        response = client.post("/audit", json=audit_payload)
        # Should fail with invalid key
        assert response.status_code == 400


class TestTransactionHistoryEndpoints:
    """Test transaction history endpoints."""
    
    def test_get_transactions(self, client):
        """Test getting transaction list."""
        response = client.get("/transactions")
        assert response.status_code == 200
        data = response.json()
        assert "transactions" in data
        assert "total_count" in data
    
    def test_get_transactions_with_limit(self, client):
        """Test getting limited transactions."""
        # Create some deposits
        for i in range(5):
            payload = {
                "identity": f"user{i}@example.com",
                "amount": 1000.0,
            }
            client.post("/deposit", json=payload)
        
        # Get with limit
        response = client.get("/transactions?limit=3")
        assert response.status_code == 200
        data = response.json()
        assert len(data["transactions"]) <= 3
        assert data["total_count"] >= 3
    
    def test_get_specific_transaction(self, client):
        """Test getting specific transaction."""
        # Create a deposit
        payload = {
            "identity": "alice@example.com",
            "amount": 1000.0,
        }
        deposit_response = client.post("/deposit", json=payload)
        assert deposit_response.status_code == 200
        deposit_data = deposit_response.json()
        
        # Get specific transaction
        response = client.get(f"/transactions/{deposit_data['deposit_hash']}")
        assert response.status_code == 200
        data = response.json()
        assert data["transaction_hash"] == deposit_data["deposit_hash"]
    
    def test_get_nonexistent_transaction(self, client):
        """Test getting nonexistent transaction."""
        response = client.get("/transactions/nonexistent")
        assert response.status_code == 404


class TestErrorHandling:
    """Test error handling."""
    
    def test_invalid_endpoint(self, client):
        """Test invalid endpoint."""
        response = client.get("/invalid/endpoint")
        assert response.status_code == 404
    
    def test_invalid_json(self, client):
        """Test invalid JSON in request."""
        response = client.post("/deposit", json={"invalid": "data"})
        assert response.status_code == 422  # Validation error


class TestAPIWorkflow:
    """Test complete API workflow."""
    
    def test_full_workflow(self, client):
        """Test complete deposit workflow."""
        # 1. Check initial state
        state = client.get("/state").json()
        assert state["num_commitments"] == 0
        
        # 2. Create deposit
        deposit_payload = {
            "identity": "alice@example.com",
            "amount": 1000.0,
        }
        deposit_response = client.post("/deposit", json=deposit_payload)
        assert deposit_response.status_code == 200
        deposit = deposit_response.json()
        
        # 3. Check state updated
        state = client.get("/state").json()
        assert state["num_commitments"] == 1
        
        # 4. Check statistics
        stats = client.get("/statistics").json()
        assert stats["total_deposits"] == 1
        assert stats["total_volume"] == 1000.0
        
        # 5. Get transaction
        tx = client.get(f"/transactions/{deposit['deposit_hash']}").json()
        assert tx["type"] == "deposit"
        assert tx["amount"] == 1000.0
