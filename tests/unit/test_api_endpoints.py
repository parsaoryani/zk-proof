"""Unit tests for API endpoints."""

import sys
import pytest
from pathlib import Path
import uuid
import os
import tempfile

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from fastapi.testclient import TestClient
from zkm.api.routes import app
from zkm.storage import reset_db_manager, get_db_manager


class TestHealthEndpoints:
    """Test health and status endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        reset_db_manager()
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db_url = f"sqlite:///{path}"
        get_db_manager(db_url)

        yield TestClient(app)

        if os.path.exists(path):
            os.unlink(path)
        reset_db_manager()

    def test_health_check(self, client):
        """Test health endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "operational"

    def test_state_endpoint(self, client):
        """Test state endpoint."""
        response = client.get("/state")
        assert response.status_code == 200
        data = response.json()
        assert "merkle_root" in data
        assert "num_commitments" in data

    def test_statistics_endpoint(self, client):
        """Test statistics endpoint."""
        response = client.get("/statistics")
        assert response.status_code == 200
        data = response.json()
        assert "total_deposits" in data
        assert "total_withdrawals" in data
        assert "total_volume" in data
        assert "total_balance" in data  # New: total system balance
        assert "user_balance" in data  # New: current user's balance


class TestDepositEndpoint:
    """Test deposit endpoint."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        reset_db_manager()
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db_url = f"sqlite:///{path}"
        get_db_manager(db_url)

        yield TestClient(app)

        if os.path.exists(path):
            os.unlink(path)
        reset_db_manager()

    def test_valid_deposit(self, client):
        """Test valid deposit."""
        response = client.post(
            "/deposit", json={"identity": "user@example.com", "amount": 100}
        )
        assert response.status_code == 200
        data = response.json()
        assert "deposit_hash" in data
        assert "commitment" in data
        assert "merkle_root" in data
        assert data["commitment_index"] >= 0

    def test_invalid_amount_zero(self, client):
        """Test deposit with zero amount."""
        response = client.post(
            "/deposit", json={"identity": "user@example.com", "amount": 0}
        )
        assert response.status_code == 400
        assert "amount" in response.json()["detail"].lower()

    def test_invalid_amount_negative(self, client):
        """Test deposit with negative amount."""
        response = client.post(
            "/deposit", json={"identity": "user@example.com", "amount": -100}
        )
        assert response.status_code == 400
        assert "amount" in response.json()["detail"].lower()

    def test_missing_identity(self, client):
        """Test deposit without identity."""
        response = client.post("/deposit", json={"amount": 100})
        assert response.status_code == 400

    def test_missing_amount(self, client):
        """Test deposit without amount."""
        response = client.post("/deposit", json={"identity": "user@example.com"})
        assert response.status_code == 400


class TestTransactionEndpoints:
    """Test transaction retrieval endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        reset_db_manager()
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db_url = f"sqlite:///{path}"
        get_db_manager(db_url)

        yield TestClient(app)

        if os.path.exists(path):
            os.unlink(path)
        reset_db_manager()

    def test_get_recent_transactions(self, client):
        """Test getting recent transactions."""
        response = client.get("/transactions")
        assert response.status_code == 200
        data = response.json()
        assert "transactions" in data
        assert "total_count" in data
        assert isinstance(data["transactions"], list)

    def test_get_transactions_with_limit(self, client):
        """Test getting transactions with limit."""
        # First create some transactions
        for i in range(3):
            client.post(
                "/deposit",
                json={"identity": f"user{i}@example.com", "amount": 50 + i},
            )

        response = client.get("/transactions?limit=2")
        assert response.status_code == 200
        data = response.json()
        assert len(data["transactions"]) <= 2

    def test_get_specific_transaction(self, client):
        """Test getting specific transaction."""
        # Create a deposit first
        deposit_resp = client.post(
            "/deposit", json={"identity": "user@example.com", "amount": 100}
        )
        deposit_hash = deposit_resp.json()["deposit_hash"]

        # Get specific transaction
        response = client.get(f"/transactions/{deposit_hash}")
        assert response.status_code == 200
        data = response.json()
        assert data["transaction_hash"] == deposit_hash
        assert data["tx_type"] == "deposit"
        assert data["amount"] == 100

    def test_get_nonexistent_transaction(self, client):
        """Test getting nonexistent transaction."""
        response = client.get("/transactions/nonexistent-hash")
        assert response.status_code in [404, 400]


class TestAuthEndpoints:
    """Test authentication endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        reset_db_manager()
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db_url = f"sqlite:///{path}"
        get_db_manager(db_url)

        yield TestClient(app)

        if os.path.exists(path):
            os.unlink(path)
        reset_db_manager()

    def test_register_new_user(self, client):
        """Test user registration."""
        username = f"newuser_{uuid.uuid4().hex[:8]}"
        response = client.post(
            "/auth/register",
            json={"username": username, "password": "password123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "user_id" in data
        assert data["username"] == username
        assert data["role"] == "user"

    def test_register_with_email(self, client):
        """Test registration with email."""
        username = f"emailuser_{uuid.uuid4().hex[:8]}"
        email = f"test_{uuid.uuid4().hex[:8]}@example.com"
        response = client.post(
            "/auth/register",
            json={
                "username": username,
                "password": "password123",
                "email": email,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == username

    def test_register_duplicate_username(self, client):
        """Test duplicate username registration."""
        # First registration
        client.post(
            "/auth/register",
            json={"username": "duplicateuser", "password": "password123"},
        )

        # Second registration with same username
        response = client.post(
            "/auth/register",
            json={"username": "duplicateuser", "password": "password456"},
        )
        assert response.status_code == 400

    def test_register_missing_username(self, client):
        """Test registration without username."""
        response = client.post(
            "/auth/register", json={"password": "password123"}
        )
        assert response.status_code == 400

    def test_register_missing_password(self, client):
        """Test registration without password."""
        response = client.post(
            "/auth/register", json={"username": "testuser"}
        )
        assert response.status_code == 400

    def test_register_empty_username(self, client):
        """Test registration with empty username."""
        response = client.post(
            "/auth/register",
            json={"username": "", "password": "password123"},
        )
        assert response.status_code == 400

    def test_register_empty_password(self, client):
        """Test registration with empty password."""
        response = client.post(
            "/auth/register",
            json={"username": "testuser", "password": ""},
        )
        assert response.status_code == 400

    def test_login_successful(self, client):
        """Test successful login."""
        # Register first
        client.post(
            "/auth/register",
            json={"username": "loginuser", "password": "password123"},
        )

        # Login
        response = client.post(
            "/auth/login",
            json={"username": "loginuser", "password": "password123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["username"] == "loginuser"
        assert "expires_in" in data

    def test_login_invalid_username(self, client):
        """Test login with invalid username."""
        response = client.post(
            "/auth/login",
            json={"username": "nonexistent", "password": "password123"},
        )
        assert response.status_code == 401

    def test_login_invalid_password(self, client):
        """Test login with invalid password."""
        # Register first
        client.post(
            "/auth/register",
            json={"username": "wrongpassuser", "password": "correctpass"},
        )

        # Login with wrong password
        response = client.post(
            "/auth/login",
            json={"username": "wrongpassuser", "password": "wrongpass"},
        )
        assert response.status_code == 401


class TestWithdrawalEndpoint:
    """Test withdrawal endpoint."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        reset_db_manager()
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db_url = f"sqlite:///{path}"
        get_db_manager(db_url)

        yield TestClient(app)

        if os.path.exists(path):
            os.unlink(path)
        reset_db_manager()

    def test_withdrawal_missing_nullifier(self, client):
        """Test withdrawal without nullifier."""
        response = client.post(
            "/withdraw",
            json={
                "merkle_path": ["hash1", "hash2"],
                "leaf_index": 0,
                "identity_encryption_proof": "proof",
                "encrypted_identity": "identity",
                "timestamp": "2026-02-05T00:00:00",
            },
        )
        assert response.status_code == 400

    def test_withdrawal_missing_merkle_path(self, client):
        """Test withdrawal without merkle path."""
        response = client.post(
            "/withdraw",
            json={
                "nullifier": "hash",
                "leaf_index": 0,
                "identity_encryption_proof": "proof",
                "encrypted_identity": "identity",
                "timestamp": "2026-02-05T00:00:00",
            },
        )
        assert response.status_code == 400
