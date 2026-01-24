"""Pytest configuration and fixtures."""

import pytest
import sys
from pathlib import Path

# Add src to path for imports
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


@pytest.fixture
def temp_db(tmp_path):
    """Fixture providing a temporary database path."""
    return tmp_path / "test.db"


@pytest.fixture(scope="session")
def test_data():
    """Fixture providing test data."""
    return {
        "sample_identity": "test@example.com",
        "sample_amount": 1000,
        "sample_tree_height": 8,
    }
