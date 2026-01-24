"""Database performance tests to verify acceptable transaction throughput."""
import time
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from zkm.storage.database import DatabaseManager, TransactionType, TransactionStatus


def get_test_db(test_name: str) -> DatabaseManager:
    """Create a test database with unique path."""
    db_path = f"sqlite:////tmp/zkm_perf_{test_name}_{int(time.time()*1000)}.db"
    db = DatabaseManager(db_path)
    db.create_tables()
    return db


def test_transaction_write_performance():
    """Test bulk write performance."""
    db = get_test_db("write")
    session = db.get_session()
    
    # Test writing 1000 transactions
    start = time.time()
    for i in range(1000):
        db.add_transaction(
            session,
            transaction_hash=f"tx_hash_{i:04d}",
            tx_type=TransactionType.DEPOSIT,
            amount=100 + i,
            status=TransactionStatus.CONFIRMED,
        )
    write_time = time.time() - start
    session.close()
    
    tps_write = 1000 / write_time
    print(f"✓ Write Performance: {tps_write:.1f} tx/s ({1000} transactions in {write_time:.2f}s)")
    assert tps_write > 100, f"Write throughput too low: {tps_write:.1f} tx/s"
    return tps_write


def test_transaction_read_performance():
    """Test bulk read performance."""
    db = get_test_db("read")
    session = db.get_session()
    
    # Setup: insert 1000 transactions
    for i in range(1000):
        db.add_transaction(
            session,
            transaction_hash=f"tx_hash_{i:04d}",
            tx_type=TransactionType.DEPOSIT,
            amount=100 + i,
            status=TransactionStatus.CONFIRMED,
        )
    session.commit()
    
    # Test reading 1000 transactions
    start = time.time()
    for i in range(1000):
        db.get_transaction(session, f"tx_hash_{i:04d}")
    read_time = time.time() - start
    session.close()
    
    tps_read = 1000 / read_time
    print(f"✓ Read Performance: {tps_read:.1f} queries/s ({1000} queries in {read_time:.2f}s)")
    assert tps_read > 500, f"Read throughput too low: {tps_read:.1f} queries/s"
    return tps_read


def test_commitment_operations_performance():
    """Test commitment storage and retrieval performance."""
    db = get_test_db("commitment")
    session = db.get_session()
    
    # Test adding commitments
    start = time.time()
    for i in range(500):
        db.add_commitment(
            session,
            commitment_hash=f"commitment_{i:04d}".encode().ljust(32, b'\x00')[:32],
            commitment_index=i,
            transaction_hash=f"tx_{i:04d}",
            merkle_root=f"root_{i}".encode().ljust(32, b'\x00')[:32],
            encrypted_secret=f"secret_{i}".encode(),
            encrypted_randomness=f"rand_{i}".encode(),
            amount=100.0 + i,
        )
    session.commit()
    add_time = time.time() - start
    
    # Test retrieving commitments by index
    start = time.time()
    for i in range(500):
        db.get_commitment_by_index(session, i)
    get_time = time.time() - start
    
    session.close()
    
    add_throughput = 500 / add_time
    get_throughput = 500 / get_time
    print(f"✓ Commitment Add: {add_throughput:.1f} ops/s")
    print(f"✓ Commitment Get: {get_throughput:.1f} ops/s")
    assert add_throughput > 100, f"Commitment add throughput too low: {add_throughput:.1f} ops/s"
    return (add_throughput, get_throughput)


def test_aggregate_query_performance():
    """Test aggregate query performance."""
    db = get_test_db("aggregate")
    session = db.get_session()
    
    # Setup: insert transactions with different volumes
    for i in range(200):
        db.add_transaction(
            session,
            transaction_hash=f"tx_hash_{i:04d}",
            tx_type=TransactionType.DEPOSIT if i % 2 == 0 else TransactionType.WITHDRAWAL,
            amount=100 + i * 10,
            status=TransactionStatus.CONFIRMED,
        )
    session.commit()
    
    # Test aggregate queries (should be fast)
    start = time.time()
    for _ in range(100):
        db.get_total_volume(session)
    volume_time = time.time() - start
    
    start = time.time()
    for _ in range(100):
        db.get_transaction_count(session)
    count_time = time.time() - start
    
    start = time.time()
    for _ in range(100):
        db.get_recent_transactions(session, limit=50)
    recent_time = time.time() - start
    
    session.close()
    
    volume_qps = 100 / volume_time
    count_qps = 100 / count_time
    recent_qps = 100 / recent_time
    
    print(f"✓ Total Volume Query: {volume_qps:.1f} q/s")
    print(f"✓ Transaction Count Query: {count_qps:.1f} q/s")
    print(f"✓ Recent Transactions Query: {recent_qps:.1f} q/s")
    
    return (volume_qps, count_qps, recent_qps)


def main():
    """Run all performance tests."""
    print("\n" + "="*60)
    print("ZK-MIXER DATABASE PERFORMANCE TESTS")
    print("="*60 + "\n")
    
    results = {}
    
    print("Testing Write Performance...")
    results['write_tps'] = test_transaction_write_performance()
    print()
    
    print("Testing Read Performance...")
    results['read_qps'] = test_transaction_read_performance()
    print()
    
    print("Testing Commitment Operations...")
    commitment_perf = test_commitment_operations_performance()
    results['commitment_add_ops'] = commitment_perf[0]
    results['commitment_get_ops'] = commitment_perf[1]
    print()
    
    print("Testing Aggregate Queries...")
    aggregate_perf = test_aggregate_query_performance()
    results['volume_query_qps'] = aggregate_perf[0]
    results['count_query_qps'] = aggregate_perf[1]
    results['recent_query_qps'] = aggregate_perf[2]
    print()
    
    print("="*60)
    print("PERFORMANCE SUMMARY")
    print("="*60)
    print(f"Write Throughput:          {results['write_tps']:.1f} tx/s")
    print(f"Read Throughput:           {results['read_qps']:.1f} queries/s")
    print(f"Commitment Add:            {results['commitment_add_ops']:.1f} ops/s")
    print(f"Commitment Get:            {results['commitment_get_ops']:.1f} ops/s")
    print(f"Aggregate Queries:         {results['volume_query_qps']:.1f}+ queries/s")
    print("="*60)
    print("✅ All performance tests PASSED")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
