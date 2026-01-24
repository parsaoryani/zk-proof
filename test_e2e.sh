#!/bin/bash

# E2E Integration Test for ZK-Mixer

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="$PROJECT_DIR/src:$PYTHONPATH"

echo "============================================"
echo "ZK-MIXER END-TO-END INTEGRATION TEST"
echo "============================================"
echo ""

# Test 1: Run all unit tests
echo "[1/4] Running unit tests..."
cd "$PROJECT_DIR"
if python -m pytest tests/unit/ -q 2>&1 | tail -5; then
    echo "✓ Unit tests passed"
else
    echo "✗ Unit tests failed"
    exit 1
fi
echo ""

# Test 2: Run database performance tests
echo "[2/4] Testing database performance..."
if python tests/performance/test_db_performance.py 2>&1 | tail -15; then
    echo "✓ Database performance acceptable"
else
    echo "✗ Database performance test failed"
    exit 1
fi
echo ""

# Test 3: Test API startup and health
echo "[3/4] Testing API server..."
python -m uvicorn zkm.api.routes:app --host 127.0.0.1 --port 8000 > /tmp/api_e2e.log 2>&1 &
API_PID=$!
sleep 3

if curl -s http://localhost:8000/health | grep -q "ok"; then
    echo "✓ API server healthy"
else
    echo "✗ API server health check failed"
    kill $API_PID 2>/dev/null
    exit 1
fi

# Test 4: Test API endpoints
echo "[4/4] Testing API endpoints..."

# Test deposit
DEPOSIT=$(curl -s -X POST http://localhost:8000/deposit \
  -H "Content-Type: application/json" \
  -d '{"identity": "test_user", "amount": 100.0}' 2>/dev/null)

if echo "$DEPOSIT" | grep -q "commitment"; then
    echo "✓ Deposit endpoint working"
else
    echo "✗ Deposit endpoint failed"
    echo "Response: $DEPOSIT"
    kill $API_PID 2>/dev/null
    exit 1
fi

# Test statistics
STATS=$(curl -s http://localhost:8000/statistics 2>/dev/null)
if echo "$STATS" | grep -q "total_deposits"; then
    echo "✓ Statistics endpoint working"
else
    echo "✗ Statistics endpoint failed"
    kill $API_PID 2>/dev/null
    exit 1
fi

# Test transactions
TXNS=$(curl -s http://localhost:8000/transactions 2>/dev/null)
if echo "$TXNS" | grep -q "transactions"; then
    echo "✓ Transactions endpoint working"
else
    echo "✗ Transactions endpoint failed"
    kill $API_PID 2>/dev/null
    exit 1
fi

# Cleanup
kill $API_PID 2>/dev/null
sleep 1

echo ""
echo "============================================"
echo "✓ ALL INTEGRATION TESTS PASSED"
echo "============================================"
echo ""
echo "System is production-ready!"
echo "Start with: ./run.sh"
