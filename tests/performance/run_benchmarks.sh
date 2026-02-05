#!/bin/bash
# ZK-Mixer Performance Benchmark Suite
# =====================================
# This script runs all performance benchmarks and generates a report.
#
# Usage:
#   ./run_benchmarks.sh              # Run all benchmarks
#   ./run_benchmarks.sh --crypto     # Run only cryptographic benchmarks
#   ./run_benchmarks.sh --db         # Run only database benchmarks
#
# Requirements:
#   - Python 3.9+ with virtual environment activated
#   - pytest and pytest-benchmark installed
#   - Run from project root or tests/performance directory

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Find project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENV_PYTHON="$PROJECT_ROOT/venv/bin/python"

# Check if virtual environment exists
if [ ! -f "$VENV_PYTHON" ]; then
    echo -e "${YELLOW}Warning: Virtual environment not found at $VENV_PYTHON${NC}"
    echo "Using system Python instead..."
    VENV_PYTHON="python"
fi

echo ""
echo -e "${BLUE}=======================================================${NC}"
echo -e "${BLUE}       ZK-MIXER PERFORMANCE BENCHMARK SUITE            ${NC}"
echo -e "${BLUE}=======================================================${NC}"
echo ""
echo "Project Root: $PROJECT_ROOT"
echo "Python: $VENV_PYTHON"
echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

cd "$PROJECT_ROOT"

run_crypto_benchmarks() {
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  CRYPTOGRAPHIC OPERATION BENCHMARKS                    ${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Running: pytest tests/performance/test_benchmarks.py -v -s -m benchmark"
    echo ""
    $VENV_PYTHON -m pytest tests/performance/test_benchmarks.py -v -s -m benchmark 2>&1 || true
    echo ""
}

run_db_benchmarks() {
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  DATABASE PERFORMANCE BENCHMARKS                       ${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Running: python tests/performance/test_db_performance.py"
    echo ""
    $VENV_PYTHON tests/performance/test_db_performance.py 2>&1 || true
    echo ""
}

# Parse arguments
case "${1:-all}" in
    --crypto|-c)
        run_crypto_benchmarks
        ;;
    --db|-d)
        run_db_benchmarks
        ;;
    all|*)
        run_crypto_benchmarks
        run_db_benchmarks
        echo -e "${BLUE}=======================================================${NC}"
        echo -e "${BLUE}       ALL BENCHMARKS COMPLETED                        ${NC}"
        echo -e "${BLUE}=======================================================${NC}"
        echo ""
        echo "Benchmark results are printed above."
        echo "For JSON export, use: pytest --benchmark-json=results.json"
        echo ""
        ;;
esac
