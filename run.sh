#!/bin/bash

# ZK-Mixer Complete Startup Script
# This script starts all components of the ZK-Mixer system locally

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_DIR/venv"
API_PORT=${API_PORT:-8000}
FRONTEND_PORT=${FRONTEND_PORT:-8001}
DB_PATH="${PROJECT_DIR}/zk_mixer.db"
LOG_DIR="${PROJECT_DIR}/.logs"

# Create log directory
mkdir -p "$LOG_DIR"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Function to cleanup on exit
cleanup() {
    print_warning "Shutting down services..."
    
    # Kill background processes
    if [ ! -z "$API_PID" ]; then
        kill $API_PID 2>/dev/null || true
    fi
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
    fi
    
    print_success "Shutdown complete"
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

# Check Python
print_status "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed"
    exit 1
fi
PYTHON_VERSION=$(python3 --version | awk '{print $2}')
print_success "Found Python $PYTHON_VERSION"

# Activate virtual environment
print_status "Setting up Python virtual environment..."
if [ ! -d "$VENV_DIR" ]; then
    print_status "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
print_success "Virtual environment activated"

# Install dependencies
print_status "Installing Python dependencies..."
pip install -q -r "$PROJECT_DIR/requirements.txt" 2>/dev/null || pip install -q pydantic fastapi uvicorn sqlalchemy

print_success "Dependencies installed"

# Initialize database
print_status "Initializing database..."
python3 -c "
import sys
sys.path.insert(0, '$PROJECT_DIR/src')
from zkm.storage.database import DatabaseManager
db = DatabaseManager('sqlite:///$DB_PATH')
db.create_tables()
print('Database initialized at $DB_PATH')
"
print_success "Database ready"

# Show system info
echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}        ZK-MIXER SYSTEM STARTUP${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Project:              ${GREEN}ZK-Mixer${NC}"
echo -e "Location:             ${GREEN}$PROJECT_DIR${NC}"
echo -e "Database:             ${GREEN}$DB_PATH${NC}"
echo -e "API Port:             ${GREEN}$API_PORT${NC}"
echo -e "Frontend Port:        ${GREEN}$FRONTEND_PORT${NC}"
echo -e "Logs:                 ${GREEN}$LOG_DIR${NC}"
echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

# Start API server
print_status "Starting API server (port $API_PORT)..."
cd "$PROJECT_DIR"
export PYTHONPATH="$PROJECT_DIR/src:$PYTHONPATH"
python3 -m uvicorn zkm.api.routes:app --host 0.0.0.0 --port $API_PORT --reload > "$LOG_DIR/api.log" 2>&1 &
API_PID=$!
print_success "API server started (PID: $API_PID)"
echo "           Logs: $LOG_DIR/api.log"

# Wait for API to start
sleep 2

# Check if API is running
if ! kill -0 $API_PID 2>/dev/null; then
    print_error "API server failed to start"
    echo "Error details:"
    cat "$LOG_DIR/api.log"
    exit 1
fi

# Start simple HTTP server for frontend
print_status "Starting frontend server (port $FRONTEND_PORT)..."
cd "$PROJECT_DIR/frontend"
python3 -m http.server $FRONTEND_PORT > "$LOG_DIR/frontend.log" 2>&1 &
SERVER_PID=$!
print_success "Frontend server started (PID: $SERVER_PID)"
echo "           Logs: $LOG_DIR/frontend.log"

sleep 1

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    print_error "Frontend server failed to start"
    echo "Error details:"
    cat "$LOG_DIR/frontend.log"
    exit 1
fi

# Run quick health check
print_status "Running health checks..."
sleep 1

# Check API health
if curl -s http://localhost:$API_PORT/health > /dev/null 2>&1; then
    print_success "API server is healthy"
else
    print_warning "Could not verify API health (may be starting up)"
fi

# Check frontend
if curl -s http://localhost:$FRONTEND_PORT > /dev/null 2>&1; then
    print_success "Frontend server is healthy"
else
    print_warning "Could not verify frontend health (may be starting up)"
fi

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✓ ZK-MIXER SYSTEM IS RUNNING${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Access the system:${NC}"
echo -e "  • Frontend:  ${GREEN}http://localhost:$FRONTEND_PORT${NC}"
echo -e "  • API Docs:  ${GREEN}http://localhost:$API_PORT/docs${NC}"
echo -e "  • API:       ${GREEN}http://localhost:$API_PORT${NC}"
echo ""
echo -e "${YELLOW}View logs:${NC}"
echo -e "  • API logs:      tail -f $LOG_DIR/api.log"
echo -e "  • Frontend logs: tail -f $LOG_DIR/frontend.log"
echo ""
echo -e "${YELLOW}Stop the system:${NC}"
echo -e "  • Press Ctrl+C to stop all services"
echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

# Print real-time log output
print_status "Starting log streaming (Ctrl+C to stop)..."
echo ""
echo -e "${BLUE}[API Server Logs]${NC}"
tail -f "$LOG_DIR/api.log" &
TAIL_PID=$!

# Keep the script running
wait
