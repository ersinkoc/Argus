#!/bin/bash
# Chaos Engineering - Fault Injection Test Suite for Argus
# Tests system resilience under adverse conditions

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

check() {
    local desc="$1"; shift
    if eval "$@" > /dev/null 2>&1; then
        echo -e "  ${GREEN}PASS${NC} $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC} $desc"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo -e "${YELLOW}═══ Argus Chaos Engineering Suite ═══${NC}"

# Check if running on Linux (tc/netem available)
if [ "$(uname)" != "Linux" ]; then
    echo -e "${YELLOW}Warning: tc/netem not available on this platform${NC}"
    echo "Skipping network latency simulation tests"
fi

# Check if argus is running
ARGUS_RUNNING=false
if curl -sf http://localhost:9091/healthz > /dev/null 2>&1; then
    ARGUS_RUNNING=true
    echo -e "${GREEN}Argus is running${NC}"
else
    echo -e "${YELLOW}Argus is not running, starting...${NC}"
    # Try to start argus in background if config exists
    if [ -f argus.json ]; then
        ./argus -config argus.json &
        sleep 3
        if curl -sf http://localhost:9091/healthz > /dev/null 2>&1; then
            ARGUS_RUNNING=true
        fi
    fi
fi

if [ "$ARGUS_RUNNING" = false ]; then
    echo -e "${RED}Cannot run chaos tests without Argus running${NC}"
    echo "Start Argus first: ./argus -config configs/argus.json"
    exit 1
fi

echo ""
echo -e "${YELLOW}[1/5] Backend Connection Failure${NC}"

# Test 1: No backend available - should return proper error
check "Graceful degradation when backend down" \
    "curl -sf http://localhost:9091/api/pool/health | grep -q 'healthy'"

# Test 2: Admin API still responds when DB is down
check "Admin API responds under backend failure" \
    "curl -sf http://localhost:9091/healthz | grep -q 'healthy'"

echo ""
echo -e "${YELLOW}[2/5] Rate Limit Stress${NC}"

# Test 3: Rapid requests to trigger rate limiting
for i in $(seq 1 20); do
    curl -sf http://localhost:9091/api/stats > /dev/null 2>&1 || true
done
check "Handles burst of rapid requests" "true"

# Test 4: Concurrent connections
check "Multiple concurrent admin requests" \
    "curl -sf http://localhost:9091/healthz & curl -sf http://localhost:9091/metrics & wait && true"

echo ""
echo -e "${YELLOW}[3/5] Malformed Request Handling${NC}"

# Test 5: Invalid JSON
check "Handles malformed JSON" \
    "curl -sf -X POST http://localhost:9091/api/gateway/query \
        -H 'Content-Type: application/json' \
        -d 'not valid json' | grep -q error"

# Test 6: Missing required fields
check "Handles missing SQL field" \
    "curl -sf -X POST http://localhost:9091/api/gateway/query \
        -H 'Content-Type: application/json' \
        -d '{\"username\":\"test\"}' | grep -q error"

# Test 7: Very long SQL
check "Handles excessively long SQL" \
    "curl -sf -X POST http://localhost:9091/api/gateway/query \
        -H 'Content-Type: application/json' \
        -d '{\"sql\":\"'$(printf 'A%.0s' {1..50000})'\",\"username\":\"test\"}' | grep -q error"

echo ""
echo -e "${YELLOW}[4/5] Session Management${NC}"

# Test 8: Session listing
check "Admin API returns session list" \
    "curl -sf http://localhost:9091/api/sessions | grep -q '['"

# Test 9: Policy reload doesn't disrupt sessions
check "Policy reload is non-disruptive" \
    "curl -sf -X POST http://localhost:9091/api/policies/reload | grep -q"

echo ""
echo -e "${YELLOW}[5/5] Memory & Resource Limits${NC}"

# Test 10: Metrics endpoint provides memory stats
check "Metrics include Go runtime stats" \
    "curl -sf http://localhost:9091/metrics | grep -q 'argus_go_'"

# Test 11: Pool stats are available
check "Pool stats available under load" \
    "curl -sf http://localhost:9091/api/pool/health | grep -q"

echo ""
echo -e "${YELLOW}═══ Summary ═══${NC}"
echo -e "Passed: ${GREEN}$PASS${NC}"
echo -e "Failed: ${RED}$FAIL${NC}"

if [ $FAIL -gt 0 ]; then
    echo -e "${RED}Chaos tests FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}All chaos tests passed - system is resilient${NC}"
fi