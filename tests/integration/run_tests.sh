#!/usr/bin/env bash
set -euo pipefail

KONG_URL="http://localhost:8000"
PDP_URL="http://localhost:8180"
PASS=0
FAIL=0
TOTAL=6

assert_status() {
    local name="$1" expected="$2" actual="$3"
    if [[ "$actual" == "$expected" ]]; then
        echo "PASS: $name (expected $expected, got $actual)"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $name (expected $expected, got $actual)"
        FAIL=$((FAIL + 1))
    fi
}

check_header() {
    local name="$1" header="$2" response="$3"
    if echo "$response" | grep -qi "$header"; then
        echo "  OK: Header '$header' present"
    else
        echo "  WARN: Header '$header' missing in response"
    fi
}

echo "=== Integration Tests: Kong + Cedar PDP ==="
echo ""

# Wait for Kong to be ready
echo "Waiting for Kong proxy..."
for i in $(seq 1 30); do
    if curl -s -o /dev/null -w '%{http_code}' "$KONG_URL" | grep -q '[0-9]'; then
        break
    fi
    sleep 1
done
echo "Kong ready."
echo ""

# Test 1: Valid auth with permitted principal -> 200
# alice (UUID 00000000-0000-0000-0000-000000000001) has permit for GET /api/test
echo "--- T1: alice GET /api/test (should be 200 Allow) ---"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$KONG_URL/api/test" -H "apikey: alice-key")
assert_status "T1: alice GET /api/test -> 200" 200 "$STATUS"

# Test 2: Valid auth without permit -> 403
# bob (UUID 00000000-0000-0000-0000-000000000002) has no permit policy -> Cedar default-deny -> 403
echo ""
echo "--- T2: bob GET /api/test (should be 403 Deny) ---"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$KONG_URL/api/test" -H "apikey: bob-key")
assert_status "T2: bob GET /api/test -> 403" 403 "$STATUS"

# Test 3: Missing auth -> 401
# No apikey header -> key-auth plugin returns 401 before cedar-pdp runs
echo ""
echo "--- T3: no auth GET /api/test (should be 401) ---"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$KONG_URL/api/test")
assert_status "T3: no auth GET /api/test -> 401" 401 "$STATUS"

# Test 4: PDP timeout -> 503 + Retry-After
# timeout-route uses a non-routable IP (10.255.255.1) that will timeout
echo ""
echo "--- T4: PDP timeout via non-routable IP (should be 503 + Retry-After) ---"
RESPONSE=$(curl -s -D - -o /dev/null --max-time 10 "$KONG_URL/api/timeout-test" -H "apikey: alice-key" 2>&1 || true)
STATUS=$(echo "$RESPONSE" | grep -E "^HTTP/" | tail -1 | awk '{print $2}' || echo "000")
assert_status "T4: PDP timeout -> 503" 503 "$STATUS"
check_header "T4" "Retry-After" "$RESPONSE"

# Test 5: PDP returns 503 -> 503 forwarded with Retry-After
# overload-route points to pdp-503 service which always returns 503
echo ""
echo "--- T5: PDP 503 backpressure (should be 503 + Retry-After forwarded) ---"
RESPONSE=$(curl -s -D - -o /dev/null "$KONG_URL/api/overload-test" -H "apikey: alice-key" 2>&1 || true)
STATUS=$(echo "$RESPONSE" | grep -E "^HTTP/" | tail -1 | awk '{print $2}' || echo "000")
assert_status "T5: PDP 503 -> 503 forwarded" 503 "$STATUS"
check_header "T5" "Retry-After" "$RESPONSE"

# Test 6: Unknown principal -> Cedar default-deny
# charlie has no permit policy -> decision must be Deny
echo ""
echo "--- T6: unknown principal charlie -> Cedar default-deny ---"
HTTP_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$PDP_URL/v1/is_authorized" \
    -H "Content-Type: application/json" \
    -d '{"principal":"User::\"charlie\"","action":"Action::\"get\"","resource":"Resource::\"/api/test\"","context":{}}')
assert_status "T6: PDP returns 200 for unknown principal" 200 "$HTTP_STATUS"

BODY=$(curl -s "$PDP_URL/v1/is_authorized" \
    -H "Content-Type: application/json" \
    -d '{"principal":"User::\"charlie\"","action":"Action::\"get\"","resource":"Resource::\"/api/test\"","context":{}}')
DECISION=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['decision'])" 2>/dev/null || echo "ERROR")
if [[ "$DECISION" == "Deny" ]]; then
    echo "  OK: Decision is Deny for unknown principal charlie (Cedar default-deny)"
else
    echo "  FAIL: Expected Deny, got $DECISION (body: $BODY)"
    FAIL=$((FAIL + 1))
    TOTAL=$((TOTAL + 1))
fi

echo ""
echo "==================================================="
echo "Results: $PASS/$TOTAL passed, $FAIL failed"
echo "==================================================="

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
