#!/usr/bin/env bash
set -euo pipefail

PDP_URL="${PDP_URL:-http://localhost:8180}"
REQUESTS="${REQUESTS:-1000}"

# Check PDP is running
if ! curl -sf "$PDP_URL/health" > /dev/null 2>&1; then
    echo "ERROR: PDP not reachable at $PDP_URL"
    echo "Start it with: cd projects/rust-pdp/pdp && CEDAR_POLICY_DIR=../tests/integration/policies cargo run"
    exit 1
fi

TIMINGS=$(mktemp)

echo "Running $REQUESTS requests to $PDP_URL/v1/is_authorized..."

# Uses the legacy direct-UID path with the test schema (tests/integration/policies/).
# Start PDP with: cd pdp && CEDAR_POLICY_DIR=../tests/integration/policies cargo run
REQUEST_BODY='{"principal":"User::\"00000000-0000-0000-0000-000000000001\"","action":"Action::\"get\"","resource":"Resource::\"/api/test\"","context":{}}'

for ((i=1; i<=REQUESTS; i++)); do
    curl -s -o /dev/null -w '%{time_total}\n' \
        -X POST "$PDP_URL/v1/is_authorized" \
        -H "Content-Type: application/json" \
        -d "$REQUEST_BODY" >> "$TIMINGS"
done

sort -n "$TIMINGS" > "${TIMINGS}.sorted"
TOTAL=$(wc -l < "${TIMINGS}.sorted")

p50=$(awk "NR==$(( TOTAL * 50 / 100 ))" "${TIMINGS}.sorted")
p95=$(awk "NR==$(( TOTAL * 95 / 100 ))" "${TIMINGS}.sorted")
p99=$(awk "NR==$(( TOTAL * 99 / 100 ))" "${TIMINGS}.sorted")
avg=$(awk '{s+=$1} END {printf "%.6f", s/NR}' "${TIMINGS}.sorted")
min=$(head -1 "${TIMINGS}.sorted")
max=$(tail -1 "${TIMINGS}.sorted")

echo ""
echo "=== PDP HTTP Latency Results ==="
echo "Requests: $TOTAL"
echo "Min:  ${min}s"
echo "Avg:  ${avg}s"
echo "P50:  ${p50}s"
echo "P95:  ${p95}s"
echo "P99:  ${p99}s"
echo "Max:  ${max}s"

rm -f "$TIMINGS" "${TIMINGS}.sorted"
