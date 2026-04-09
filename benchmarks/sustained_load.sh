#!/usr/bin/env bash
# sustained_load.sh -- 5-minute sustained load test for p99 stability validation.
#
# Validates that p99 latency holds under sustained traffic, not just 15-second bursts.
# Checks for: allocator fragmentation, tokio runtime pressure, file watcher overhead,
# and any latency drift over time.
#
# Prerequisites: oha (cargo install oha), PDP running on PDP_PORT (default 8180)
#
# Usage: bash sustained_load.sh [duration_seconds] [concurrency]
#   Default: 300s (5 min), concurrency 50 and 100

set -euo pipefail

PDP_PORT="${PDP_PORT:-8180}"
BASE_URL="http://127.0.0.1:${PDP_PORT}"
DURATION="${1:-300}"
RESULTS_DIR="results/sustained_$(date +%Y%m%dT%H%M%S)"

# Verify PDP is running
if ! curl -sf "${BASE_URL}/healthz" > /dev/null 2>&1; then
    echo "ERROR: PDP not responding at ${BASE_URL}/healthz"
    echo "Start with: cd pdp && CEDAR_POLICY_DIR=../policies cargo run --release"
    exit 1
fi

# Verify oha is installed
if ! command -v oha &> /dev/null; then
    echo "ERROR: oha not found. Install with: cargo install oha"
    exit 1
fi

mkdir -p "${RESULTS_DIR}"

# Allow request body (editor role, GET /api/v1/users)
ALLOW_BODY='{"principal":"ignored","action":"GET","resource":"/api/v1/users","claims":{"sub":"sustained-user","email":"user@example.com","department":"engineering","org":"acme","roles":["editor"],"subscription_tier":"professional","suspended":false,"allowed_scopes":["internal"]}}'

echo "=== Sustained Load Test ==="
echo "Duration: ${DURATION}s per concurrency level"
echo "PDP: ${BASE_URL}"
echo "Results: ${RESULTS_DIR}/"
echo ""

for CONCURRENCY in ${2:-50 100}; do
    echo "--- Concurrency ${CONCURRENCY}, ${DURATION}s ---"

    OUTFILE="${RESULTS_DIR}/c${CONCURRENCY}_${DURATION}s.json"

    oha -z "${DURATION}s" \
        -c "${CONCURRENCY}" \
        -m POST \
        -H "Content-Type: application/json" \
        -d "${ALLOW_BODY}" \
        --json \
        "${BASE_URL}/v1/is_authorized" > "${OUTFILE}" 2>/dev/null

    # Extract key metrics
    P50=$(jq -r '.latencyPercentiles.p50' "${OUTFILE}" 2>/dev/null || echo "N/A")
    P95=$(jq -r '.latencyPercentiles.p95' "${OUTFILE}" 2>/dev/null || echo "N/A")
    P99=$(jq -r '.latencyPercentiles.p99' "${OUTFILE}" 2>/dev/null || echo "N/A")
    MAX=$(jq -r '.latencyPercentiles.p100' "${OUTFILE}" 2>/dev/null || echo "N/A")
    RPS=$(jq -r '.summary.requestsPerSec' "${OUTFILE}" 2>/dev/null || echo "N/A")
    TOTAL=$(jq -r '.summary.total' "${OUTFILE}" 2>/dev/null || echo "N/A")
    ERRORS=$(jq -r '.statusCodeDistribution | to_entries | map(select(.key != "200")) | map(.value) | add // 0' "${OUTFILE}" 2>/dev/null || echo "N/A")

    echo "  Total requests: ${TOTAL}"
    echo "  RPS: ${RPS}"
    echo "  p50: ${P50}"
    echo "  p95: ${P95}"
    echo "  p99: ${P99}"
    echo "  Max: ${MAX}"
    echo "  Non-200 responses: ${ERRORS}"
    echo ""
done

echo "Raw JSON results saved to ${RESULTS_DIR}/"
echo "Done."
