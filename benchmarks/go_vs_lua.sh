#!/usr/bin/env bash
set -euo pipefail

# Go vs Lua Kong Plugin Performance Comparison
# Requires: oha (cargo install oha), Docker, Docker Compose
#
# Runs identical load tests against both Go and Lua plugin stacks,
# measures throughput and latency, and produces a comparison table.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"
DURATION="${DURATION:-30}"
TIMESTAMP=$(date +%Y%m%dT%H%M%S)

mkdir -p "$RESULTS_DIR"

# --- Prerequisites ---

if ! command -v oha &>/dev/null; then
    echo "ERROR: oha not found. Install with: cargo install oha"
    exit 1
fi

if ! command -v docker &>/dev/null; then
    echo "ERROR: docker not found"
    exit 1
fi

if ! docker compose version &>/dev/null; then
    echo "ERROR: docker compose plugin not found"
    exit 1
fi

# --- Configuration ---

CONCURRENCY_LEVELS=(1 10 50 100)
KONG_URL="http://localhost:8000"
PDP_URL="http://localhost:8180"

# Use the existing benchmark fixture for direct PDP tests.
FIXTURE_FILE="${SCRIPT_DIR}/fixtures/claims_allow.json"
if [[ ! -f "$FIXTURE_FILE" ]]; then
    echo "ERROR: fixture not found at $FIXTURE_FILE"
    exit 1
fi

# --- Helper functions ---

wait_for_service() {
    local url="$1" max_wait="${2:-60}"
    echo "  Waiting for $url ..."
    for ((i=1; i<=max_wait; i++)); do
        if curl -sf "$url" > /dev/null 2>&1; then
            echo "  Ready."
            return 0
        fi
        sleep 1
    done
    echo "  TIMEOUT waiting for $url after ${max_wait}s"
    return 1
}

# Run oha and capture JSON output.
run_oha() {
    local url="$1" concurrency="$2"
    shift 2
    oha -c "$concurrency" -z "${DURATION}s" "$@" --output-format json "$url" 2>/dev/null
}

# Extract metrics from oha JSON output.
# Prints: rps p50_ms p99_ms max_ms
extract_metrics() {
    local json_file="$1"
    python3 - "$json_file" <<'PYEOF'
import sys, json, pathlib

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
summary = data.get("summary", {})

rps = summary.get("requestsPerSec", summary.get("successRate", 0))
slowest = summary.get("slowest", 0)

# oha percentiles can be a list of {percentile, latency} or a dict.
p = data.get("responseTimePercentiles", data.get("latencyPercentiles", {}))
if isinstance(p, list):
    pdict = {str(x.get("percentile", "")): x.get("latency", 0) for x in p}
    p50 = float(pdict.get("50", pdict.get("0.5", 0)))
    p99 = float(pdict.get("99", pdict.get("0.99", 0)))
elif isinstance(p, dict):
    p50 = float(p.get("p50", p.get("50", 0)))
    p99 = float(p.get("p99", p.get("99", 0)))
else:
    p50 = p99 = 0.0

print(f"{rps:.0f}\t{p50*1000:.3f}\t{p99*1000:.3f}\t{slowest*1000:.3f}")
PYEOF
}

print_header() {
    printf "%-12s %-10s %-12s %-12s %-12s\n" "concurrency" "rps" "p50_ms" "p99_ms" "max_ms"
}

print_row() {
    local concurrency="$1" metrics="$2"
    local rps p50 p99 max_val
    IFS=$'\t' read -r rps p50 p99 max_val <<< "$metrics"
    printf "%-12s %-10s %-12s %-12s %-12s\n" "$concurrency" "$rps" "$p50" "$p99" "$max_val"
}

# --- Test runner ---

test_stack() {
    local label="$1" compose_file="$2"

    echo ""
    echo "=== Testing: $label ==="
    echo ""

    # Start stack
    echo "Starting Docker stack..."
    docker compose -f "$compose_file" up -d --build 2>&1 | tail -5

    if ! wait_for_service "$PDP_URL/health" 120; then
        echo "FATAL: PDP did not become healthy. Tearing down."
        docker compose -f "$compose_file" down 2>&1 | tail -1
        return 1
    fi

    # Wait for Kong to start accepting requests (key-auth returns 401, not connection refused).
    echo "  Waiting for Kong proxy..."
    for ((i=1; i<=60; i++)); do
        local http_code
        http_code=$(curl -sf -o /dev/null -w "%{http_code}" -H "apikey: bench-key" "${KONG_URL}/api/test" 2>/dev/null || echo "000")
        if [[ "$http_code" != "000" ]]; then
            echo "  Kong responding (HTTP $http_code)."
            break
        fi
        sleep 1
    done

    # Allow services to stabilize after initial connections
    sleep 3

    # --- Direct PDP (bypass Kong) ---
    echo ""
    echo "--- Direct PDP (bypass Kong) ---"
    print_header

    for c in "${CONCURRENCY_LEVELS[@]}"; do
        local json_file="${RESULTS_DIR}/${TIMESTAMP}_${label}_pdp_c${c}.json"
        run_oha "$PDP_URL/v1/is_authorized" "$c" \
            -m POST -H "Content-Type: application/json" -d @"$FIXTURE_FILE" \
            > "$json_file"
        local metrics
        metrics=$(extract_metrics "$json_file")
        print_row "$c" "$metrics"
    done

    # --- Through Kong ---
    echo ""
    echo "--- Through Kong ($label) ---"
    print_header

    for c in "${CONCURRENCY_LEVELS[@]}"; do
        local json_file="${RESULTS_DIR}/${TIMESTAMP}_${label}_kong_c${c}.json"
        run_oha "${KONG_URL}/api/test" "$c" \
            -H "apikey: bench-key" \
            > "$json_file"
        local metrics
        metrics=$(extract_metrics "$json_file")
        print_row "$c" "$metrics"
    done

    # Tear down
    echo ""
    echo "Tearing down $label stack..."
    docker compose -f "$compose_file" down 2>&1 | tail -1
}

# --- Main ---

echo "=== Go vs Lua Kong Plugin Performance Comparison ==="
echo "Duration per test: ${DURATION}s"
echo "Concurrency levels: ${CONCURRENCY_LEVELS[*]}"
echo "Timestamp: ${TIMESTAMP}"
echo ""

test_stack "lua" "${SCRIPT_DIR}/docker-compose.lua.yml"
test_stack "go" "${SCRIPT_DIR}/docker-compose.go.yml"

echo ""
echo "=== Comparison Complete ==="
echo "Raw results in: $RESULTS_DIR/"
echo ""
echo "To analyze: compare kong results at matching concurrency levels."
echo "Go IPC overhead = go_kong_p50 - lua_kong_p50 (at same concurrency)"
echo "Throughput ratio = lua_rps / go_rps (>1 means Lua is faster)"
