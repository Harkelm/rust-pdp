#!/usr/bin/env bash
set -euo pipefail

# Concurrent HTTP throughput benchmark for Cedar PDP
# Requires: oha (cargo install oha)
# Usage: Start PDP with production policies, then run this script
#   Terminal 1: cd pdp && CEDAR_POLICY_DIR=../policies cargo run --release
#   Terminal 2: cd benchmarks && bash concurrent_throughput.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PDP_URL="${PDP_URL:-http://localhost:8180}"
DURATION="${DURATION:-30}"
RESULTS_DIR="${SCRIPT_DIR}/results"
TIMESTAMP=$(date +%Y%m%dT%H%M%S)

mkdir -p "$RESULTS_DIR"

# Check prerequisites
if ! command -v oha &>/dev/null; then
    echo "ERROR: oha not found. Install with: cargo install oha"
    exit 1
fi

if ! curl -sf "$PDP_URL/health" > /dev/null 2>&1; then
    echo "ERROR: PDP not reachable at $PDP_URL"
    echo "Start with: cd pdp && CEDAR_POLICY_DIR=../policies cargo run --release"
    exit 1
fi

# Get PDP info
POLICY_INFO=$(curl -sf "$PDP_URL/v1/policy-info" 2>/dev/null || echo "(policy-info endpoint not available)")
echo "PDP status: $POLICY_INFO"
echo ""

CONCURRENCY_LEVELS=(1 10 50 100 200 500)

# Extract metrics from oha JSON output.
# oha JSON structure (verified against oha 1.x):
#   summary.requestsPerSec, summary.slowest, summary.fastest, summary.average
#   latencyPercentiles.p50, .p95, .p99 (values in seconds)
#   statusCodeDistribution: {"200": N, ...}
#   errorDistribution: {"error msg": N, ...}
extract_metric() {
    local json="$1"
    local py_expr="$2"
    local fallback="${3:-N/A}"
    echo "$json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
try:
    $py_expr
except Exception:
    print('$fallback')
" 2>/dev/null || echo "$fallback"
}

run_bench() {
    local label="$1"
    local body_file="$2"
    local summary_file="${RESULTS_DIR}/${TIMESTAMP}_${label}_summary.tsv"

    echo "=== $label ==="
    echo ""
    printf "%-12s %-10s %-10s %-10s %-10s %-10s %-10s\n" \
        "concurrency" "rps" "p50_ms" "p95_ms" "p99_ms" "max_ms" "errors"
    echo "---"

    # Write TSV header
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
        "concurrency" "rps" "p50_ms" "p95_ms" "p99_ms" "max_ms" "errors" \
        > "$summary_file"

    for c in "${CONCURRENCY_LEVELS[@]}"; do
        # Run oha: -D for body from file, --output-format json, --no-tui for non-interactive
        local json
        json=$(oha -c "$c" -z "${DURATION}s" \
            -m POST \
            -H "Content-Type: application/json" \
            -D "${SCRIPT_DIR}/${body_file}" \
            --output-format json \
            --no-tui \
            "$PDP_URL/v1/is_authorized" 2>/dev/null)

        # Extract metrics from oha JSON
        # Latency values are in seconds; convert to milliseconds
        local rps p50 p95 p99 max_lat errors

        rps=$(extract_metric "$json" \
            "v=d['summary']['requestsPerSec']; print(f'{v:.0f}' if v is not None else 'N/A')")

        p50=$(extract_metric "$json" \
            "v=d['latencyPercentiles']['p50']; print(f'{v*1000:.3f}' if v is not None else 'N/A')")

        p95=$(extract_metric "$json" \
            "v=d['latencyPercentiles']['p95']; print(f'{v*1000:.3f}' if v is not None else 'N/A')")

        p99=$(extract_metric "$json" \
            "v=d['latencyPercentiles']['p99']; print(f'{v*1000:.3f}' if v is not None else 'N/A')")

        max_lat=$(extract_metric "$json" \
            "v=d['summary']['slowest']; print(f'{v*1000:.3f}' if v is not None else 'N/A')")

        errors=$(extract_metric "$json" \
            "e=d.get('errorDistribution',{}); print(sum(e.values()) if e else 0)" "0")

        printf "%-12s %-10s %-10s %-10s %-10s %-10s %-10s\n" \
            "$c" "$rps" "$p50" "$p95" "$p99" "$max_lat" "$errors"

        # Append to TSV summary
        printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
            "$c" "$rps" "$p50" "$p95" "$p99" "$max_lat" "$errors" \
            >> "$summary_file"

        # Save raw JSON per concurrency level
        echo "$json" > "${RESULTS_DIR}/${TIMESTAMP}_${label}_c${c}.json"
    done

    echo ""
}

run_bench "allow" "fixtures/claims_allow.json"
run_bench "deny" "fixtures/claims_deny.json"

echo "Raw results saved to: $RESULTS_DIR/"
echo "Done."
