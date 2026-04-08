#!/usr/bin/env bash
set -euo pipefail

# Hot-reload under load benchmark for Cedar PDP
# Measures latency impact of policy reload during concurrent traffic
# Requires: oha (cargo install oha), PDP running with production policies
#
# Usage:
#   Terminal 1: cd pdp && CEDAR_POLICY_DIR=../policies cargo run --release
#   Terminal 2: cd benchmarks && bash reload_spike.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PDP_URL="${PDP_URL:-http://localhost:8180}"
ITERATIONS="${ITERATIONS:-5}"
LOAD_DURATION="${LOAD_DURATION:-15}"
RELOAD_AT="${RELOAD_AT:-5}"
CONCURRENCY="${CONCURRENCY:-100}"
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

BODY_FILE="${SCRIPT_DIR}/fixtures/claims_allow.json"
if [[ ! -f "$BODY_FILE" ]]; then
    echo "ERROR: $BODY_FILE not found"
    exit 1
fi

# Extract a single metric from oha JSON output
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

# Run a single load test and return JSON
run_load() {
    oha -c "$CONCURRENCY" -z "${LOAD_DURATION}s" \
        -m POST \
        -H "Content-Type: application/json" \
        -D "$BODY_FILE" \
        --output-format json \
        --no-tui \
        "$PDP_URL/v1/is_authorized" 2>/dev/null
}

echo "=== Hot-Reload Under Load ==="
echo "Config: concurrency=$CONCURRENCY, duration=${LOAD_DURATION}s, reload at ${RELOAD_AT}s, iterations=$ITERATIONS"
echo ""

# --- Baseline run (no reload) ---
echo "Running baseline (no reload)..."
baseline_json=$(run_load)
echo "$baseline_json" > "${RESULTS_DIR}/${TIMESTAMP}_reload_baseline.json"

baseline_p99=$(extract_metric "$baseline_json" \
    "v=d['latencyPercentiles']['p99']; print(f'{v*1000:.3f}' if v is not None else 'N/A')")
baseline_max=$(extract_metric "$baseline_json" \
    "v=d['summary']['slowest']; print(f'{v*1000:.3f}' if v is not None else 'N/A')")
baseline_rps=$(extract_metric "$baseline_json" \
    "v=d['summary']['requestsPerSec']; print(f'{v:.0f}' if v is not None else 'N/A')")

echo "Baseline: p99=${baseline_p99}ms  max=${baseline_max}ms  rps=${baseline_rps}"
echo ""

# --- Reload runs ---
echo "Running $ITERATIONS reload iterations..."
echo ""
printf "%-12s %-12s %-12s %-12s %-12s\n" \
    "iteration" "p99_ms" "max_ms" "rps" "reload_ms"
echo "---"

declare -a p99_values=()
declare -a max_values=()

for i in $(seq 1 "$ITERATIONS"); do
    # Start oha in background
    oha_output=$(mktemp)
    oha -c "$CONCURRENCY" -z "${LOAD_DURATION}s" \
        -m POST \
        -H "Content-Type: application/json" \
        -D "$BODY_FILE" \
        --output-format json \
        --no-tui \
        "$PDP_URL/v1/is_authorized" > "$oha_output" 2>/dev/null &
    oha_pid=$!

    # Wait for the reload trigger point
    sleep "$RELOAD_AT"

    # Trigger reload and measure time
    reload_start=$(date +%s%N)
    curl -sf -X POST "$PDP_URL/admin/reload" > /dev/null 2>&1 || true
    reload_end=$(date +%s%N)
    reload_ms=$(( (reload_end - reload_start) / 1000000 ))

    # Wait for oha to finish
    wait "$oha_pid" || true

    # Read results
    local_json=$(cat "$oha_output")
    rm -f "$oha_output"

    # Save raw JSON
    echo "$local_json" > "${RESULTS_DIR}/${TIMESTAMP}_reload_iter${i}.json"

    # Extract metrics
    iter_p99=$(extract_metric "$local_json" \
        "v=d['latencyPercentiles']['p99']; print(f'{v*1000:.3f}' if v is not None else 'N/A')")
    iter_max=$(extract_metric "$local_json" \
        "v=d['summary']['slowest']; print(f'{v*1000:.3f}' if v is not None else 'N/A')")
    iter_rps=$(extract_metric "$local_json" \
        "v=d['summary']['requestsPerSec']; print(f'{v:.0f}' if v is not None else 'N/A')")

    printf "%-12s %-12s %-12s %-12s %-12s\n" \
        "$i" "$iter_p99" "$iter_max" "$iter_rps" "$reload_ms"

    p99_values+=("$iter_p99")
    max_values+=("$iter_max")
done

echo ""

# Compute median of the reload runs
median_p99=$(printf '%s\n' "${p99_values[@]}" | grep -v 'N/A' | sort -n | awk '
    { a[NR] = $1 }
    END {
        if (NR == 0) { print "N/A"; exit }
        mid = int((NR + 1) / 2)
        if (NR % 2 == 1) print a[mid]
        else printf "%.3f\n", (a[mid] + a[mid+1]) / 2
    }
')

median_max=$(printf '%s\n' "${max_values[@]}" | grep -v 'N/A' | sort -n | awk '
    { a[NR] = $1 }
    END {
        if (NR == 0) { print "N/A"; exit }
        mid = int((NR + 1) / 2)
        if (NR % 2 == 1) print a[mid]
        else printf "%.3f\n", (a[mid] + a[mid+1]) / 2
    }
')

echo "--- Summary ---"
echo "Baseline (no reload):          p99=${baseline_p99}ms  max=${baseline_max}ms"
echo "With reload (median of $ITERATIONS):    p99=${median_p99}ms  max=${median_max}ms"

# Compute spike percentage if both values are numeric
python3 -c "
try:
    bp = float('$baseline_p99')
    mp = float('$median_p99')
    bm = float('$baseline_max')
    mm = float('$median_max')
    p99_delta = mp - bp
    p99_pct = (p99_delta / bp) * 100 if bp > 0 else 0
    max_delta = mm - bm
    max_pct = (max_delta / bm) * 100 if bm > 0 else 0
    print(f'Spike: p99 {p99_delta:+.3f}ms ({p99_pct:+.1f}%)  max {max_delta:+.3f}ms ({max_pct:+.1f}%)')
except (ValueError, ZeroDivisionError):
    print('Spike: unable to compute (baseline or median unavailable)')
" 2>/dev/null || echo "Spike: unable to compute"

echo ""
echo "Raw results saved to: $RESULTS_DIR/"
echo "Done."
