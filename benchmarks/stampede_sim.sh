#!/usr/bin/env bash
set -euo pipefail

# Cache Stampede Simulation
# Simulates synchronized cache expiry and measures the thundering herd effect.
#
# Requires: oha (cargo install oha), Docker, Docker Compose
#
# Phases:
#   1. warm       -- fill cache with a single PARC triple (low concurrency)
#   2. wait       -- sleep past cache TTL so all entries expire simultaneously
#   3. stampede   -- blast with high concurrency (all requests miss cache at once)
#   4. steady     -- re-run at high concurrency (cache warm again, spike is transient)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"
TIMESTAMP=$(date +%Y%m%dT%H%M%S)
KONG_URL="http://localhost:8000"
PDP_URL="http://localhost:8180"

# Cache TTL for stampede test (ms). Must be long enough to fill, short enough to expire quickly.
CACHE_TTL_MS=5000
EXPIRY_WAIT=5.5  # seconds to sleep after warm phase (TTL + margin)

WARM_REQUESTS="${WARM_REQUESTS:-1000}"
WARM_CONCURRENCY="${WARM_CONCURRENCY:-10}"
STAMPEDE_REQUESTS="${STAMPEDE_REQUESTS:-1000}"
STAMPEDE_CONCURRENCY="${STAMPEDE_CONCURRENCY:-200}"

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

# --- Temp file management ---

TMPDIR_BENCH=$(mktemp -d "${TMPDIR:-/tmp}/stampede_bench.XXXXXX")
trap 'cleanup' EXIT

cleanup() {
    echo ""
    echo "Cleaning up..."
    if [[ -f "${TMPDIR_BENCH}/docker-compose.override.yml" ]]; then
        docker compose \
            -f "${SCRIPT_DIR}/docker-compose.go.yml" \
            -f "${TMPDIR_BENCH}/docker-compose.override.yml" \
            down 2>/dev/null || true
    fi
    docker compose -f "${SCRIPT_DIR}/docker-compose.go.yml" down 2>/dev/null || true
    rm -rf "$TMPDIR_BENCH"
}

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

wait_for_kong() {
    echo "  Waiting for Kong proxy..."
    for ((i=1; i<=60; i++)); do
        local http_code
        http_code=$(curl -sf -o /dev/null -w "%{http_code}" -H "apikey: bench-key" "${KONG_URL}/api/test" 2>/dev/null || echo "000")
        if [[ "$http_code" != "000" ]]; then
            echo "  Kong responding (HTTP $http_code)."
            return 0
        fi
        sleep 1
    done
    echo "  TIMEOUT waiting for Kong"
    return 1
}

# Run oha and capture JSON output.
run_oha() {
    local url="$1" concurrency="$2" requests="$3"
    shift 3
    oha -c "$concurrency" -n "$requests" --no-tui "$@" --output-format json "$url" 2>/dev/null
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

# Generate a Kong declarative config with a specific cache_ttl_ms.
generate_kong_config() {
    local ttl_ms="$1" output_file="$2"
    sed "s/cache_ttl_ms: [0-9]*/cache_ttl_ms: ${ttl_ms}/" \
        "${SCRIPT_DIR}/kong-go.yml" > "$output_file"
}

# Generate a docker-compose override that mounts the custom kong config.
generate_compose_override() {
    local kong_config_path="$1" override_file="$2"
    cat > "$override_file" <<COMPEOF
services:
  kong:
    volumes:
      - ${kong_config_path}:/etc/kong/kong.yml:ro
COMPEOF
}

# --- Main ---

echo "=== Cache Stampede Simulation ==="
echo "Cache TTL: ${CACHE_TTL_MS}ms"
echo "Expiry wait: ${EXPIRY_WAIT}s"
echo "Warm: ${WARM_REQUESTS} requests @ concurrency ${WARM_CONCURRENCY}"
echo "Stampede: ${STAMPEDE_REQUESTS} requests @ concurrency ${STAMPEDE_CONCURRENCY}"
echo "Timestamp: ${TIMESTAMP}"
echo ""

# Generate custom kong config with the stampede TTL.
KONG_CONFIG="${TMPDIR_BENCH}/kong-go-stampede.yml"
COMPOSE_OVERRIDE="${TMPDIR_BENCH}/docker-compose.override.yml"
generate_kong_config "$CACHE_TTL_MS" "$KONG_CONFIG"
generate_compose_override "$KONG_CONFIG" "$COMPOSE_OVERRIDE"

# Start docker stack.
echo "Starting Go stack (cache_ttl_ms=${CACHE_TTL_MS})..."
docker compose \
    -f "${SCRIPT_DIR}/docker-compose.go.yml" \
    -f "$COMPOSE_OVERRIDE" \
    up -d --build 2>&1 | tail -5

if ! wait_for_service "$PDP_URL/health" 120; then
    echo "FATAL: PDP did not become healthy."
    exit 1
fi

if ! wait_for_kong; then
    echo "FATAL: Kong did not respond."
    exit 1
fi

# Stabilize.
sleep 2

# --- Phase 1: Warm cache ---
echo ""
echo "--- Phase 1: Warm cache ---"
echo "  Sending ${WARM_REQUESTS} requests at concurrency ${WARM_CONCURRENCY}..."
WARM_JSON="${RESULTS_DIR}/${TIMESTAMP}_stampede_warm.json"
run_oha "${KONG_URL}/api/test" "$WARM_CONCURRENCY" "$WARM_REQUESTS" \
    -H "apikey: bench-key" > "$WARM_JSON"
WARM_METRICS=$(extract_metrics "$WARM_JSON")
echo "  Warm: $WARM_METRICS"

# --- Phase 2: Wait for cache expiry ---
echo ""
echo "--- Phase 2: Waiting ${EXPIRY_WAIT}s for cache to expire ---"
sleep "$EXPIRY_WAIT"

# --- Phase 3: Stampede (thundering herd) ---
echo ""
echo "--- Phase 3: Stampede (post-expiry burst) ---"
echo "  Sending ${STAMPEDE_REQUESTS} requests at concurrency ${STAMPEDE_CONCURRENCY}..."
STAMPEDE_JSON="${RESULTS_DIR}/${TIMESTAMP}_stampede_burst.json"
run_oha "${KONG_URL}/api/test" "$STAMPEDE_CONCURRENCY" "$STAMPEDE_REQUESTS" \
    -H "apikey: bench-key" > "$STAMPEDE_JSON"
STAMPEDE_METRICS=$(extract_metrics "$STAMPEDE_JSON")
echo "  Stampede: $STAMPEDE_METRICS"

# --- Phase 4: Steady state (cache warm again) ---
echo ""
echo "--- Phase 4: Steady state (cache re-warmed) ---"
echo "  Sending ${STAMPEDE_REQUESTS} requests at concurrency ${STAMPEDE_CONCURRENCY}..."
STEADY_JSON="${RESULTS_DIR}/${TIMESTAMP}_stampede_steady.json"
run_oha "${KONG_URL}/api/test" "$STAMPEDE_CONCURRENCY" "$STAMPEDE_REQUESTS" \
    -H "apikey: bench-key" > "$STEADY_JSON"
STEADY_METRICS=$(extract_metrics "$STEADY_JSON")
echo "  Steady: $STEADY_METRICS"

# --- Tear down ---
echo ""
echo "Tearing down..."
docker compose \
    -f "${SCRIPT_DIR}/docker-compose.go.yml" \
    -f "$COMPOSE_OVERRIDE" \
    down 2>&1 | tail -1

# --- Summary ---

echo ""
echo "=== Cache Stampede Results ==="
echo ""
printf "%-14s %-10s %-13s %-10s %-10s %-10s\n" "phase" "requests" "concurrency" "p50_ms" "p99_ms" "max_ms"
printf "%-14s %-10s %-13s %-10s %-10s %-10s\n" "----------" "--------" "-----------" "------" "------" "------"

IFS=$'\t' read -r w_rps w_p50 w_p99 w_max <<< "$WARM_METRICS"
IFS=$'\t' read -r s_rps s_p50 s_p99 s_max <<< "$STAMPEDE_METRICS"
IFS=$'\t' read -r t_rps t_p50 t_p99 t_max <<< "$STEADY_METRICS"

printf "%-14s %-10s %-13s %-10s %-10s %-10s\n" "warm_cache" "$WARM_REQUESTS" "$WARM_CONCURRENCY" "$w_p50" "$w_p99" "$w_max"
printf "%-14s %-10s %-13s %-10s %-10s %-10s\n" "post_expiry" "$STAMPEDE_REQUESTS" "$STAMPEDE_CONCURRENCY" "$s_p50" "$s_p99" "$s_max"
printf "%-14s %-10s %-13s %-10s %-10s %-10s\n" "steady_state" "$STAMPEDE_REQUESTS" "$STAMPEDE_CONCURRENCY" "$t_p50" "$t_p99" "$t_max"

# --- Stampede impact analysis ---

echo ""
python3 - "$w_p99" "$s_p99" "$CACHE_TTL_MS" <<'PYEOF'
import sys

warm_p99 = float(sys.argv[1])
stampede_p99 = float(sys.argv[2])
ttl_ms = int(sys.argv[3])

if warm_p99 > 0:
    ratio = stampede_p99 / warm_p99
    print(f"Stampede impact: p99 increased {ratio:.1f}x vs warm cache ({stampede_p99:.3f}ms vs {warm_p99:.3f}ms)")
else:
    print(f"Stampede impact: warm p99 was 0, cannot compute ratio")

# Jitter recommendation
jitter_pct = 20
jitter_window_ms = ttl_ms * jitter_pct / 100
print(f"")
print(f"Recommendation: Add {jitter_pct}% TTL jitter to smooth expiry distribution")
print(f"  With {jitter_pct}% jitter on {ttl_ms}ms TTL:")
print(f"  - Entries expire across a {jitter_window_ms:.0f}ms window ({ttl_ms - jitter_window_ms:.0f}-{ttl_ms}ms)")
print(f"  - At concurrency 200, only ~{100//(ttl_ms//int(jitter_window_ms)) if jitter_window_ms > 0 else 100}% of requests")
print(f"    would hit a cold cache in any given {jitter_window_ms:.0f}ms slice")
print(f"  - Eliminates synchronized stampede on TTL boundary")
PYEOF

echo ""
echo "Raw JSON results in: ${RESULTS_DIR}/"
