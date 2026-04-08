#!/usr/bin/env bash
set -euo pipefail

# Cache Effectiveness Benchmark
# Measures how decision caching affects throughput at different TTL values.
#
# Requires: oha (cargo install oha), Docker, Docker Compose
#
# For each TTL, runs three passes through Kong's Go plugin stack:
#   cold  -- first 5000 requests (cache empty)
#   warm  -- second 5000 requests (same PARC triple, cache populated)
#   varied -- 5000 requests across 100 different paths (multiple cache entries)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"
TIMESTAMP=$(date +%Y%m%dT%H%M%S)
REQUESTS="${REQUESTS:-5000}"
CONCURRENCY="${CONCURRENCY:-50}"
KONG_URL="http://localhost:8000"
PDP_URL="http://localhost:8180"

TTL_VALUES=(0 1000 5000 30000 60000)

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

TMPDIR_BENCH=$(mktemp -d "${TMPDIR:-/tmp}/cache_bench.XXXXXX")
trap 'cleanup' EXIT

cleanup() {
    echo ""
    echo "Cleaning up..."
    # Tear down any running stack (use the last compose file if it exists)
    if [[ -f "${TMPDIR_BENCH}/docker-compose.override.yml" ]]; then
        docker compose \
            -f "${SCRIPT_DIR}/docker-compose.go.yml" \
            -f "${TMPDIR_BENCH}/docker-compose.override.yml" \
            down 2>/dev/null || true
    fi
    # Also tear down base stack in case override wasn't used
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
# Prints: rps p50_ms p99_ms
extract_metrics() {
    local json_file="$1"
    python3 - "$json_file" <<'PYEOF'
import sys, json, pathlib

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
summary = data.get("summary", {})

rps = summary.get("requestsPerSec", summary.get("successRate", 0))

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

print(f"{rps:.0f}\t{p50*1000:.3f}\t{p99*1000:.3f}")
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

# Generate a file with varied URLs for the multi-key cache test.
generate_varied_urls() {
    local output_file="$1" count="${2:-100}"
    for ((i=0; i<count; i++)); do
        echo "${KONG_URL}/api/test/item${i}"
    done > "$output_file"
}

# --- Main ---

echo "=== Cache Effectiveness Benchmark ==="
echo "Requests per pass: ${REQUESTS}"
echo "Concurrency: ${CONCURRENCY}"
echo "TTL values: ${TTL_VALUES[*]} ms"
echo "Timestamp: ${TIMESTAMP}"
echo ""

# Generate varied URL list for multi-key tests.
VARIED_URLS_FILE="${TMPDIR_BENCH}/varied_urls.txt"
generate_varied_urls "$VARIED_URLS_FILE" 100

# Collect results for the final table.
declare -a RESULT_ROWS=()

for ttl in "${TTL_VALUES[@]}"; do
    echo ""
    echo "--- TTL: ${ttl}ms ---"

    # Generate custom kong config with this TTL.
    KONG_CONFIG="${TMPDIR_BENCH}/kong-go-ttl${ttl}.yml"
    COMPOSE_OVERRIDE="${TMPDIR_BENCH}/docker-compose.override.yml"
    generate_kong_config "$ttl" "$KONG_CONFIG"
    generate_compose_override "$KONG_CONFIG" "$COMPOSE_OVERRIDE"

    # Start docker stack with the override.
    echo "Starting Go stack (cache_ttl_ms=${ttl})..."
    docker compose \
        -f "${SCRIPT_DIR}/docker-compose.go.yml" \
        -f "$COMPOSE_OVERRIDE" \
        up -d --build 2>&1 | tail -5

    if ! wait_for_service "$PDP_URL/health" 120; then
        echo "FATAL: PDP did not become healthy. Skipping TTL=${ttl}."
        docker compose \
            -f "${SCRIPT_DIR}/docker-compose.go.yml" \
            -f "$COMPOSE_OVERRIDE" \
            down 2>&1 | tail -1
        continue
    fi

    if ! wait_for_kong; then
        echo "FATAL: Kong did not respond. Skipping TTL=${ttl}."
        docker compose \
            -f "${SCRIPT_DIR}/docker-compose.go.yml" \
            -f "$COMPOSE_OVERRIDE" \
            down 2>&1 | tail -1
        continue
    fi

    # Stabilize.
    sleep 2

    # --- Cold pass (cache empty, single PARC triple) ---
    echo "  Running cold pass..."
    COLD_JSON="${RESULTS_DIR}/${TIMESTAMP}_cache_ttl${ttl}_cold.json"
    run_oha "${KONG_URL}/api/test" "$CONCURRENCY" "$REQUESTS" \
        -H "apikey: bench-key" > "$COLD_JSON"
    COLD_METRICS=$(extract_metrics "$COLD_JSON")
    echo "  Cold: $COLD_METRICS"

    # --- Warm pass (cache populated from cold pass, same triple) ---
    echo "  Running warm pass..."
    WARM_JSON="${RESULTS_DIR}/${TIMESTAMP}_cache_ttl${ttl}_warm.json"
    run_oha "${KONG_URL}/api/test" "$CONCURRENCY" "$REQUESTS" \
        -H "apikey: bench-key" > "$WARM_JSON"
    WARM_METRICS=$(extract_metrics "$WARM_JSON")
    echo "  Warm: $WARM_METRICS"

    # --- Varied pass (100 different paths -> 100 cache keys) ---
    # oha --urls-from-file cycles through URLs from a file, one per line.
    # Each path creates a distinct cache key (principal|action|resource).
    echo "  Running varied pass (100 distinct paths)..."
    VARIED_JSON="${RESULTS_DIR}/${TIMESTAMP}_cache_ttl${ttl}_varied.json"
    oha -c "$CONCURRENCY" -n "$REQUESTS" --no-tui \
        -H "apikey: bench-key" \
        --urls-from-file --output-format json "$VARIED_URLS_FILE" 2>/dev/null > "$VARIED_JSON"
    VARIED_METRICS=$(extract_metrics "$VARIED_JSON")
    echo "  Varied: $VARIED_METRICS"

    # Collect rows.
    RESULT_ROWS+=("${ttl}\tcold\t${COLD_METRICS}")
    RESULT_ROWS+=("${ttl}\twarm\t${WARM_METRICS}")
    RESULT_ROWS+=("${ttl}\tvaried\t${VARIED_METRICS}")

    # Tear down.
    echo "  Tearing down..."
    docker compose \
        -f "${SCRIPT_DIR}/docker-compose.go.yml" \
        -f "$COMPOSE_OVERRIDE" \
        down 2>&1 | tail -1
done

# --- Summary table ---

echo ""
echo "=== Cache Effectiveness Results ==="
echo ""
printf "%-10s %-10s %-10s %-10s %-10s\n" "ttl_ms" "pass" "rps" "p50_ms" "p99_ms"
printf "%-10s %-10s %-10s %-10s %-10s\n" "------" "------" "------" "------" "------"

for row in "${RESULT_ROWS[@]}"; do
    IFS=$'\t' read -r ttl pass rps p50 p99 <<< "$row"
    printf "%-10s %-10s %-10s %-10s %-10s\n" "$ttl" "$pass" "$rps" "$p50" "$p99"
done

echo ""
echo "Raw JSON results in: ${RESULTS_DIR}/"
echo ""
echo "Interpretation:"
echo "  - TTL=0: no caching, cold and warm should be similar"
echo "  - TTL>0: warm pass should show higher RPS and lower latency (cache hits)"
echo "  - Varied pass: measures cache with 100 distinct keys (lower hit rate on first fill)"
