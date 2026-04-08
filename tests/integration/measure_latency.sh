#!/usr/bin/env bash
set -euo pipefail

REQUESTS=1000
KONG_URL="http://localhost:8000"
HTTPBIN_URL="http://localhost:8080"

measure() {
    local label="$1" url="$2"
    shift 2
    local extra_args=("$@")
    local timings_file
    timings_file=$(mktemp)

    echo "Measuring: $label ($REQUESTS requests)..."
    for ((i=1; i<=REQUESTS; i++)); do
        curl -s -o /dev/null -w '%{time_total}\n' "${extra_args[@]}" "$url" >> "$timings_file"
        if ((i % 100 == 0)); then
            printf "  %d/%d\r" "$i" "$REQUESTS"
        fi
    done
    echo ""

    sort -n "$timings_file" > "${timings_file}.sorted"

    local count
    count=$(wc -l < "${timings_file}.sorted")

    local p50_line p95_line p99_line
    p50_line=$(( count * 50 / 100 ))
    p95_line=$(( count * 95 / 100 ))
    p99_line=$(( count * 99 / 100 ))

    # Ensure at least line 1
    [[ $p50_line -lt 1 ]] && p50_line=1
    [[ $p95_line -lt 1 ]] && p95_line=1
    [[ $p99_line -lt 1 ]] && p99_line=1

    local p50 p95 p99 avg
    p50=$(awk "NR==${p50_line}" "${timings_file}.sorted")
    p95=$(awk "NR==${p95_line}" "${timings_file}.sorted")
    p99=$(awk "NR==${p99_line}" "${timings_file}.sorted")
    avg=$(awk '{s+=$1} END {printf "%.6f", s/NR}' "${timings_file}.sorted")

    printf "  %-45s avg=%.3fs  p50=%.3fs  p95=%.3fs  p99=%.3fs\n" \
        "$label" "$avg" "$p50" "$p95" "$p99"

    rm -f "$timings_file" "${timings_file}.sorted"
}

echo "=== Latency Measurement: Kong + Cedar PDP ==="
echo "Requests per scenario: $REQUESTS"
echo ""

# Scenario 1: With PDP enabled (Kong -> key-auth -> cedar-pdp plugin -> PDP -> httpbin)
measure "With PDP (Kong -> plugin -> PDP -> upstream)" \
    "$KONG_URL/api/test" \
    -H "apikey: alice-key"

# Scenario 2: Without PDP (direct to httpbin, no authorization overhead)
measure "Without PDP (direct httpbin)" \
    "$HTTPBIN_URL/get"

echo ""
echo "PDP overhead = (With PDP p50) - (Without PDP p50)"
echo "Note: overhead includes Kong processing, Lua plugin, HTTP round-trip to PDP, and Cedar evaluation."
echo ""
echo "Done."
