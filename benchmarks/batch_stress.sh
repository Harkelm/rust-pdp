#!/usr/bin/env bash
set -euo pipefail

# Batch endpoint stress test for Cedar PDP
# Measures: batch vs sequential performance, rayon thread pool behavior
# Requires: oha (cargo install oha), PDP running with production policies
#
# Usage:
#   Terminal 1: cd pdp && CEDAR_POLICY_DIR=../policies cargo run --release
#   Terminal 2: cd benchmarks && bash batch_stress.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PDP_URL="${PDP_URL:-http://localhost:8180}"
RESULTS_DIR="${SCRIPT_DIR}/results"
TIMESTAMP=$(date +%Y%m%dT%H%M%S)
TMPDIR_BATCH=$(mktemp -d)
trap 'rm -rf "$TMPDIR_BATCH"' EXIT

mkdir -p "$RESULTS_DIR"

# --- Prerequisites ---
if ! command -v oha &>/dev/null; then
    echo "ERROR: oha not found. Install with: cargo install oha" >&2
    exit 1
fi

if ! curl -sf "${PDP_URL}/health" >/dev/null 2>&1; then
    echo "ERROR: PDP not reachable at ${PDP_URL}/health" >&2
    echo "Start with: cd pdp && CEDAR_POLICY_DIR=../policies cargo run --release" >&2
    exit 1
fi

# --- Generate batch request JSON files ---
generate_batch_files() {
    python3 -c "
import json, sys, os

tmpdir = sys.argv[1]
sizes = [1, 10, 50, 100]

for n in sizes:
    requests = []
    for i in range(n):
        requests.append({
            'principal': 'ignored',
            'action': 'GET',
            'resource': f'/api/v1/resource-{i}',
            'context': {},
            'claims': {
                'sub': f'batch-user-{i}',
                'email': f'user-{i}@example.com',
                'department': 'engineering',
                'org': 'acme',
                'roles': ['editor'],
                'subscription_tier': 'professional',
                'suspended': False,
                'allowed_scopes': ['internal']
            }
        })
    with open(os.path.join(tmpdir, f'batch_{n}.json'), 'w') as f:
        json.dump({'requests': requests}, f)

# Single request for sequential baseline
single = {
    'principal': 'ignored',
    'action': 'GET',
    'resource': '/api/v1/resource-0',
    'context': {},
    'claims': {
        'sub': 'batch-user-0',
        'email': 'user-0@example.com',
        'department': 'engineering',
        'org': 'acme',
        'roles': ['editor'],
        'subscription_tier': 'professional',
        'suspended': False,
        'allowed_scopes': ['internal']
    }
}
with open(os.path.join(tmpdir, 'single.json'), 'w') as f:
    json.dump(single, f)
" "$TMPDIR_BATCH"
}

echo "Generating batch request files..."
generate_batch_files

# --- Helper: extract metrics from oha JSON output ---
# oha --json outputs summary stats we can parse
extract_metrics() {
    local json_file="$1"
    python3 -c "
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

rps = data.get('summary', {}).get('requestsPerSec', 0)
total = data.get('summary', {}).get('total', 0)
p50 = data.get('latencyPercentiles', {}).get('p50', 0) * 1000
p99 = data.get('latencyPercentiles', {}).get('p99', 0) * 1000
avg = data.get('summary', {}).get('average', 0) * 1000
count = data.get('summary', {}).get('successRate', 0)

print(f'{total:.3f} {avg:.3f} {p50:.3f} {p99:.3f} {rps:.1f}')
" "$json_file"
}

OUTFILE="${RESULTS_DIR}/batch_stress_${TIMESTAMP}.txt"

echo "=== Cedar PDP Batch Stress Test ===" | tee "$OUTFILE"
echo "Timestamp: $(date -Iseconds)" | tee -a "$OUTFILE"
echo "PDP: ${PDP_URL}" | tee -a "$OUTFILE"
echo "" | tee -a "$OUTFILE"

# --- 1. Sequential baseline: 100 individual requests ---
echo "Running sequential baseline (100 requests, c=1)..." | tee -a "$OUTFILE"
SEQ_JSON="${TMPDIR_BATCH}/seq_result.json"
oha -n 100 -c 1 --no-tui --output-format json \
    -m POST \
    -H "Content-Type: application/json" \
    -D "${TMPDIR_BATCH}/single.json" \
    "${PDP_URL}/v1/is_authorized" > "$SEQ_JSON" 2>/dev/null

SEQ_METRICS=$(extract_metrics "$SEQ_JSON")
SEQ_TOTAL=$(echo "$SEQ_METRICS" | awk '{print $1}')
SEQ_AVG=$(echo "$SEQ_METRICS" | awk '{print $2}')
SEQ_P50=$(echo "$SEQ_METRICS" | awk '{print $3}')
SEQ_P99=$(echo "$SEQ_METRICS" | awk '{print $4}')

# --- 2. Batch comparison: 1 batch of 100 ---
echo "Running batch comparison (1 x batch_100, c=1)..." | tee -a "$OUTFILE"
BATCH_JSON="${TMPDIR_BATCH}/batch_result.json"
oha -n 1 -c 1 --no-tui --output-format json \
    -m POST \
    -H "Content-Type: application/json" \
    -D "${TMPDIR_BATCH}/batch_100.json" \
    "${PDP_URL}/v1/batch_is_authorized" > "$BATCH_JSON" 2>/dev/null

BATCH_METRICS=$(extract_metrics "$BATCH_JSON")
BATCH_TOTAL=$(echo "$BATCH_METRICS" | awk '{print $1}')
BATCH_AVG=$(echo "$BATCH_METRICS" | awk '{print $2}')

# Per-decision latency = batch total time / 100 decisions
BATCH_PER_DECISION=$(python3 -c "print(f'{float(\"${BATCH_TOTAL}\") * 1000 / 100:.3f}')")

# Speedup = sequential total / batch total
SPEEDUP=$(python3 -c "
s = float('${SEQ_TOTAL}')
b = float('${BATCH_TOTAL}')
print(f'{s/b:.1f}' if b > 0 else 'N/A')
")

echo "" | tee -a "$OUTFILE"
echo "=== Batch vs Sequential Comparison ===" | tee -a "$OUTFILE"
printf "Sequential (100 requests, c=1):  total=%ss  per_request=%sms  p50=%sms  p99=%sms\n" \
    "$SEQ_TOTAL" "$SEQ_AVG" "$SEQ_P50" "$SEQ_P99" | tee -a "$OUTFILE"
printf "Batch (1 x 100, c=1):           total=%ss  per_decision=%sms\n" \
    "$BATCH_TOTAL" "$BATCH_PER_DECISION" | tee -a "$OUTFILE"
echo "Speedup: ${SPEEDUP}x" | tee -a "$OUTFILE"

# --- 3. Concurrency stress ---
echo "" | tee -a "$OUTFILE"
echo "=== Batch Concurrency Scaling ===" | tee -a "$OUTFILE"
printf "%-12s %-13s %-10s %-10s %-10s %-15s\n" \
    "batch_size" "concurrency" "rps" "p50_ms" "p99_ms" "decisions/sec" | tee -a "$OUTFILE"

BATCH_SIZES=(10 50 100)
CONCURRENCIES=(1 10 50)
REQUESTS_PER_RUN=100

for bs in "${BATCH_SIZES[@]}"; do
    for conc in "${CONCURRENCIES[@]}"; do
        RESULT_JSON="${TMPDIR_BATCH}/stress_${bs}_${conc}.json"
        oha -n "$REQUESTS_PER_RUN" -c "$conc" --no-tui --output-format json \
            -m POST \
            -H "Content-Type: application/json" \
            -D "${TMPDIR_BATCH}/batch_${bs}.json" \
            "${PDP_URL}/v1/batch_is_authorized" > "$RESULT_JSON" 2>/dev/null

        METRICS=$(extract_metrics "$RESULT_JSON")
        RPS=$(echo "$METRICS" | awk '{print $5}')
        P50=$(echo "$METRICS" | awk '{print $3}')
        P99=$(echo "$METRICS" | awk '{print $4}')
        DPS=$(python3 -c "print(f'{float(\"${RPS}\") * ${bs}:.1f}')")

        printf "%-12s %-13s %-10s %-10s %-10s %-15s\n" \
            "$bs" "$conc" "$RPS" "$P50" "$P99" "$DPS" | tee -a "$OUTFILE"
    done
done

echo "" | tee -a "$OUTFILE"
echo "Results saved to: ${OUTFILE}" | tee -a "$OUTFILE"
