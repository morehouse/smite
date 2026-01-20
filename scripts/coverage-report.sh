#!/bin/bash
#
# Generate an HTML coverage report from a corpus of fuzz inputs.
#
# Usage: ./scripts/coverage-report.sh <corpus-dir> [output-dir]
#
# This script:
# 1. Builds (if needed) a coverage-instrumented Docker image
# 2. Runs each corpus input through lnd-scenario
# 3. Merges coverage data and generates an HTML report
#
set -eu

if [ $# -lt 1 ]; then
    echo "Usage: $0 <corpus-dir> [output-dir]"
    echo ""
    echo "Arguments:"
    echo "  corpus-dir  Directory containing fuzz input files"
    echo "  output-dir  Output directory for coverage report (default: ./coverage-report)"
    echo ""
    echo "Environment variables:"
    echo "  REBUILD=1   Force rebuild of Docker image"
    echo "  PARALLEL=N  Number of parallel jobs (default: number of CPU cores)"
    exit 1
fi

# Convert to absolute paths to prevent Docker from interpreting relative paths
# as named volumes
CORPUS_DIR="$(cd "$1" && pwd)"
OUTPUT_DIR="${2:-./coverage-report}"
OUTPUT_DIR="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"

# Validate PARALLEL
MAX_JOBS="${PARALLEL:-$(nproc)}"
if ! [[ "$MAX_JOBS" =~ ^[0-9]+$ ]] || [ "$MAX_JOBS" -eq 0 ]; then
    echo "Error: PARALLEL must be a positive integer, got '$MAX_JOBS'"
    exit 1
fi

# Verify corpus directory exists
if [ ! -d "$CORPUS_DIR" ]; then
    echo "Error: Corpus directory '$CORPUS_DIR' does not exist"
    exit 1
fi

# Count inputs
INPUT_COUNT=$(find "$CORPUS_DIR" -maxdepth 1 -type f | wc -l)
if [ "$INPUT_COUNT" -eq 0 ]; then
    echo "Error: No input files found in '$CORPUS_DIR'"
    exit 1
fi

echo "Found $INPUT_COUNT input files in corpus"

# Build coverage image if needed (use REBUILD=1 to force rebuild)
if [ "${REBUILD:-}" = "1" ] || ! docker image inspect smite-lnd-coverage >/dev/null 2>&1; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    SMITE_DIR="$(dirname "$SCRIPT_DIR")"

    echo "Building coverage Docker image..."
    docker build -t smite-lnd-coverage -f "$SMITE_DIR/workloads/lnd/Dockerfile.coverage" "$SMITE_DIR"
fi

# Create output directories (remove old data to avoid mixing with previous runs)
rm -rf "$OUTPUT_DIR/covdata" "$OUTPUT_DIR/merged"
mkdir -p "$OUTPUT_DIR/covdata" "$OUTPUT_DIR/merged"

echo "Processing corpus inputs with $MAX_JOBS parallel jobs..."

# Runs a single corpus input through the LND scenario.
#
# Note: We mount the entire corpus directory because AFL++ filenames contain
# colons (e.g., id:000000,time:0) which conflict with Docker's -v syntax. Also
# each input gets its own coverage subdirectory to avoid filename collisions.
run_input() {
    local i="$1"
    local input_name="$2"
    local covdir="$OUTPUT_DIR/covdata/input-$i"

    mkdir "$covdir"
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$CORPUS_DIR:/corpus:ro" \
        -v "$covdir:/covdata" \
        -e SMITE_INPUT="/corpus/$input_name" \
        -e GOCOVERDIR=/covdata \
        smite-lnd-coverage \
        /lnd-scenario >/dev/null 2>&1 || true
}

# Process inputs in parallel with job limiting
i=0
active_jobs=0
for input in "$CORPUS_DIR"/*; do
    [ -f "$input" ] || continue

    INPUT_NAME=$(basename "$input")

    # Run in background
    run_input "$i" "$INPUT_NAME" &
    active_jobs=$((active_jobs + 1))
    i=$((i + 1))

    # Limit parallelism
    if [ "$active_jobs" -ge "$MAX_JOBS" ]; then
        echo "Progress: $i/$INPUT_COUNT inputs started"
        wait -n 2>/dev/null || true
        active_jobs=$((active_jobs - 1))
    fi
done

# Wait for remaining jobs
echo "Waiting for remaining jobs to complete..."
wait

echo ""
echo "Merging coverage data and generating report..."

# Merge coverage and generate report
docker run --rm --user "$(id -u):$(id -g)" \
    -v "$OUTPUT_DIR:/output" \
    -e GOCACHE=/tmp/go-cache \
    -e GOPATH=/tmp/go \
    smite-lnd-coverage \
    sh -c '
        set -eu

        # Build comma-separated list of coverage directories
        COVDIRS=$(find /output/covdata -mindepth 1 -maxdepth 1 -type d | sort | tr "\n" "," | sed "s/,$//")
        if [ -z "$COVDIRS" ]; then
            echo "Error: No coverage data found"
            exit 1
        fi

        echo "Merging coverage data from $(echo "$COVDIRS" | tr "," "\n" | wc -l) directories..."
        go tool covdata merge -i="$COVDIRS" -o=/output/merged

        echo "Converting to text profile..."
        go tool covdata textfmt -i=/output/merged -o=/output/coverage.txt

        echo "Generating HTML report..."
        cd /lnd && go tool cover -html=/output/coverage.txt -o=/output/coverage.html

        echo ""
        echo "Coverage summary:"
        go tool covdata percent -i=/output/merged
    '

echo ""
echo "Coverage report generated: $OUTPUT_DIR/coverage.html"
