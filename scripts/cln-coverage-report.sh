#!/bin/bash
#
# Generate an HTML coverage report for CLN from a corpus of fuzz inputs.
#
# Usage: ./scripts/cln-coverage-report.sh <corpus-dir> [output-dir]
#
# This script:
# 1. Builds (if needed) a coverage-instrumented Docker image
# 2. Runs each corpus input through cln-scenario
# 3. Merges profraw files and generates an HTML report
#
set -eu

if [ $# -lt 1 ]; then
    echo "Usage: $0 <corpus-dir> [output-dir]"
    echo ""
    echo "Arguments:"
    echo "  corpus-dir  Directory containing fuzz input files"
    echo "  output-dir  Output directory for coverage report (default: ./cln-coverage-report)"
    echo ""
    echo "Environment variables:"
    echo "  REBUILD=1   Force rebuild of Docker image"
    echo "  PARALLEL=N  Number of parallel jobs (default: number of CPU cores)"
    exit 1
fi

# Convert to absolute paths to prevent Docker from interpreting relative paths
# as named volumes
CORPUS_DIR="$(cd "$1" && pwd)"
OUTPUT_DIR="${2:-./cln-coverage-report}"
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
if [ "${REBUILD:-}" = "1" ] || ! docker image inspect smite-cln-coverage >/dev/null 2>&1; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    SMITE_DIR="$(dirname "$SCRIPT_DIR")"

    echo "Building coverage Docker image..."
    docker build -t smite-cln-coverage -f "$SMITE_DIR/workloads/cln/Dockerfile.coverage" "$SMITE_DIR"
fi

# Create output directories (remove old data to avoid mixing with previous runs)
rm -rf "$OUTPUT_DIR/profraw" "$OUTPUT_DIR/html"
mkdir -p "$OUTPUT_DIR/profraw"

# Runs a single corpus input through the CLN scenario.
#
# LLVM source-based coverage writes profraw files atomically on process exit
# (via atexit handler), so unlike Go coverage there is no risk of truncated
# files. We still retry on failure since Docker containers can fail to start
# under high parallel load.
#
# CLN spawns subdaemons as separate processes, each producing its own profraw
# file. We use %p_%m in the profile filename to get unique files per process.
#
# Note: We mount the entire corpus directory because AFL++ filenames contain
# colons (e.g., id:000000,time:0) which conflict with Docker's -v syntax. Also
# each input gets its own profraw subdirectory to avoid filename collisions.
run_input() {
    local i="$1"
    local input_name="$2"
    local profdir="$OUTPUT_DIR/profraw/input-$i"
    local max_retries=3

    for ((attempt=0; attempt<max_retries; attempt++)); do
        rm -rf "$profdir"
        mkdir "$profdir"

        docker run --rm --user "$(id -u):$(id -g)" \
            -v "$CORPUS_DIR:/corpus:ro" \
            -v "$profdir:/profdata" \
            -e SMITE_INPUT="/corpus/$input_name" \
            -e LLVM_PROFILE_FILE="/profdata/cln-%p_%m.profraw" \
            smite-cln-coverage \
            /cln-scenario >/dev/null 2>&1 || true

        # Success if at least one profraw file was produced
        if ls "$profdir"/*.profraw >/dev/null 2>&1; then
            return 0
        fi

        # Retry with backoff
        sleep $((attempt + 1))
    done

    echo "Warning: input-$i ($input_name) produced no coverage data after $max_retries attempts" >&2
}

# Run first input as smoke test to verify the Docker image works.
echo "Running first input as smoke test..."
FIRST_INPUT=$(find "$CORPUS_DIR" -maxdepth 1 -type f | head -1)
if [ -z "$FIRST_INPUT" ]; then
    echo "Error: No input files found"
    exit 1
fi
FIRST_NAME=$(basename "$FIRST_INPUT")
run_input 0 "$FIRST_NAME"

if ! ls "$OUTPUT_DIR/profraw/input-0"/*.profraw >/dev/null 2>&1; then
    echo "Error: First input produced no coverage data"
    exit 1
fi
echo "Smoke test passed"

echo "Processing remaining $((INPUT_COUNT - 1)) inputs with $MAX_JOBS parallel jobs..."

# Process remaining inputs in parallel with job limiting
i=1
active_jobs=0
for input in "$CORPUS_DIR"/*; do
    [ -f "$input" ] || continue
    INPUT_NAME=$(basename "$input")

    # Skip first input (already processed)
    if [ "$INPUT_NAME" = "$FIRST_NAME" ]; then
        continue
    fi

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

# Merge profraw files and generate report.
# Unlike LDK (single binary), CLN has multiple instrumented binaries
# (lightningd, subdaemons, plugins). Pass all of them to llvm-cov via -object
# flags.
docker run --rm --user "$(id -u):$(id -g)" \
    -v "$OUTPUT_DIR:/output" \
    smite-cln-coverage \
    sh -c '
        set -eu

        # Build list of profraw files
        find /output/profraw -name "*.profraw" -type f > /tmp/profraw-list.txt
        PROFRAW_COUNT=$(wc -l < /tmp/profraw-list.txt)
        echo "Found $PROFRAW_COUNT profraw files"

        if [ "$PROFRAW_COUNT" -eq 0 ]; then
            echo "Error: No profraw files found"
            exit 1
        fi

        # Merge all profraw files into a single profdata file
        echo "Merging profraw files..."
        llvm-profdata merge -sparse -f /tmp/profraw-list.txt -o /output/merged.profdata

        # Build -object flags for all instrumented binaries (subdaemons + plugins).
        # Subdaemons are in libexec/c-lightning/lightning_*, plugins are in
        # libexec/c-lightning/plugins/.
        OBJECTS=""
        for bin in /usr/local/libexec/c-lightning/lightning_* \
                   /usr/local/libexec/c-lightning/plugins/*; do
            [ -f "$bin" ] && OBJECTS="$OBJECTS -object=$bin"
        done

        # Generate HTML report with annotated source
        echo "Generating HTML report..."
        llvm-cov show \
            /usr/local/bin/lightningd \
            $OBJECTS \
            --instr-profile=/output/merged.profdata \
            --format=html \
            --output-dir=/output/html \
            --show-line-counts-or-regions

        echo ""
        echo "Coverage summary:"
        llvm-cov report \
            /usr/local/bin/lightningd \
            $OBJECTS \
            --instr-profile=/output/merged.profdata
    '

echo ""
echo "Coverage report generated: $OUTPUT_DIR/html/index.html"
