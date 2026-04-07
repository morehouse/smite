# Smite

Smite is a coverage-guided fuzzing framework for Lightning Network implementations, derived from [fuzzamoto](https://github.com/dergoegge/fuzzamoto).

## Supported Targets

- [LND](https://github.com/lightningnetwork/lnd)
- [LDK](https://github.com/lightningdevkit/ldk-node)
- [CLN](https://github.com/ElementsProject/lightning)
- [Eclair](https://github.com/ACINQ/eclair)

## Prerequisites

- x86_64 architecture
- Modern Linux operating system
- Docker
- [AFL++](https://github.com/AFLplusplus/AFLplusplus) built from source with Nyx mode

## Quick Start

Choose a target (`lnd`, `ldk`, `cln`, or `eclair`) and a scenario (`encrypted_bytes`, `noise`, or `init`) and follow the steps below:

```bash
# Choose target and scenario
TARGET=lnd
SCENARIO=encrypted_bytes

# Build the Docker image
docker build -t smite-$TARGET-$SCENARIO -f workloads/$TARGET/Dockerfile --build-arg SCENARIO=$SCENARIO .

# Enable the KVM VMware backdoor (required for Nyx)
./scripts/enable-vmware-backdoor.sh

# Create the Nyx sharedir
./scripts/setup-nyx.sh /tmp/smite-nyx smite-$TARGET-$SCENARIO ~/AFLplusplus

# Create seed corpus
mkdir -p /tmp/smite-seeds
echo 'AAAA' > /tmp/smite-seeds/seed1

# Start fuzzing
~/AFLplusplus/afl-fuzz -X -i /tmp/smite-seeds -o /tmp/smite-out -- /tmp/smite-nyx
```

## Running Modes

### Nyx Mode

Uses the [Nyx hypervisor](https://nyx-fuzz.com/) for fast snapshot-based fuzzing.
AFL++ manages the fuzzing loop and coverage feedback.

The `-X` flag enables standalone Nyx mode:

```bash
afl-fuzz -X -i <seeds> -o <output> -- <sharedir>
```

### Local Mode

This mode runs without Nyx and is used to reproduce and debug crashes.

#### Reproducing Crashes

When AFL++ finds a crash:

```bash
# Get the crash input
cp /tmp/smite-out/default/crashes/<crashing-input> ./crash

# Reproduce in local mode (use the matching image and scenario binary)
docker run --rm -v $PWD/crash:/input.bin -e SMITE_INPUT=/input.bin smite-$TARGET-$SCENARIO /$TARGET-scenario
```

### Coverage Report Mode

Generate an HTML coverage report showing which parts of the target were exercised by a fuzzing corpus:

```bash
# Generate coverage report
./scripts/coverage-report.sh $TARGET $SCENARIO /tmp/smite-out/default/queue/

# View the report
firefox ./$TARGET-$SCENARIO-coverage-report/html/index.html
```

## Project Structure

```
smite/              # Core Rust library (runners, scenarios, noise protocol, BOLT messages)
smite-ir/           # Library to build and mutate Intermediate Representation (IR) programs
smite-nyx-sys/      # Nyx FFI bindings
smite-scenarios/    # Scenario implementations and target binaries
workloads/
  lnd/              # LND fuzzing workload (Dockerfile, init script)
  ldk/              # LDK fuzzing workload (Dockerfile, init script, ldk-node wrapper)
  cln/              # CLN fuzzing workload (Dockerfile, init script)
  eclair/           # Eclair fuzzing workload (Dockerfile, init script, instrumentation agent)
scripts/
  setup-nyx.sh              # Helper to create Nyx sharedirs
  enable-vmware-backdoor.sh # Enable KVM VMware backdoor for Nyx
  coverage-report.sh        # Generate a coverage report for any scenario
  symbolize-crash.sh        # Symbolize CLN crash report stack traces
```
