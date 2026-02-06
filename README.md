# Smite

Smite is a coverage-guided fuzzing framework for Lightning Network implementations, derived from [fuzzamoto](https://github.com/dergoegge/fuzzamoto).

## Supported Targets

- [LND](https://github.com/lightningnetwork/lnd)
- [LDK](https://github.com/lightningdevkit/ldk-node)

## Prerequisites

- x86_64 architecture
- Modern Linux operating system
- Docker
- [AFL++](https://github.com/AFLplusplus/AFLplusplus) built from source with Nyx mode

## Quick Start

Choose a target (LND or LDK) and follow the steps below:

```bash
# Build the Docker image
docker build -t smite-lnd -f workloads/lnd/Dockerfile .  # for LND
docker build -t smite-ldk -f workloads/ldk/Dockerfile .  # for LDK

# Enable the KVM VMware backdoor (required for Nyx)
./scripts/enable-vmware-backdoor.sh

# Create the Nyx sharedir
./scripts/setup-nyx.sh /tmp/smite-nyx smite-lnd ~/AFLplusplus  # for LND
./scripts/setup-nyx.sh /tmp/smite-nyx smite-ldk ~/AFLplusplus  # for LDK

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
CRASH=/tmp/smite-out/default/crashes/id:000000,...

# Reproduce in local mode (use the matching image and scenario binary)
docker run --rm -v $CRASH:/input.bin -e SMITE_INPUT=/input.bin smite-lnd /lnd-scenario
docker run --rm -v $CRASH:/input.bin -e SMITE_INPUT=/input.bin smite-ldk /ldk-scenario
```

### Coverage Report Mode

Generate an HTML coverage report showing which parts of LND were exercised by a fuzzing corpus:

```bash
# Generate coverage report from a fuzzing corpus
./scripts/coverage-report.sh /tmp/smite-out/default/queue/ ./coverage-report

# View the report
firefox ./coverage-report/coverage.html
```

## Project Structure

```
smite/              # Core Rust library (runners, scenarios, noise protocol, BOLT messages)
smite-nyx-sys/      # Nyx FFI bindings
smite-scenarios/    # Scenario implementations and target binaries
workloads/
  lnd/              # LND fuzzing workload (Dockerfile, init script)
  ldk/              # LDK fuzzing workload (Dockerfile, init script, ldk-node wrapper)
scripts/
  setup-nyx.sh              # Helper to create Nyx sharedirs
  enable-vmware-backdoor.sh # Enable KVM VMware backdoor for Nyx
  coverage-report.sh        # Generate a coverage report
```
