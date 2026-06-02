# smitebot

`smitebot` is the Smite automation CLI. It is intended to orchestrate common fuzzing workflows and reduce manual setup/operations.

## Install

Install `smitebot` once from this repository:

```bash
cargo install --path smitebot
```

After install, run it directly:

```bash
smitebot doctor --aflpp-path ~/AFLplusplus
smitebot doctor --aflpp-path ~/AFLplusplus --json
```

## Commands

### smitebot build

`smitebot build` builds Smite workload Docker images for manual rebuilds and debugging.

```bash
smitebot build --target lnd --scenario encrypted_bytes
smitebot build --target cln --scenario noise --coverage
smitebot build --target ldk --scenario init --image local/ldk-init:debug --no-cache
```

Flags:

- `--target`: Workload implementation to build an image for (`lnd`, `cln`, `ldk`, or `eclair`).
- `--scenario`: Scenario that the image should run.
- `--coverage`: Build a coverage-instrumented image.
- `--image`: Use a custom image tag instead of the default tag used by Smite.
- `--smite-dir`: Path to the Smite repository root. Defaults to the current directory.
- `--no-cache`: Perform a clean rebuild without using cached Docker layers.

By default, image tags follow the existing Smite convention:

```text
smite-<target>-<scenario>
smite-<target>-<scenario>-coverage
```

### smitebot doctor

`smitebot doctor` validates host prerequisites before running Smite campaigns.

```bash
smitebot doctor --aflpp-path ~/AFLplusplus --smite-dir .
smitebot doctor --aflpp-path ~/AFLplusplus --smite-dir . --json
```

## Checks

- `x86_64` architecture
- CPU virtualization enabled (`vmx` or `svm`)
- `/dev/kvm` is present and openable
- Docker daemon is reachable (`docker version`)
- AFL++ built with Nyx support (`libnyx.so` under `--aflpp-path`)
- VMware backdoor is enabled
- AFL++ tools (`afl-fuzz`, `afl-cmin`, `afl-tmin`, `afl-whatsup`) are executable under `--aflpp-path`
- Required host tools (`bash`, `python`, `python3`)
- Required Smite scripts are present and executable
- Required workload Dockerfiles are present

## JSON output

By default, output is in a human readable format. The `--json` flag changes output to structured JSON:

```json
{
  "checks": [
    { "name": "x86_64 architecture", "passed": true },
    { "name": "Docker daemon reachable", "passed": false, "reason": "docker version: exit status: 1" }
  ],
  "overall": false
}
```
