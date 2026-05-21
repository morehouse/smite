# smitebot

`smitebot` is the Smite automation CLI. It is intended to orchestrate common fuzzing workflows and reduce manual setup/operations.

## Install

Install `smitebot` once from this repository:

```bash
cargo install --path smitebot
```

After install, run it directly:

```bash
smitebot doctor
smitebot doctor --json
```

## Commands

### smitebot doctor

`smitebot doctor` validates host prerequisites before running Smite campaigns.

```bash
smitebot doctor
smitebot doctor --json
smitebot doctor --aflpp-path ~/AFLplusplus --smite-dir .
```

## Checks

- `x86_64` architecture
- CPU virtualization enabled (`vmx` or `svm`)
- `/dev/kvm` is present and openable
- Docker daemon is reachable (`docker info`)
- Required host tools (`bash`, `python3`)
- AFL++ tools (`afl-fuzz`, `afl-cmin`, `afl-tmin`, `afl-whatsup`) available on `PATH` or under `--aflpp-path`
- Nyx packer `hget` exists under AFL++
- `libnyx.so` is found on `LD_LIBRARY_PATH` or under `--aflpp-path`
- VMware backdoor is enabled
- Required Smite scripts are present and executable
- Required workload Dockerfiles are present

## JSON output

By default, output is in a human readable format. The `--json` flag changes output to structured JSON:

```json
{
  "checks": [
    { "name": "x86_64 architecture", "passed": true },
    { "name": "Docker daemon reachable", "passed": false, "reason": "docker info exited with status exit status: 1" }
  ],
  "overall": false
}
```
