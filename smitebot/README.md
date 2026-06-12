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

## Configuration

Campaign settings are stored in a TOML file. See [`sample-campaign.toml`](sample-campaign.toml) for a complete example.

| Field        | Required | Description                                                          |
| ------------ | -------- | -------------------------------------------------------------------- |
| `target`     | yes      | Lightning implementation to fuzz (`lnd`, `cln`, `ldk`, or `eclair`). |
| `scenario`   | yes      | Scenario binary selected by the workload Dockerfile.                 |
| `aflpp_path` | yes      | Path to the AFL++ source tree.                                       |
| `smite_dir`  | yes      | Path to the smite repository root.                                   |
| `runners`    | yes      | Number of parallel AFL++ instances to launch (must be at least 1).   |
| `seed_dir`   | no       | Directory containing seed inputs; omit to start from an empty corpus.|
| `output_dir` | yes      | AFL++ output directory for findings and stats.                       |
| `sharedir`   | yes      | Nyx shared directory path; created automatically by `smitebot start`.|
| `image`      | no       | Docker image tag override; defaults to `smite-<target>-<scenario>`.  |
| `afl_env`    | no       | Extra environment variables passed to AFL++ instances.               |
| `afl_flags`  | no       | Extra CLI flags appended to `afl-fuzz`.                              |

## Commands

### smitebot config

`smitebot config` validates a campaign configuration file, reports the resolved settings, and checks that referenced paths exist on disk.

```bash
smitebot config sample-campaign.toml
```

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
