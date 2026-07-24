# smitebot

`smitebot` is the Smite automation CLI. It orchestrates fuzzing campaigns against Lightning Network implementations using AFL++ and Nyx, reducing multi-step manual workflows to single commands.

## Install

```bash
cargo install --path smitebot
```

## Configuration

Campaign settings are stored in a TOML file. See [`sample-campaign.toml`](sample-campaign.toml) for a complete example.

| Field          | Required | Description                                                                               |
| -------------- | -------- | ----------------------------------------------------------------------------------------- |
| `target`       | yes      | Lightning implementation to fuzz (`lnd`, `cln`, `ldk`, or `eclair`).                      |
| `scenario`     | yes      | Scenario binary selected by the workload Dockerfile.                                      |
| `aflpp_path`   | yes      | Path to the AFL++ source tree.                                                            |
| `smite_dir`    | yes      | Path to the smite repository root.                                                        |
| `runners`      | yes      | Number of parallel AFL++ instances to launch (must be at least 1).                        |
| `seed_dir`     | no       | Directory containing seed inputs; omit to start from an empty corpus.                     |
| `output_dir`   | yes      | AFL++ output directory for findings and stats.                                            |
| `sharedir`     | yes      | Nyx shared directory path; created automatically by `smitebot start`.                     |
| `image`        | no       | Docker image tag override; defaults to `smite-<target>-<scenario>`.                       |
| `tmux_session` | no       | Custom tmux session name; defaults to the campaign ID. Must not contain `:`, `.`, or `#`. |
| `afl_env`      | no       | Extra environment variables passed to AFL++ instances.                                    |
| `afl_flags`    | no       | Extra CLI flags appended to `afl-fuzz`.                                                   |

## Commands

### smitebot start

Launches a fuzzing campaign. Builds the Docker image, sets up the Nyx sharedir, spawns parallel AFL++ instances inside a tmux session (one window per runner), and attaches to the session.

```bash
smitebot start campaign.toml
```

Each runner gets a deterministic strategy distribution:
- Power schedule (`-p`): round-robin across `fast`, `explore`, `coe`, `lin`, `quad`, `exploit`, `rare`
- `-a binary`: ~70% of secondary runners
- `AFL_DISABLE_TRIM`: ~60% of secondary runners
- `AFL_FINAL_SYNC`: primary runner only
- `AFL_IMPORT_FIRST`: enabled when runner count < 16
- `AFL_TESTCACHE_SIZE`: auto-sized from available RAM

For IR scenarios (scenario names starting with `ir`), the required AFL++ custom mutator environment variables are injected automatically. User `afl_env` values override strategy defaults.

`start` begins fresh campaigns only. If `output_dir` already holds a prior run's `fuzzer_stats`, it exits with an error instead of resuming (resume is not yet supported).

After spawning, startup is verified by polling for `fuzzer_stats` files. Because AFL++ writes `fuzzer_stats` only after calibrating every seed (minutes under Nyx), a runner is reported as failed the moment its tmux window exits rather than after a fixed timeout; the poll otherwise waits up to a generous ceiling (10 min) for a runner that stays alive but never starts. On failure, the tmux session is preserved with `remain-on-exit` so error output can be inspected.

Campaign state is saved to `~/.smitebot/runs/<campaign-id>/state.json` for use by future `stop` and `status` commands.

### smitebot stop

Stops a running campaign: reaps every runner's process group — afl-fuzz and its Nyx QEMU child, which shares the group — tears down the tmux session, and records the stop time in `state.json`.

```bash
smitebot stop <campaign-id>
```

`<campaign-id>` is the directory name under `~/.smitebot/runs` (printed by `smitebot start`). 

### smitebot status

Reports the status of a campaign. Detects whether the campaign is still running (its tmux session is alive) and adapts:

```bash
smitebot status <campaign-id>
smitebot status <campaign-id> --summary
```

- `--summary`: Print a one-shot text summary to the terminal instead of attaching to the live dashboard.
- `<campaign-id>` is the directory name under `~/.smitebot/runs` (printed by `smitebot start`).

### smitebot config

Validates a campaign configuration file, reports the resolved settings, and checks that referenced paths exist on disk.

```bash
smitebot config campaign.toml
smitebot config campaign.toml --json
```

- `--json`: Emit machine-readable JSON output. Both success and error paths produce valid JSON.

### smitebot build

Builds Smite workload Docker images. Accepts a campaign config file or standalone CLI flags. When both are provided, CLI flags override config values.

```bash
smitebot build --target lnd --scenario encrypted_bytes
smitebot build campaign.toml
smitebot build campaign.toml --target cln
smitebot build campaign.toml --coverage --no-cache
```

- `--target`: Target implementation to build. Required when no config file is provided.
- `--scenario`: Scenario binary for the workload Dockerfile. Required when no config file is provided.
- `--smite-dir`: Path to the smite repository root; defaults to `.` when no config file is provided.
- `--coverage`: Build a coverage-instrumented image.
- `--image`: Docker image tag; overrides the config value and the default naming convention.
- `--no-cache`: Perform a clean rebuild without using cached Docker layers.

Image tags follow the Smite convention: `smite-<target>-<scenario>` or `smite-<target>-<scenario>-coverage`.

### smitebot doctor

Validates host prerequisites before running Smite campaigns. Accepts a campaign config file or standalone CLI flags. When both are provided, CLI flags override config values.

```bash
smitebot doctor --aflpp-path ~/AFLplusplus
smitebot doctor campaign.toml
smitebot doctor campaign.toml --json
smitebot doctor campaign.toml --aflpp-path ~/other-aflpp
```

- `--aflpp-path`: Path to AFL++ source tree. Required when no config file is provided.
- `--smite-dir`: Path to the smite repository root; overrides the config value.
- `--json`: Emit machine-readable JSON output.

Checks performed:

- `x86_64` architecture
- CPU virtualization enabled (`vmx` or `svm`)
- `/dev/kvm` is present and openable
- Docker daemon is reachable (`docker version`)
- AFL++ built with Nyx support (`libnyx.so` under `--aflpp-path`)
- VMware backdoor is enabled
- AFL++ tools (`afl-fuzz`, `afl-cmin`, `afl-tmin`, `afl-whatsup`) are executable
- Required host tools (`bash`, `python`, `python3`, `tmux`)
- Required Smite scripts are present and executable
- Required workload Dockerfiles are present

JSON output example:

```json
{
  "checks": [
    { "name": "x86_64 architecture", "passed": true },
    { "name": "Docker daemon reachable", "passed": false, "reason": "docker version: exit status: 1" }
  ],
  "overall": false
}
```

### smitebot print-ir

Decodes a serialized IR program and prints it to standard output. IR programs are opaque postcard-encoded `Program`s, the same form the fuzzing loop serializes them in; point it at one to see what it actually does.

```bash
smitebot print-ir input.bin
smitebot print-ir output/default/crashes/id:000000,sig:06,...
```

- `path`: Path to a postcard-encoded IR program.

The program is printed using the IR's `Display` format, the same textual form the `smite-ir` mutator emits in its trim logs. An empty program prints `(empty program)`.
