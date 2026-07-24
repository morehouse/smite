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

### smitebot bench-exec

Benchmarks Nyx execution speed by running a single input through the target's VM many times. Each execution is a snapshot restore plus one target run, so the results isolate VM/snapshot and target speed from AFL++'s mutation and scheduling overhead.

```bash
smitebot bench-exec campaign.toml
smitebot bench-exec campaign.toml --input testcase.bin --iterations 5000
```

- `--input`: Input file to execute repeatedly. Defaults to a single `0x00` byte. The default is handy for quickly measuring performance gains that come from the target itself rather than a specific test case: every exec still does the live-target ping-pong the executor uses to confirm the VM is up, so it exercises that path. It's a fast way to check improvements like JVM warmup/optimization.
- `-n`, `--iterations`: Number of timed executions per run (default `1000`).
- `-r`, `--repeat`: Number of full boot+measure runs to average over (default `1`). Each run boots a fresh VM, so repeats capture boot- and snapshot-level variance a single run cannot.
- `--worker-id`: Nyx worker id, which also selects the pinned CPU (default `0`).
- `--max-input-size`: Input buffer size in bytes for the VM. Defaults to the input size rounded up to a 4 KiB page, so the snapshot resets only as much memory as the fixed input needs; pass `1048576` to match AFL++'s 1 MiB buffer.
- `-t`, `--timeout`: Per-execution timeout in seconds; an exec that runs longer is counted as timed out (default `2`).
- `--no-build`: Skip building the image and setting up the sharedir; reuse an existing one.

Like `start`, `bench-exec` builds the Docker image and sets up the Nyx sharedir before running, so it works from a clean checkout. Pass `--no-build` to skip that and reuse an already-prepared sharedir (`sharedir/config.ron`) from a prior `start`, `bench-exec`, or `scripts/setup-nyx.sh`. Either way it needs `libnyx.so` under `aflpp_path`, which it loads at runtime the same way `afl-fuzz` does.

The first execution of each run creates the snapshot (VM boot, target init, snapshot capture) and is timed separately. The remaining executions are timed as a group and reported as steady-state throughput:

```
Smite Nyx benchmark
  target:      lnd/encrypted_bytes
  sharedir:    /tmp/smite-nyx
  input size:  1 bytes
  input buffer:4096 bytes
  iterations:  1000
  repeats:     1

  snapshot creation (first exec): 512.30 ms

  steady-state (snapshot restore + target run):
    execs/sec: 1234.5
    wall time: 810.20 ms
    latency:   min 0.7 µs  mean 0.8 µs  median 0.8 µs  p99 1.2 µs  max 3.4 ms
    input execution: mean 0.5 µs  median 0.5 µs   (guest runtime)
    nyx overhead:    mean 0.3 µs  median 0.3 µs   (restore + reset + ipc; 42 dirty pages/exec)
    failed iterations: 0 / 1000
    coverage determinism: 98.4% stable (12 / 750 edges fluctuated)
```

Each per-exec latency is split into two parts read from libnyx's auxiliary buffer:

- **input execution** is the guest runtime the target actually spent processing the input, measured inside the VM. This is the "true" cost of the input; use it to tell whether a change made the target's own work faster.
- **nyx overhead** is the wall time minus that guest runtime: snapshot restore/reset plus hypercall round-trips. `dirty pages/exec` is the number of pages restored each execution, the main driver of that overhead, so a change that dirties more memory (e.g. spawning a process per block) shows up as both higher overhead and more dirty pages.

`coverage determinism` reports how reproducible the target's edge coverage is across the identical executions. Each execution's AFL coverage bitmap is captured and its per-edge hit counts are bucketed with AFL's count classes; an edge whose bucketed count is not identical across all executions is counted as fluctuated, and the denominator is the edges hit at least once. High determinism (close to 100%) means the same input reliably reaches the same code; fluctuation points to nondeterminism (uninitialized memory, timing-dependent branches, ASLR, background threads) that adds noise to the fuzzer's coverage signal. Bucketing means benign loop-trip jitter is not counted. Capturing the bitmap is timed separately and excluded from `execs/sec`, so the throughput numbers are unaffected.

With `--repeat` greater than 1 each run is reported separately, followed by an aggregate (mean, stddev, and range of execs/sec across runs; coverage determinism is pooled over all runs).

`failed iterations` counts executions that ended in a crash, timeout, or error rather than a clean run; a non-zero count means the input is not a clean steady-state case and the numbers are skewed.

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
