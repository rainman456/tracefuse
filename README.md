# TraceFuse

TraceFuse is an adaptive Firecracker sandbox for AI-generated Python workloads. It observes a workload’s real behavior, proposes a least-privilege policy, requires human approval, and then replays the workload under that policy inside a disposable microVM.

> **Core idea:** observe first, trust never by default, enforce fail-closed.

---

## How It Works

TraceFuse runs each workload in an isolated environment and produces an auditable trace.

1. **Observe** — Run the code once in observe mode. TraceFuse records file access, process execution, network destinations, syscalls, and blocked actions.
2. **Propose** — The controller converts observed behavior into a policy proposal. Risky findings (metadata endpoints, sensitive files, shells, unexpected private ranges) are reported but **not** automatically allowlisted.
3. **Approve** — A human reviews and explicitly approves the policy (`tracefuse policy approve ...`).
4. **Enforce** — The workload runs again under the approved policy. Network access is constrained by nftables, syscalls by seccomp, and resource usage by cgroups. Anything outside policy is blocked.
5. **Diff** — Compare two traces to detect behavioral regressions (for example, a “useful” run vs. a malicious variant).

### Two backends

| Backend | Use case | Isolation |
|---|---|---|
| `local` | Fast developer loop on any laptop | **Not a security boundary** (shares host kernel) |
| `firecracker` | Real isolation on Linux/KVM | MicroVM boundary (separate kernel, guest init, nftables/seccomp/cgroups) |

### What gets enforced in the Firecracker backend

- **Network:** nftables `policy drop` allowlist in the guest; only approved destinations are reachable.
- **Syscalls:** dangerous syscalls are denied; in enforce mode, only syscalls seen during the approved observe run (plus a minimal runtime set) are allowed.
- **Resources:** cgroup v2 limits (`memory.max`, `pids.max`) applied to the workload.
- **Observation:** guest eBPF observer (`bpftrace`) + Python audit-hook tracer (`tracer.py`) emit events over the serial console.
- **Fail closed:** missing policy/nftables/cgroup artifacts or enforcement failures cause the run to refuse execution.

---

## Quick Start (Local, no KVM)

Runs on any machine with Python 3 and Go installed. This is for development of the policy loop only.

```bash
git clone https://github.com/rainman456/tracefuse.git
cd tracefuse

# 1) Run unit tests
make test

# 2) Run end-to-end demo (observe -> approve -> enforce -> attack blocked -> diff)
make demo

# 3) Run demo and verify the security claims
make demo 2>&1 | tee demo.log && make verify-demo
```

`make demo` builds `bin/tracefuse` automatically.

The local backend is useful for iteration, but **it does not provide VM isolation**.

---

## Run with Real Isolation (Firecracker on Linux/KVM)

### Prerequisites

- Linux host with KVM enabled (`/dev/kvm` present and accessible)
- Firecracker binary (`firecracker --version`)
- Go toolchain (to build `tracefuse`)
- Python 3
- Host tools: `mkfs.ext4`, `truncate`, `resize2fs`, `e2fsck`, `ip`, `sudo`, `curl`
- A Firecracker-compatible **uncompressed** Linux kernel (`vmlinux`) with BTF enabled
- A base Ubuntu ext4 rootfs image

Recommended kernel config (minimum for TraceFuse guest):

```text
CONFIG_DEBUG_INFO_BTF=y
CONFIG_BPF_EVENTS=y
CONFIG_BPF_SYSCALL=y
CONFIG_FTRACE=y
CONFIG_NF_TABLES=y
CONFIG_NF_TABLES_IPV4=y
CONFIG_CGROUPS=y
CONFIG_MEMCG=y
CONFIG_CGROUP_PIDS=y
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_EXT4_FS=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_NET=y
```

### 1) Build the guest image

TraceFuse expects:
- `guest/out/vmlinux` — uncompressed kernel with `.BTF`
- `guest/out/rootfs.ext4` — ext4 rootfs with TraceFuse guest components installed

Build them from a base rootfs and kernel:

```bash
# From repo root
BASE_ROOTFS=/path/to/ubuntu.ext4 \
KERNEL=/path/to/vmlinux \
make guest
```

What `guest/build-rootfs.sh` does:
- Validates kernel is ELF `vmlinux` and contains a `.BTF` section
- Copies kernel to `guest/out/vmlinux`
- Copies base rootfs to `guest/out/rootfs.ext4` and grows it to 2 GiB (if smaller)
- Mounts the image and installs guest runtime packages: `python3`, `python3-seccomp`, `bpftrace`, `nftables`, `iproute2`, `ca-certificates`, `curl`
- Installs TraceFuse guest files:
  - `/sbin/tracefuse-init` (guest PID 1)
  - `/opt/tracefuse/observer.bt` (bpftrace observer)
  - `/opt/tracefuse/tracer.py` (Python audit-hook policy agent)
- Verifies required binaries/files exist inside the image

> **Tip:** If your base image is minimal, ensure `apt` works in chroot (the script bind-mounts `/dev`, `/dev/pts`, `/proc`, `/sys` and prepares apt dirs).

### 2) Create host TAP networking (no NAT)

TraceFuse uses a host-only TAP device for guest networking. No NAT is configured by default.

```bash
./scripts/setup-tap.sh tf0
# prints: export TF_TAP=tf0
```

This creates `tf0` with `172.16.0.1/30` on the host. The guest uses `172.16.0.2/30` and default route via `172.16.0.1`.

### 3) Run host preflight checks

`make host-check` is read-only and validates the host is ready:

```bash
make host-check
# or directly:
TF_TAP=tf0 TF_KERNEL=guest/out/vmlinux TF_ROOTFS=guest/out/rootfs.ext4 ./scripts/check-host.sh
```

It checks:
- Linux host + `/dev/kvm` access
- `firecracker` binary present
- Kernel is ELF and has `.BTF`
- Rootfs exists and is ext4
- Required host tools installed
- TAP device exists, has `172.16.0.1/30`, and is UP
- (Optional) mock API reachability on `http://172.16.0.1:8080/data`

### 4) Run the Firecracker demo

```bash
TF_BACKEND=firecracker TF_TAP=tf0 make demo
```

The demo script (`scripts/demo.sh`) will:
- Start a mock API server on `172.16.0.1:8080` (for firecracker backend)
- Run `demos/safe.py` in observe mode
- Run `demos/useful.py` in observe mode (learns the mock API destination)
- Approve the proposed policy
- Run `demos/useful.py` in enforce mode (should succeed)
- Run `demos/malicious.py` in enforce mode under the same policy (should be blocked)
- Run `demos/malicious.py` in observe mode (records findings, no trust granted)
- Diff useful vs malicious traces

### 5) Verify the demo guarantees

```bash
TF_BACKEND=firecracker TF_TAP=tf0 make demo 2>&1 | tee demo.log
./scripts/verify-demo.sh demo.log
```

`verify-demo.sh` checks for expected outcomes (approved policy, allowed useful run, blocked metadata/shell/sensitive-file actions, and regression diff).

---

## VM Creation and Execution Lifecycle (Firecracker backend)

For each `tracefuse run --backend firecracker ...` invocation, TraceFuse creates a **fresh** microVM:

1. **Prepare workspace** (temp dir)
   - Copies workload as `/workspace/main.py` in a workspace image
   - Writes `.tracefuse/mode`, `.tracefuse/mock_host`, and (in enforce mode) `policy.json`, `nft.rules`, `hosts`, `seccomp.json`
   - Builds a 64M ext4 workspace image (`mkfs.ext4 -d ...`)

2. **Prepare disposable rootfs**
   - Copies `guest/out/rootfs.ext4` to a per-run temporary rootfs file
   - The base image is never modified by a run

3. **Boot microVM via Firecracker API**
   - Creates Firecracker config (kernel, rootfs drive, workspace drive, vCPU/memory, TAP network if configured)
   - Starts the VM and connects to the serial console

4. **Guest init (`/sbin/tracefuse-init`, PID 1)**
   - Mounts `/proc`, `/sys`, `/dev`, cgroup v2, debugfs/tracefs
   - Mounts workspace (`/dev/vdb`) at `/workspace`
   - Configures guest network (`172.16.0.2/30`, default route `172.16.0.1`) when `eth0` exists
   - In enforce mode: **fails closed** if policy/nft rules missing or nftables cannot load
   - Sets cgroup limits and runs workload in `/sys/fs/cgroup/workload`
   - Starts bpftrace observer (`/opt/tracefuse/observer.bt`) when available
   - Executes workload via `python3 -I -B /opt/tracefuse/tracer.py /workspace/main.py`
   - Emits tagged console lines (`TFEVT`, `TFOUT`, `TFEXIT`) and powers off

5. **Controller ingests console as untrusted input**
   - Parses events, stdout, exit code, and nftables block lines
   - Normalizes and stores trace in `.tracefuse/traces/`

6. **Cleanup**
   - VM destroyed and temporary run directory removed

This per-run copy model prioritizes isolation and reproducibility over boot-time optimization.

---

## CLI Reference

```bash
tracefuse run --code FILE [--mode observe|enforce] [--policy ID] [--backend local|firecracker]
tracefuse policy list|show|approve ID
tracefuse diff TRACE_A TRACE_B
tracefuse report TRACE
```

### `tracefuse run` flags

| Flag | Default | Description |
|---|---|---|
| `--code` | (required) | Python file to execute |
| `--mode` | `observe` | `observe` or `enforce` |
| `--policy` | empty | Approved policy ID (required for `enforce`) |
| `--backend` | `local` (`TF_BACKEND`) | `local` or `firecracker` |
| `--timeout` | `30s` | Hard execution timeout |
| `--memory-mb` | `256` | Guest memory limit |
| `--vcpus` | `1` | Guest vCPUs |
| `--fc-bin` | `firecracker` (`TF_FIRECRACKER`) | Firecracker binary |
| `--kernel` | `guest/out/vmlinux` (`TF_KERNEL`) | Guest kernel path |
| `--rootfs` | `guest/out/rootfs.ext4` (`TF_ROOTFS`) | Guest rootfs path |
| `--tap` | empty (`TF_TAP`) | Host TAP device (empty = no network) |
| `--mock-host` | `127.0.0.1` (`TF_MOCK_HOST`) | Host address the workload should call for mock API |
| `--trusted-hosts` | empty (`TF_TRUSTED_HOSTS`) | Comma-separated hosts that may be learned when private (e.g., TAP gateway) |
| `--python` | `python3` (`TF_PYTHON`) | Python interpreter (local backend) |

### Common environment variables

| Variable | Purpose |
|---|---|
| `TRACEFUSE_STATE` | Override state directory (default `.tracefuse`) |
| `TF_BACKEND` | Default backend (`local` / `firecracker`) |
| `TF_TAP` | TAP device name (e.g., `tf0`) |
| `TF_KERNEL` | Path to guest kernel (`vmlinux`) |
| `TF_ROOTFS` | Path to guest rootfs (`ext4`) |
| `TF_FIRECRACKER` | Path to firecracker binary |
| `TF_MOCK_HOST` | Mock API host address seen by guest/workload |
| `TF_TRUSTED_HOSTS` | Allowlisted private host(s) for policy learning (e.g., `172.16.0.1`) |
| `TF_SECCOMP_STRICT` | Stricter seccomp mode (removes runtime compatibility set) |
| `TF_REQUIRE_SECCOMP` | Fail closed (exit 126) if seccomp cannot be enforced as required |
| `TMPDIR` | Use a large temp dir (Firecracker backend copies the 2 GiB rootfs per run) |

---

## Project Layout

```text
cmd/tracefuse/          CLI entrypoint
internal/firecracker/   Firecracker microVM lifecycle (REST API over unix socket)
internal/sandbox/       Backend implementations (local, firecracker) + console parsing
internal/policy/        Policy proposal, evaluation, nftables/seccomp artifact generation
internal/diff/          Behavioral diff between traces
internal/trace/         Trace/event schema
internal/report/        Human-readable run output, findings, cross-checks
internal/store/         Local state persistence (.tracefuse/)
guest/                  Guest init (PID 1), bpftrace observer, rootfs build script
scripts/                Demo, host preflight, TAP setup, verification
demos/                  Sample workloads (safe/useful/malicious) + mock API server
reports/                Captured evidence artifacts (logs, casts, recordings)
docs/                   Architecture, threat model, explainer
```

---

## Security Model (Current)

TraceFuse enforces the following rules in code:

1. **Observation never grants permission.** Findings such as metadata IPs, private ranges, shells, sensitive files, and privilege changes are excluded from proposals unless explicitly trusted by the operator (and never for metadata/link-local endpoints).
2. **Enforce mode requires approval.** Unapproved policies are rejected.
3. **Baseline deny always applies.** Sensitive targets (e.g., metadata endpoints, `/etc/shadow`) remain blocked.
4. **Network enforcement fails closed.** Guest nftables uses `policy drop` with explicit allow rules.
5. **Guest signals are untrusted input.** The controller treats console events as untrusted and normalizes them outside the VM.
6. **Syscall guardrails are enforced.** Dangerous syscalls are denied; enforce mode uses an approved-observation-derived seccomp allowlist (with configurable strictness/fail-closed behavior).

> See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for details and boundaries.

---

## Troubleshooting / Operational Notes

- **`/tmp` is too small (tmpfs):** set `TMPDIR=$HOME/tmp` (or another large disk path). The Firecracker backend copies the rootfs per VM.
- **`/dev/kvm` permission denied:** add your user to the `kvm` group and re-login.
- **TAP missing / wrong address:** run `./scripts/setup-tap.sh tf0` and re-run `make host-check`.
- **Kernel has no `.BTF`:** rebuild/use a kernel with `CONFIG_DEBUG_INFO_BTF=y` (required for bpftrace observation).
- **`nft` or `bpftrace` missing in guest:** rebuild the rootfs with `make guest`; the build script verifies guest dependencies.
- **Demo cannot reach mock API in Firecracker mode:** ensure mock server binds `172.16.0.1` and `TF_TAP=tf0`/`TF_TRUSTED_HOSTS` are set appropriately (the demo script handles this).
- **Slow or flaky VM boot on nested virtualization:** use a bare-metal/KVM-capable instance and confirm CPU virtualization flags.

---

## Verified Firecracker Run (Evidence)

Exercised on an Ubuntu 26.04 x86_64 EC2 host with KVM, Firecracker v1.18.0, and a Firecracker CI kernel (6.18.62):

- `make host-check` → PASS
- `TF_BACKEND=firecracker TF_TAP=tf0 make demo` → PASS
- `./scripts/verify-demo.sh demo.log` → PASS

Observed guarantees:
- Useful workload succeeded under approved policy (mock API data returned)
- Malicious variant was blocked under the same policy (`169.254.169.254:80`, `curl`, `/etc/shadow`)
- Behavioral diff reported regression

Evidence files:
- `reports/stage2-host-check.txt`
- `reports/stage2-demo.log`
- `reports/stage2-verify-demo.txt`

Recording:
- [Watch MP4](reports/stage2-demo.mp4)
- [Permanent asciinema cast](reports/stage2-demo.cast)
- [Online asciinema replay](https://asciinema.org/a/CSKovFSaPx55lxZy)

![TraceFuse Stage 2 demo](reports/stage2-demo.gif)

---

## Roadmap

Planned / not yet implemented (see `docs/`):
- arm64 syscall tables
- Snapshot-restore fast path in CLI
- vsock control channel (replace serial console transport)
- Signed trace receipts
- IPv6 support
- Web UI

---

## Further Reading

- [`docs/EXPLAINER.md`](docs/EXPLAINER.md) — plain-English walkthrough
- [`docs/architecture.md`](docs/architecture.md) — system architecture
- [`docs/threat-model.md`](docs/threat-model.md) — threat model and boundaries
- [`docs/TRACEFUSE_VISUAL_GUIDE.md`](docs/TRACEFUSE_VISUAL_GUIDE.md) — visual guide (if present)

## Sources / Inspiration

- Firecracker design docs and announcement
- Fly.io sandboxing posts
- Modal sandbox posts
- Datadog eBPF hardening lessons
- CubeSandbox networking notes
