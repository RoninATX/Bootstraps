# VoidLink Detection Script

A bash script to check Linux systems for indicators of compromise (IOCs) associated with **VoidLink**, a sophisticated cloud-native malware framework discovered by Check Point Research in January 2026.

## Quick Start

### Remote Execution (one-liner)

```bash
curl -fsSL https://raw.githubusercontent.com/RoninATX/Bootstraps/main/voidlink-check.sh | sudo bash
```

### Local Execution

```bash
# Download the script
curl -O https://raw.githubusercontent.com/RoninATX/Bootstraps/main/voidlink-check.sh

# Make it executable
chmod +x voidlink-check.sh

# Run with root privileges
sudo ./voidlink-check.sh
```

> **Note:** Some checks require root privileges for full visibility into kernel modules, eBPF programs, network sockets, and system logs.

---

## What is VoidLink?

VoidLink is a Linux malware framework discovered by Check Point Research in December 2025. Key characteristics:

- **Cloud-first design** — Detects and targets AWS, GCP, Azure, Alibaba, and Tencent environments
- **Highly modular** — 30+ plugins for reconnaissance, credential theft, persistence, and lateral movement
- **Multiple rootkit options** — Uses LD_PRELOAD, kernel modules (LKM), or eBPF depending on the target kernel version
- **Adaptive evasion** — Adjusts behavior based on detected security tools
- **Container-aware** — Includes Docker escape and Kubernetes privilege escalation capabilities

As of the initial report, no real-world infections have been confirmed—the framework appears to still be in development. However, its sophistication suggests it's intended for serious use.

**Reference:** [Check Point Research - VoidLink Analysis](https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/)

---

## What the Script Checks

### Check 1: Known File Hashes

**What it does:** Scans common directories (`/tmp`, `/var/tmp`, `/dev/shm`, `/usr/local/bin`, `/opt`) for executable files and compares their SHA256 hashes against the known VoidLink samples published by Check Point.

**Why it matters:** If VoidLink's exact binaries are present on your system, this will catch them immediately. However, since malware can be recompiled with different hashes, a clean result here doesn't guarantee safety.

---

### Check 2: LD_PRELOAD Hooks

**What it does:** Checks three things:
1. Whether `/etc/ld.so.preload` exists and contains entries
2. Whether the current shell has `LD_PRELOAD` set
3. Whether any running process has `LD_PRELOAD` in its environment

**Why it matters:** `LD_PRELOAD` forces the dynamic linker to load a specified shared library before all others. This allows code injection into any program. VoidLink uses this technique for persistence on older kernels (< 4.0) or when kernel-level rootkits are disabled.

**Legitimate uses:** Debugging tools, performance profilers, and some security software use `LD_PRELOAD`. Investigate any findings in context.

---

### Check 3: eBPF Programs

**What it does:** 
1. Reports your kernel version and which rootkit technique VoidLink would use
2. Lists all loaded eBPF programs (requires `bpftool` and root)

**Why it matters:** eBPF (extended Berkeley Packet Filter) allows running sandboxed programs inside the Linux kernel. While incredibly useful for networking and observability, malicious eBPF programs can hook syscalls, hide processes and files, and intercept network traffic—all without loading a traditional kernel module. VoidLink uses eBPF rootkits on kernels ≥ 5.5.

**What's normal:** Docker, Cilium, Falco, Datadog, systemd, and many observability tools use eBPF legitimately.

---

### Check 4: Kernel Modules

**What it does:**
1. Reports total loaded kernel modules
2. Shows recent module-related kernel messages from `dmesg`
3. Checks if the kernel is "tainted" (which can indicate unsigned or out-of-tree modules)

**Why it matters:** VoidLink deploys loadable kernel modules (LKM) for rootkit functionality on kernels ≥ 4.0 when eBPF isn't available. Malicious kernel modules can hide processes, files, network connections, and even themselves.

**What to look for:** Unexpected modules, recently loaded modules you don't recognize, or a tainted kernel flag.

---

### Check 5: Systemd Persistence

**What it does:**
1. Lists systemd service files modified in the last 7 days
2. Checks for services that execute binaries from suspicious paths (`/tmp`, `/dev/shm`, `/var/tmp`)

**Why it matters:** VoidLink's `systemd_persist` plugin creates or modifies systemd service files so the malware starts automatically on boot. Legitimate software rarely runs from `/tmp` or similar locations.

---

### Check 6: Cron Persistence

**What it does:**
1. Shows the current user's crontab
2. Displays system crontab entries
3. Checks `/etc/cron.d/` for entries running programs from suspicious paths
4. Lists cron files modified in the last 7 days

**Why it matters:** VoidLink's `cron_persist` plugin uses cron jobs for persistence. Like systemd, cron entries that execute from `/tmp` or `/dev/shm` are red flags.

---

### Check 7: Network Connections

**What it does:**
1. Lists established network connections
2. Checks for connections to cloud metadata endpoints (169.254.169.254)
3. Counts DNS connections (excessive counts may indicate DNS tunneling)
4. Checks for unusual raw sockets (potential ICMP tunneling)

**Why it matters:** VoidLink supports multiple command-and-control channels:
- HTTP/HTTPS (with traffic camouflage)
- DNS tunneling
- ICMP tunneling
- WebSocket
- Peer-to-peer mesh networking

It also queries cloud metadata APIs to identify the environment, which generates connections to `169.254.169.254` or similar provider-specific endpoints.

---

### Check 8: Credential Store Access

**What it does:**
1. Lists SSH directory contents and file access times
2. Checks for SSH authorized_keys entries
3. Notes browser credential store locations and their access times
4. Checks for git credential helpers and plaintext credential files

**Why it matters:** VoidLink includes multiple credential harvesting plugins:
- `ssh_harvester` — Collects SSH keys and configs
- `browser_stealer` — Extracts Chrome/Firefox passwords and cookies
- `keyring_dump` — Pulls secrets from the system keyring
- `passwd_dump` — Reads local password databases

Unusual access patterns to these files may indicate harvesting activity.

---

### Check 9: Container Environment

**What it does:**
1. Detects if the script is running inside a container
2. Checks if the Docker socket (`/var/run/docker.sock`) is accessible
3. Looks for Kubernetes service account tokens
4. Lists running containers on the host

**Why it matters:** VoidLink is explicitly designed for cloud and container environments. It includes:
- `docker_escape` — Attempts known container breakout techniques
- `k8s_privesc` — Kubernetes privilege escalation
- `k8s_exec` — Kubernetes resource enumeration

A readable Docker socket from within a container is a significant escape vector.

---

### Check 10: Anti-Forensics Indicators

**What it does:**
1. Checks shell history file size (suspiciously small may indicate wiping)
2. Checks if history logging is disabled
3. Checks auth log size for anomalies
4. Looks for files with timestamps in the future (possible timestomping)

**Why it matters:** VoidLink includes anti-forensics capabilities:
- `log_wiper` — Removes log entries matching specific patterns
- `history_wipe` — Clears shell history
- `timestomp` — Alters file timestamps to disrupt forensic timelines

These techniques help attackers cover their tracks.

---

## Interpreting Results

The script uses color-coded output:
- 🟢 **[OK]** — Check passed, no issues found
- 🔵 **[INFO]** — Informational, review in context
- 🟡 **[CHECK]** — Currently running this check
- 🔴 **[WARNING]** — Potential indicator found, investigate further

**Important:** Not all warnings indicate compromise. Many findings have legitimate explanations:
- Docker/Kubernetes networking modules are normal on container hosts
- Security and observability tools use eBPF legitimately
- Recently modified service files may be from normal updates

Always investigate warnings in the context of your specific environment.

---

## Limitations

This script checks for **known indicators** but cannot guarantee detection of VoidLink or similar threats because:

1. **Hash-based detection** fails if malware is recompiled
2. **Rootkits can hide themselves** from userspace tools
3. **New variants** may use different techniques
4. **Fileless malware** may leave minimal traces

Consider this script one layer in a defense-in-depth strategy, not a complete security solution.

---

## Recommended Security Practices

- Run this script periodically, not just once
- Implement proper logging and ship logs off-system
- Use a host-based intrusion detection system (HIDS)
- Keep systems patched and updated
- Restrict Docker socket access where possible
- Use read-only containers and minimal base images
- Implement network segmentation for sensitive workloads

---

## License

MIT — Use freely, modify as needed, no warranty.

## Credits

- Detection logic based on [Check Point Research's VoidLink analysis](https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/)
- Script and documentation developed in collaboration with [Claude](https://claude.ai) (Opus 4.5) by Anthropic
- Script maintained at [RoninATX/Bootstraps](https://github.com/RoninATX/Bootstraps)
