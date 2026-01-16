#!/bin/bash

#===============================================================================
# VoidLink Malware Detection Script
# Based on Check Point Research findings (January 2026)
# https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/
#
# This script checks for indicators of compromise (IOCs) associated with the
# VoidLink Linux malware framework. VoidLink is a sophisticated, cloud-first
# implant that targets Linux systems with modular plugins, rootkit capabilities,
# and adaptive evasion techniques.
#
# Usage: sudo ./voidlink_check.sh
# Note: Some checks require root privileges for full effectiveness
#===============================================================================

set -o pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Track findings
FINDINGS=0

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

print_check() {
    echo -e "${YELLOW}[CHECK]${NC} $1"
}

print_ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${RED}[WARNING]${NC} $1"
    ((FINDINGS++))
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

#===============================================================================
# CHECK 1: Known VoidLink File Hashes
#===============================================================================
# VoidLink samples have known SHA256 hashes. This check scans common directories
# for any files matching these signatures. These are the Stage 0 loader, Stage 1
# loader, and various implant builds identified by Check Point Research.
#===============================================================================

print_header "CHECK 1: Known VoidLink File Hashes (SHA256)"

KNOWN_HASHES=(
    "70aa5b3516d331e9d1876f3b8994fc8c18e2b1b9f15096e6c790de8cdadb3fc9"  # Stage 0
    "13025f83ee515b299632d267f94b37c71115b22447a0425ac7baed4bf60b95cd"  # Stage 1
    "05eac3663d47a29da0d32f67e10d161f831138e10958dcd88b9dc97038948f69"  # Implant
    "15cb93d38b0a4bd931434a501d8308739326ce482da5158eb657b0af0fa7ba49"  # Implant
    "6850788b9c76042e0e29a318f65fceb574083ed3ec39a34bc64a1292f4586b41"  # Implant
    "6dcfe9f66d3aef1efd7007c588a59f69e5cd61b7a8eca1fb89a84b8ccef13a2b"  # Implant
    "28c4a4df27f7ce8ced69476cc7923cf56625928a7b4530bc7b484eec67fe3943"  # Implant
    "e990a39e479e0750d2320735444b6c86cc26822d86a40d37d6e163d0fe058896"  # Implant
    "4c4201cc1278da615bacf48deef461bf26c343f8cbb2d8596788b41829a39f3f"  # Implant
)

print_check "Scanning common directories for known malicious hashes..."
print_info "This may take a moment depending on filesystem size"

# Build grep pattern from known hashes
HASH_PATTERN=$(IFS="|"; echo "${KNOWN_HASHES[*]}")

# Directories to scan (adjust based on your environment)
SCAN_DIRS="/tmp /var/tmp /dev/shm /usr/local/bin /opt"

hash_found=0
for dir in $SCAN_DIRS; do
    if [[ -d "$dir" ]]; then
        while IFS= read -r -d '' file; do
            hash=$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1)
            if echo "$hash" | grep -qE "$HASH_PATTERN"; then
                print_warning "KNOWN VOIDLINK HASH FOUND: $file ($hash)"
                hash_found=1
            fi
        done < <(find "$dir" -type f -executable -print0 2>/dev/null)
    fi
done

if [[ $hash_found -eq 0 ]]; then
    print_ok "No known VoidLink hashes found in scanned directories"
fi

#===============================================================================
# CHECK 2: LD_PRELOAD Hooks
#===============================================================================
# VoidLink uses LD_PRELOAD for persistence on older kernels (<4.0) or when
# kernel-level rootkits are disabled. LD_PRELOAD forces the dynamic linker to
# load a specified shared library before all others, allowing code injection
# into any dynamically-linked program.
#
# Legitimate uses exist (debugging, instrumentation), but unexpected entries
# are suspicious.
#===============================================================================

print_header "CHECK 2: LD_PRELOAD Hooks (Userspace Persistence)"

print_check "Checking /etc/ld.so.preload..."
if [[ -f /etc/ld.so.preload ]]; then
    content=$(cat /etc/ld.so.preload 2>/dev/null)
    if [[ -n "$content" ]]; then
        print_warning "/etc/ld.so.preload contains entries:"
        echo "$content" | while read -r line; do
            echo "         -> $line"
        done
    else
        print_ok "/etc/ld.so.preload exists but is empty"
    fi
else
    print_ok "/etc/ld.so.preload does not exist"
fi

print_check "Checking current shell environment for LD_PRELOAD..."
if [[ -n "$LD_PRELOAD" ]]; then
    print_warning "LD_PRELOAD is set in current environment: $LD_PRELOAD"
else
    print_ok "LD_PRELOAD not set in current environment"
fi

print_check "Scanning running processes for LD_PRELOAD..."
ld_preload_procs=0
for pid_dir in /proc/[0-9]*; do
    pid=$(basename "$pid_dir")
    if [[ -r "$pid_dir/environ" ]]; then
        if grep -qz "LD_PRELOAD" "$pid_dir/environ" 2>/dev/null; then
            cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null)
            preload_val=$(tr '\0' '\n' < "$pid_dir/environ" 2>/dev/null | grep "^LD_PRELOAD=")
            print_warning "PID $pid has LD_PRELOAD set: $cmdline"
            echo "         -> $preload_val"
            ((ld_preload_procs++))
        fi
    fi
done

if [[ $ld_preload_procs -eq 0 ]]; then
    print_ok "No running processes have LD_PRELOAD set"
fi

#===============================================================================
# CHECK 3: eBPF Programs
#===============================================================================
# VoidLink deploys eBPF-based rootkits on kernels >= 5.5 with eBPF support.
# eBPF (extended Berkeley Packet Filter) allows running sandboxed programs in
# the kernel without loading kernel modules. Malicious eBPF can hook syscalls,
# hide processes/files, and intercept network traffic.
#
# Requires bpftool and root privileges for full visibility.
#===============================================================================

print_header "CHECK 3: eBPF Programs (Kernel-Level Hooks)"

print_check "Checking kernel version for eBPF rootkit susceptibility..."
kernel_version=$(uname -r | cut -d'-' -f1)
kernel_major=$(echo "$kernel_version" | cut -d'.' -f1)
kernel_minor=$(echo "$kernel_version" | cut -d'.' -f2)

print_info "Kernel version: $(uname -r)"

if [[ $kernel_major -gt 5 ]] || [[ $kernel_major -eq 5 && $kernel_minor -ge 5 ]]; then
    print_info "Kernel >= 5.5 detected - VoidLink would use eBPF rootkit on this system"
elif [[ $kernel_major -ge 4 ]]; then
    print_info "Kernel >= 4.0 detected - VoidLink would use LKM rootkit on this system"
else
    print_info "Kernel < 4.0 detected - VoidLink would use LD_PRELOAD on this system"
fi

print_check "Enumerating loaded eBPF programs..."
if command -v bpftool &> /dev/null; then
    if [[ $EUID -eq 0 ]]; then
        ebpf_progs=$(bpftool prog list 2>/dev/null)
        if [[ -n "$ebpf_progs" ]]; then
            print_info "Loaded eBPF programs (review for anything unexpected):"
            echo "$ebpf_progs" | while read -r line; do
                echo "         $line"
            done
            print_info "Common legitimate eBPF: systemd, docker, cilium, falco, datadog"
        else
            print_ok "No eBPF programs currently loaded"
        fi
    else
        print_info "Run as root for full eBPF visibility (bpftool requires CAP_SYS_ADMIN)"
    fi
else
    print_info "bpftool not installed - install with: apt install linux-tools-common"
fi

#===============================================================================
# CHECK 4: Kernel Modules (LKM Rootkit)
#===============================================================================
# VoidLink uses loadable kernel modules (LKM) for rootkit functionality on
# kernels >= 4.0 when eBPF isn't available. Malicious LKMs can hide processes,
# files, network connections, and even themselves from detection.
#
# Look for: unsigned modules, recently loaded modules, modules with suspicious
# names, or modules not matching your known configuration.
#===============================================================================

print_header "CHECK 4: Kernel Modules (LKM Rootkit Detection)"

print_check "Listing currently loaded kernel modules..."
module_count=$(lsmod | wc -l)
print_info "Total modules loaded: $((module_count - 1))"

print_check "Checking for recently loaded modules (last 24 hours)..."
# Note: Module load times aren't directly tracked, but we can check dmesg
if [[ $EUID -eq 0 ]]; then
    recent_modules=$(dmesg --time-format=iso 2>/dev/null | grep -i "module" | tail -20)
    if [[ -n "$recent_modules" ]]; then
        print_info "Recent module-related kernel messages:"
        echo "$recent_modules" | while read -r line; do
            echo "         $line"
        done
    fi
fi

print_check "Checking for modules not in standard kernel module path..."
kernel_mod_dir="/lib/modules/$(uname -r)"
while read -r mod_name _; do
    # Check if module exists in standard locations
    if ! find "$kernel_mod_dir" -name "${mod_name}.ko*" 2>/dev/null | grep -q .; then
        print_info "Module '$mod_name' not found in $kernel_mod_dir (may be built-in or third-party)"
    fi
done < /proc/modules

print_check "Checking for unsigned/tainted kernel..."
if [[ -r /proc/sys/kernel/tainted ]]; then
    taint=$(cat /proc/sys/kernel/tainted)
    if [[ "$taint" -ne 0 ]]; then
        print_warning "Kernel is tainted (value: $taint) - may indicate unsigned modules"
        print_info "Taint flags: https://docs.kernel.org/admin-guide/tainted-kernels.html"
    else
        print_ok "Kernel is not tainted"
    fi
fi

#===============================================================================
# CHECK 5: Systemd Persistence
#===============================================================================
# VoidLink's systemd_persist plugin creates or modifies systemd service files
# to ensure the implant starts automatically on boot. Check for:
# - Recently modified service files
# - Services with suspicious ExecStart paths
# - Services running from /tmp, /dev/shm, or user directories
#===============================================================================

print_header "CHECK 5: Systemd Service Persistence"

print_check "Looking for recently modified systemd service files..."
SYSTEMD_PATHS="/etc/systemd/system /usr/lib/systemd/system /lib/systemd/system ~/.config/systemd/user"

for spath in $SYSTEMD_PATHS; do
    if [[ -d "$spath" ]]; then
        recent=$(find "$spath" -name "*.service" -mtime -7 2>/dev/null)
        if [[ -n "$recent" ]]; then
            print_info "Services modified in last 7 days in $spath:"
            echo "$recent" | while read -r svc; do
                mod_time=$(stat -c '%y' "$svc" 2>/dev/null | cut -d'.' -f1)
                echo "         $svc (modified: $mod_time)"
            done
        fi
    fi
done

print_check "Checking for services with suspicious ExecStart paths..."
service_files=$(find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system -maxdepth 1 -name "*.service" 2>/dev/null)
while IFS= read -r spath; do
    if [[ -f "$spath" ]]; then
        exec_start=$(grep -E "^ExecStart=" "$spath" 2>/dev/null | head -1)
        # Use word boundaries or path patterns to avoid false matches
        # e.g., /tmp/ or /tmp$ but not /tmpfiles
        if echo "$exec_start" | grep -qE "(^|[= ])/tmp(/|$| )|/dev/shm(/|$| )|/var/tmp(/|$| )"; then
            print_warning "Suspicious ExecStart in $(basename "$spath"): $exec_start"
        fi
    fi
done <<< "$service_files"

print_ok "Systemd service scan complete"

#===============================================================================
# CHECK 6: Cron Persistence
#===============================================================================
# VoidLink's cron_persist plugin installs or modifies cron jobs for persistence.
# Cron entries can be hidden in various locations:
# - User crontabs (/var/spool/cron/crontabs/)
# - System crontab (/etc/crontab)
# - Cron directories (/etc/cron.d/, /etc/cron.daily/, etc.)
#===============================================================================

print_header "CHECK 6: Cron Job Persistence"

print_check "Checking user crontab..."
user_cron=$(crontab -l 2>/dev/null)
if [[ -n "$user_cron" ]]; then
    print_info "Current user's crontab entries:"
    echo "$user_cron" | while read -r line; do
        echo "         $line"
    done
else
    print_ok "No crontab for current user"
fi

print_check "Checking system crontab (/etc/crontab)..."
if [[ -r /etc/crontab ]]; then
    # Filter out comments and empty lines for review
    entries=$(grep -v "^#" /etc/crontab | grep -v "^$" | grep -v "^PATH" | grep -v "^SHELL")
    if [[ -n "$entries" ]]; then
        print_info "System crontab entries:"
        echo "$entries" | while read -r line; do
            echo "         $line"
        done
    fi
fi

print_check "Checking /etc/cron.d/ for unexpected entries..."
if [[ -d /etc/cron.d ]]; then
    for cronfile in /etc/cron.d/*; do
        if [[ -f "$cronfile" ]]; then
            # Check for execution from suspicious paths
            if grep -qE "/tmp/|/dev/shm|/var/tmp" "$cronfile" 2>/dev/null; then
                print_warning "Suspicious path in cron file: $cronfile"
                grep -E "/tmp/|/dev/shm|/var/tmp" "$cronfile" | while read -r line; do
                    echo "         -> $line"
                done
            fi
        fi
    done
fi

print_check "Looking for recently modified cron files..."
recent_cron=$(find /etc/cron* /var/spool/cron -type f -mtime -7 2>/dev/null)
if [[ -n "$recent_cron" ]]; then
    print_info "Cron files modified in last 7 days:"
    echo "$recent_cron" | while read -r cf; do
        echo "         $cf"
    done
fi

print_ok "Cron persistence scan complete"

#===============================================================================
# CHECK 7: Network Connections
#===============================================================================
# VoidLink supports multiple C2 channels: HTTP/HTTPS, DNS tunneling, ICMP
# tunneling, and WebSocket. It also implements mesh/P2P networking between
# infected hosts. Look for:
# - Unexpected outbound connections
# - Unusual DNS query patterns
# - ICMP traffic (potential tunneling)
# - Connections to cloud metadata endpoints (169.254.169.254)
#===============================================================================

print_header "CHECK 7: Network Connections & C2 Indicators"

print_check "Listing established outbound connections..."
if command -v ss &> /dev/null; then
    established=$(ss -tupan 2>/dev/null | grep ESTAB)
    if [[ -n "$established" ]]; then
        print_info "Established connections (review for unexpected destinations):"
        echo "$established" | head -20 | while read -r line; do
            echo "         $line"
        done
        conn_count=$(echo "$established" | wc -l)
        if [[ $conn_count -gt 20 ]]; then
            print_info "... and $((conn_count - 20)) more connections"
        fi
    fi
else
    print_info "ss not available, using netstat..."
    netstat -tupan 2>/dev/null | grep ESTABLISHED | head -20
fi

print_check "Checking for connections to cloud metadata endpoints..."
# VoidLink queries cloud metadata to identify the environment
metadata_conns=$(ss -tupan 2>/dev/null | grep -E "169\.254\.169\.254|metadata\.google|metadata\.azure")
if [[ -n "$metadata_conns" ]]; then
    print_warning "Connections to cloud metadata endpoints detected:"
    echo "$metadata_conns" | while read -r line; do
        echo "         $line"
    done
else
    print_ok "No suspicious metadata endpoint connections"
fi

print_check "Checking for potential DNS tunneling (high DNS traffic)..."
# Count unique DNS connections - excessive counts may indicate tunneling
if [[ $EUID -eq 0 ]]; then
    dns_conns=$(ss -tupan 2>/dev/null | grep ":53 " | wc -l)
    print_info "Current DNS connections: $dns_conns"
    if [[ $dns_conns -gt 50 ]]; then
        print_warning "High number of DNS connections - possible DNS tunneling"
    fi
fi

print_check "Checking for raw socket usage (ICMP tunneling indicator)..."
if [[ $EUID -eq 0 ]]; then
    # Filter out standard kernel ipv6-icmp socket which is always present
    raw_sockets=$(ss -w 2>/dev/null | grep -v "^Netid" | grep -v "ipv6-icmp.*\*:\*")
    if [[ -n "$raw_sockets" ]]; then
        print_warning "Raw sockets detected (could indicate ICMP tunneling):"
        echo "$raw_sockets" | while read -r line; do
            echo "         $line"
        done
    else
        print_ok "No suspicious raw sockets detected"
    fi
fi

#===============================================================================
# CHECK 8: SSH Key and Credential Harvesting Indicators
#===============================================================================
# VoidLink includes multiple credential harvesting plugins:
# - ssh_harvester: Collects SSH keys and configs
# - browser_stealer: Targets Chrome/Firefox credentials and cookies
# - keyring_dump: Extracts secrets from system keyring
# - passwd_dump: Reads local password databases
#
# Check for unusual access to credential stores.
#===============================================================================

print_header "CHECK 8: Credential Store Access Indicators"

print_check "Checking SSH key file access times..."
if [[ -d ~/.ssh ]]; then
    print_info "SSH directory contents and access times:"
    ls -la ~/.ssh 2>/dev/null | while read -r line; do
        echo "         $line"
    done
    
    # Check for unauthorized keys
    if [[ -f ~/.ssh/authorized_keys ]]; then
        key_count=$(wc -l < ~/.ssh/authorized_keys)
        print_info "authorized_keys contains $key_count key(s) - verify these are expected"
    fi
else
    print_ok "No .ssh directory found for current user"
fi

print_check "Checking for recent access to browser credential stores..."
browser_paths=(
    "$HOME/.config/google-chrome/Default/Login Data"
    "$HOME/.config/chromium/Default/Login Data"
    "$HOME/.mozilla/firefox/*.default*/logins.json"
    "$HOME/snap/firefox/common/.mozilla/firefox/*.default*/logins.json"
)

for bpath in "${browser_paths[@]}"; do
    for file in $bpath; do
        if [[ -f "$file" ]]; then
            access_time=$(stat -c '%x' "$file" 2>/dev/null | cut -d'.' -f1)
            print_info "Browser credential store: $file (accessed: $access_time)"
        fi
    done 2>/dev/null
done

print_check "Checking for git credential helpers that might be targeted..."
git_creds=$(git config --global credential.helper 2>/dev/null)
if [[ -n "$git_creds" ]]; then
    print_info "Git credential helper configured: $git_creds"
fi
if [[ -f ~/.git-credentials ]]; then
    print_warning "Plaintext git credentials file exists: ~/.git-credentials"
fi

#===============================================================================
# CHECK 9: Container and Kubernetes Environment
#===============================================================================
# VoidLink is cloud-first and includes specific modules for container
# environments:
# - docker_escape: Container breakout attempts
# - k8s_privesc: Kubernetes privilege escalation
# - k8s_exec: Kubernetes resource enumeration
#
# If you're running containers, additional scrutiny is warranted.
#===============================================================================

print_header "CHECK 9: Container/Kubernetes Environment"

print_check "Detecting if running inside a container..."
in_container=0

if [[ -f /.dockerenv ]]; then
    print_info "Running inside Docker container (/.dockerenv exists)"
    in_container=1
fi

if grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
    print_info "Container cgroup detected"
    in_container=1
fi

if [[ -f /run/secrets/kubernetes.io ]]; then
    print_info "Kubernetes service account detected"
    in_container=1
fi

if [[ $in_container -eq 0 ]]; then
    print_ok "Not running inside a container"
fi

print_check "Checking for Docker socket access (container escape vector)..."
if [[ -S /var/run/docker.sock ]]; then
    if [[ -r /var/run/docker.sock ]]; then
        print_warning "Docker socket is readable - potential container escape vector"
    else
        print_ok "Docker socket exists but is not readable by current user"
    fi
fi

print_check "Checking for Kubernetes service account tokens..."
k8s_token="/var/run/secrets/kubernetes.io/serviceaccount/token"
if [[ -f "$k8s_token" ]]; then
    print_warning "Kubernetes service account token accessible: $k8s_token"
    print_info "VoidLink's k8s_privesc plugin targets these tokens"
fi

print_check "Checking for running containers on this host..."
if command -v docker &> /dev/null; then
    container_count=$(docker ps -q 2>/dev/null | wc -l)
    if [[ $container_count -gt 0 ]]; then
        print_info "Running containers: $container_count"
        docker ps --format "table {{.ID}}\t{{.Image}}\t{{.Status}}" 2>/dev/null | head -10
    fi
fi

#===============================================================================
# CHECK 10: Anti-Forensics Indicators
#===============================================================================
# VoidLink includes anti-forensics capabilities:
# - log_wiper: Removes matching log entries
# - history_wipe: Clears shell history
# - timestomp: Alters file timestamps
#
# Look for signs that logs or history have been tampered with.
#===============================================================================

print_header "CHECK 10: Anti-Forensics Indicators"

print_check "Checking shell history status..."
hist_file="${HISTFILE:-$HOME/.bash_history}"
if [[ -f "$hist_file" ]]; then
    hist_size=$(wc -l < "$hist_file" 2>/dev/null)
    print_info "Shell history file: $hist_file ($hist_size lines)"
    
    # Check if history is suspiciously small or truncated
    if [[ $hist_size -lt 10 ]]; then
        print_warning "Shell history is suspiciously small - may have been wiped"
    fi
else
    print_warning "Shell history file not found - may have been deleted"
fi

print_check "Checking if HISTFILE is disabled..."
# Note: Environment checks are unreliable when running via sudo
# Focus on whether history is actually being written
if [[ -f "$hist_file" && $(stat -c '%s' "$hist_file" 2>/dev/null) -gt 0 ]]; then
    print_ok "History file exists and has content"
elif [[ "$HISTSIZE" == "0" ]] || [[ "$HISTFILESIZE" == "0" ]]; then
    print_warning "History logging appears to be disabled (HISTSIZE or HISTFILESIZE is 0)"
fi

print_check "Checking auth logs for gaps or anomalies..."
auth_log="/var/log/auth.log"
if [[ ! -f "$auth_log" ]]; then
    auth_log="/var/log/secure"  # RHEL/CentOS
fi

if [[ -r "$auth_log" ]]; then
    log_size=$(stat -c '%s' "$auth_log" 2>/dev/null)
    print_info "Auth log size: $log_size bytes"
    if [[ $log_size -lt 1000 ]]; then
        print_warning "Auth log is suspiciously small - may have been tampered with"
    fi
else
    if [[ $EUID -eq 0 ]]; then
        print_warning "Cannot read auth log"
    else
        print_info "Run as root to check auth logs"
    fi
fi

print_check "Looking for files with suspicious timestamps..."
# Files with timestamps far in the future or past may have been timestomped
future_files=$(find /tmp /var/tmp /dev/shm -type f -newermt "$(date -d '+1 day' '+%Y-%m-%d')" 2>/dev/null | head -5)
if [[ -n "$future_files" ]]; then
    print_warning "Files with future timestamps found (possible timestomping):"
    echo "$future_files" | while read -r f; do
        echo "         $f"
    done
fi

#===============================================================================
# SUMMARY
#===============================================================================

print_header "SCAN COMPLETE - SUMMARY"

echo ""
if [[ $FINDINGS -gt 0 ]]; then
    echo -e "${RED}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}  WARNINGS FOUND: $FINDINGS potential indicators detected${NC}"
    echo -e "${RED}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Review the warnings above carefully. Not all findings indicate"
    echo "compromise - some may be legitimate. Investigate each warning"
    echo "in context of your environment."
    echo ""
    echo "For confirmed infections, consider:"
    echo "  1. Isolating the affected system from the network"
    echo "  2. Capturing forensic images before remediation"
    echo "  3. Checking other systems that may have been accessed from this host"
    echo "  4. Rotating all credentials that may have been exposed"
else
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  NO WARNINGS - No obvious VoidLink indicators detected${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "This scan checks for known indicators but cannot guarantee the"
    echo "absence of compromise. VoidLink is designed for stealth and may"
    echo "evade detection. Consider:"
    echo "  - Running this scan periodically"
    echo "  - Implementing proper monitoring and logging"
    echo "  - Keeping systems patched and updated"
fi

echo ""
echo "Reference: Check Point Research - VoidLink Analysis"
echo "https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/"
echo ""
