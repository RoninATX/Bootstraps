#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# bootstrap-secure-pi.slim.sh — Raspberry Pi (Ubuntu) minimal bootstrap
# Focused for Pi Imager "OS Customization" images that already:
#   - create the admin user, set hostname
#   - enable SSH and (optionally) enforce public-key-only auth
# This script:
#   - Ensures basic SSH hardening (non-destructive)
#   - Enables UFW and opens SSH + Portainer
#   - apt update/upgrade
#   - Installs Docker + Portainer CE
#   - Enables fail2ban and unattended-upgrades (safe defaults)
#   - Prints a summary to /root/BOOTSTRAP_SUMMARY.txt
# -----------------------------------------------------------------------------
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (e.g., sudo -i; then bash bootstrap-secure-pi.slim.sh)"; exit 1
fi

# ---- Inputs (noninteractive) -------------------------------------------------
NEWUSER="$(whoami)"
echo "Admin username: $NEWUSER"

# ---- System updates ----------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y
apt-get install -y ca-certificates curl gnupg ufw

# Ensure sudo & docker groups later
usermod -aG sudo "$NEWUSER" || true

# ---- SSH hardening (idempotent, minimal) ------------------------------------
SSHCFG='/etc/ssh/sshd_config'
CLOUDINIT_DROPIN='/etc/ssh/sshd_config.d/50-cloud-init.conf'

patch_line() {
  local key="$1" val="$2"
  if grep -qiE "^[# ]*${key}[[:space:]]+" "$SSHCFG"; then
    sed -Ei "s|^[# ]*(${key})[[:space:]].*|\1 ${val}|I" "$SSHCFG"
  else
    echo "${key} ${val}" >> "$SSHCFG"
  fi
}

# If Pi Imager already enforces key-only, these remain no-ops; otherwise they apply.
# Port left at default 22 (Pi Imager or default sshd)
patch_line "PubkeyAuthentication"   "yes"
patch_line "PasswordAuthentication" "no"
patch_line "PermitRootLogin"        "no"
patch_line "UsePAM"                 "yes"

# Avoid cloud-init overrides re-enabling password auth on some images
[[ -f "$CLOUDINIT_DROPIN" ]] && rm -f "$CLOUDINIT_DROPIN"

# Ensure SSH dir for admin user (Pi Imager likely injected keys)
mkdir -p "/home/${NEWUSER}/.ssh"
chmod 700 "/home/${NEWUSER}/.ssh"
chown -R "${NEWUSER}:${NEWUSER}" "/home/${NEWUSER}/.ssh"

# Validate config; reload to avoid dropping session
/usr/sbin/sshd -t
systemctl reload ssh || systemctl restart ssh

# ---- UFW rules (non-destructive) --------------------------------------------
# Do not reset to preserve any pre-seeded rules from Pi Imager; just ensure required ports.
ufw allow 22/tcp || true
ufw allow 9443/tcp || true
ufw --force enable

# ---- Docker (official repo) --------------------------------------------------
install -m 0755 -d /etc/apt/keyrings
if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
fi

. /etc/os-release
CODENAME="${UBUNTU_CODENAME:-$(. /etc/lsb-release 2>/dev/null; echo ${DISTRIB_CODENAME:-})}"
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list

apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
usermod -aG docker "$NEWUSER" || true

# ---- Portainer CE ------------------------------------------------------------
docker volume create portainer_data >/dev/null 2>&1 || true
if docker ps -a --format '{{.Names}}' | grep -q '^portainer$'; then
  docker rm -f portainer >/dev/null 2>&1 || true
fi

docker run -d \
  -p 8000:8000 \
  -p 9443:9443 \
  --name portainer \
  --restart=always \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v portainer_data:/data \
  portainer/portainer-ce:latest

# ---- unattended-upgrades -----------------------------------------------------
apt-get install -y unattended-upgrades
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
# Disable auto-reboots by default (safer for homelab)
if grep -q '^Unattended-Upgrade::Automatic-Reboot' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null; then
  sed -i 's/^Unattended-Upgrade::Automatic-Reboot.*/Unattended-Upgrade::Automatic-Reboot "false";/' /etc/apt/apt.conf.d/50unattended-upgrades
else
  echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
fi
systemctl enable --now unattended-upgrades

# ---- fail2ban (sshd jail) ----------------------------------------------------
apt-get install -y fail2ban

cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
banaction = ufw
backend = systemd
findtime = 10m
bantime  = 1h
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
mode = aggressive
EOF

systemctl enable --now fail2ban
sleep 1
F2B_STATUS="$(fail2ban-client status sshd 2>/dev/null || true)"

# ---- Summary -----------------------------------------------------------------
IP4_LOCAL="$(hostname -I 2>/dev/null | awk '{print $1}')"
INCLUDE_WAN_URL="${INCLUDE_WAN_URL:-0}"

if [[ "${INCLUDE_WAN_URL}" == "1" ]]; then
  PUB_IP="$(curl -4 -s https://ifconfig.io || true)"
  [[ -z "${PUB_IP}" ]] && PUB_IP="(unavailable)"
fi

# Hardware detection for summary
if [[ -r /proc/device-tree/model ]]; then
  HW_MODEL=$(tr -d '\0' </proc/device-tree/model)
else
  HW_MODEL="$(uname -mrs)"
fi

SUMMARY="/root/BOOTSTRAP_SUMMARY.txt"
{
  echo "✅ Secure bootstrap (Pi slim) complete."
  echo
  echo "Admin user          : ${NEWUSER}"
  echo "Hostname            : $(hostname)"
  echo "Hardware model       : ${HW_MODEL}"
    echo "Password auth       : disabled (enforced)"
  echo "Root login          : disabled"
  if [[ -f "/home/${NEWUSER}/.ssh/authorized_keys" ]]; then
    echo "SSH keys            : /home/${NEWUSER}/.ssh/authorized_keys"
  else
    echo "SSH keys            : (none copied; Pi Imager likely injected)"
  fi
  echo "UFW                 : enabled; allowing 22/tcp and 9443/tcp"
  echo
  echo "Docker              : installed and running"
  echo "Portainer container : up (portainer/portainer-ce:latest)"
  echo "Portainer URL (LAN) : https://${IP4_LOCAL:-<your-ip>}:9443"
  if [[ "${INCLUDE_WAN_URL}" == "1" ]]; then
    echo "Portainer URL (WAN) : https://${PUB_IP}:9443"
  fi
  echo
  echo "Unattended upgrades : enabled (security updates nightly)"
  echo "Auto-reboot         : disabled"
  echo
  echo "fail2ban            : enabled (banaction=ufw, sshd mode=aggressive)"
    echo "findtime/bantime    : 10m / 1h ; maxretry=5"
  echo "fail2ban status     :"
  echo "${F2B_STATUS}"
} | tee "$SUMMARY"

echo "Summary saved to: $SUMMARY"
