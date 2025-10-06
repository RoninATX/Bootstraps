#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# bootstrap-secure=pi.sh — Ubuntu minimal bootstrap + fail2ban + unattended-upgrades
# - SSH hardening (keys only, custom port, no root)
# - UFW basic firewall
# - apt update/upgrade
# - Install Docker + Portainer CE
# - Enable fail2ban (sshd jail) and unattended-upgrades
# - Print a summary and save it to /root/BOOTSTRAP_SUMMARY.txt
# -----------------------------------------------------------------------------

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (e.g., sudo -i; then bash bootstrap-secure-pi.sh)"; exit 1
fi

# ---- Inputs ------------------------------------------------------------------
# Assume the admin user is already created as part of the Pi Manager Config; just capture the username.
NEWUSER="$(whoami)"
echo "Admin username: $NEWUSER"

read -rp "SSH port [22]: " SSHPORT
SSHPORT="${SSHPORT:-22}"
if ! [[ "$SSHPORT" =~ ^[0-9]+$ ]] || (( SSHPORT < 1 || SSHPORT > 65535 )); then
  echo "Invalid port; defaulting to 22"; SSHPORT=22
fi

read -rp "Copy root's authorized_keys to the new user? [y/N]: " COPY_KEYS
COPY_KEYS="${COPY_KEYS:-n}"

# Optional: trusted IP/CIDR to always ignore in fail2ban (e.g., your home WAN IP or LAN)
read -rp "fail2ban ignoreip (space-separated IPs/CIDRs) [leave blank for none]: " F2B_IGNOREIP
F2B_IGNOREIP="${F2B_IGNOREIP:-}"

# ---- System updates ----------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y
apt-get install -y ca-certificates curl gnupg ufw apt-transport-https software-properties-common

# ---- User & sudo -------------------------------------------------------------
if ! id "$NEWUSER" &>/dev/null; then
  useradd --create-home --shell /bin/bash "$NEWUSER"
fi
echo "${NEWUSER}:${P1}" | chpasswd
usermod -aG sudo "$NEWUSER"

# ---- SSH hardening -----------------------------------------------------------
SSHCFG='/etc/ssh/sshd_config'
CLOUDINIT_D='/etc/ssh/sshd_config.d'
CLOUDINIT_DROPIN="${CLOUDINIT_D}/50-cloud-init.conf"

patch_line() {
  local key="$1" val="$2"
  if grep -qiE "^[# ]*${key}[[:space:]]+" "$SSHCFG"; then
    sed -Ei "s|^[# ]*(${key})[[:space:]].*|\1 ${val}|I" "$SSHCFG"
  else
    echo "${key} ${val}" >> "$SSHCFG"
  fi
}

patch_line "Port"                    "$SSHPORT"
patch_line "Protocol"                "2"
patch_line "PubkeyAuthentication"    "yes"
patch_line "PasswordAuthentication"  "no"
patch_line "PermitRootLogin"         "no"
patch_line "ChallengeResponseAuthentication" "no"
patch_line "UsePAM"                  "yes"   # Keep PAM for fail2ban & policy hooks

[[ -f "$CLOUDINIT_DROPIN" ]] && rm -f "$CLOUDINIT_DROPIN"

mkdir -p "/home/${NEWUSER}/.ssh"
chmod 700 "/home/${NEWUSER}/.ssh"
if [[ "$COPY_KEYS" =~ ^[Yy]$ && -f /root/.ssh/authorized_keys ]]; then
  cp /root/.ssh/authorized_keys "/home/${NEWUSER}/.ssh/authorized_keys"
  chmod 600 "/home/${NEWUSER}/.ssh/authorized_keys"
fi
chown -R "${NEWUSER}:${NEWUSER}" "/home/${NEWUSER}/.ssh"

/usr/sbin/sshd -t
systemctl restart ssh

# ---- UFW basic rules ---------------------------------------------------------
ufw --force reset
ufw allow "${SSHPORT}/tcp"
ufw allow 9443/tcp     # Portainer HTTPS UI
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
usermod -aG docker "$NEWUSER"

# ---- Portainer CE ------------------------------------------------------------
docker volume create portainer_data >/dev/null
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
# Ensure periodic runs are enabled
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Keep default 50unattended-upgrades (security updates). You can extend origins later if desired.
# Optional: Disable automatic reboots by default (safer for homelab)
if grep -q '^Unattended-Upgrade::Automatic-Reboot' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null; then
  sed -i 's/^Unattended-Upgrade::Automatic-Reboot.*/Unattended-Upgrade::Automatic-Reboot "false";/' /etc/apt/apt.conf.d/50unattended-upgrades
else
  echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
fi
systemctl enable --now unattended-upgrades

# ---- fail2ban (sshd jail) ----------------------------------------------------
apt-get install -y fail2ban

# Base jail.local tuned for Ubuntu + UFW
cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
# Use UFW for banning so rules are simple to manage
banaction = ufw
backend = systemd
# Optional trusted IP/CIDR(s) that should never be banned:
ignoreip = 127.0.0.1/8 ::1${F2B_IGNOREIP:+ ${F2B_IGNOREIP}}
# Reasonable defaults (tweak in cloud if you like it harsher)
findtime = 10m
bantime  = 1h
maxretry = 5
destemail = root@localhost
sender = fail2ban@$(hostname -f 2>/dev/null || hostname)

[sshd]
enabled = true
port = ${SSHPORT}
logpath = %(sshd_log)s
mode = aggressive
EOF

systemctl enable --now fail2ban
# Give fail2ban a moment to read the jail
sleep 2
F2B_STATUS="$(fail2ban-client status sshd 2>/dev/null || true)"

# ---- Summary -----------------------------------------------------------------
IP4_LOCAL="$(hostname -I 2>/dev/null | awk '{print $1}')"
PUB_IP="$(curl -4 -s https://ifconfig.io || true)"
[[ -z "${PUB_IP}" ]] && PUB_IP="(unavailable)"

SUMMARY="/root/BOOTSTRAP_SUMMARY.txt"
{
  echo "✅ Secure bootstrap complete."
  echo
  echo "New admin user      : ${NEWUSER}"
  echo "SSH port            : ${SSHPORT}"
  echo "Password auth       : disabled"
  echo "Root login          : disabled"
  if [[ -f "/home/${NEWUSER}/.ssh/authorized_keys" ]]; then
    echo "SSH keys            : /home/${NEWUSER}/.ssh/authorized_keys"
  else
    echo "SSH keys            : (none copied; add your public key to /home/${NEWUSER}/.ssh/authorized_keys)"
  fi
  echo "UFW                 : enabled; allowing ${SSHPORT}/tcp and 9443/tcp"
  echo
  echo "Docker              : installed and running"
  echo "Portainer container : up (portainer/portainer-ce:latest)"
  echo "Portainer URL (LAN) : https://${IP4_LOCAL:-<your-ip>}:9443"
  echo "Portainer URL (WAN) : https://${PUB_IP}:9443"
  echo
  echo "Unattended upgrades : enabled (security updates nightly)"
  echo "Auto-reboot         : disabled (edit /etc/apt/apt.conf.d/50unattended-upgrades to change)"
  echo
  echo "fail2ban            : enabled (banaction=ufw, sshd mode=aggressive)"
  echo "ignoreip            : ${F2B_IGNOREIP:-(none)}"
  echo "findtime/bantime    : 10m / 1h ; maxretry=5"
  echo "fail2ban status     :"
  echo "${F2B_STATUS}"
  echo
  echo "Next steps:"
  echo "1) Reconnect SSH as: ssh -p ${SSHPORT} ${NEWUSER}@${IP4_LOCAL:-<server-ip>}"
  echo "2) Open Portainer in your browser (set admin password on first visit)."
  echo "3) (Optional) Tune fail2ban at /etc/fail2ban/jail.local; then 'systemctl restart fail2ban'."
  echo "4) (Optional) Extend unattended-upgrades origins in /etc/apt/apt.conf.d/50unattended-upgrades."
} | tee "$SUMMARY"

echo
echo "Summary saved to: $SUMMARY"
echo "You may need to log out/in for docker group membership to take effect for ${NEWUSER}."
