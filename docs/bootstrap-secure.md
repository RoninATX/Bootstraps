# bootstrap-secure.sh

## Quick start
Run the script directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/RoninATX/Bootstraps/main/bootstrap-secure.sh | sudo bash
```

## Overview
`bootstrap-secure.sh` is a minimal yet production-hardened Ubuntu bootstrap script designed to bring a fresh cloud or homelab instance up to a secure and functional baseline. It handles user setup, SSH lockdown, system updates, Docker installation, and deploys Portainer CE for container management. Additionally, it includes automated security layers such as fail2ban (for brute-force protection) and unattended-upgrades (for nightly security patching).

## Features
- **System base**: Assumes an Ubuntu host (cloud VPS or Raspberry Pi) and performs apt updates and upgrades automatically.
- **User creation**: Creates a new non-root administrative user with sudo privileges and prompts for username and password at runtime.
- **SSH hardening**:
  - Disables root login.
  - Disables password authentication (SSH keys only).
  - Supports custom SSH port selection.
  - Optionally copies root’s authorized keys.
  - Cleans cloud-init SSH overrides.
- **Firewall (UFW)**: Enables UFW by default, allowing only SSH (custom port) and Portainer HTTPS (9443/tcp).
- **Docker Engine**: Installs the latest stable Docker Engine, CLI, and Compose plugins via the official Docker repo.
- **Portainer CE**: Deploys Portainer CE (`portainer/portainer-ce:latest`) with persistent data volume and HTTPS access on port 9443.
- **Security enhancements**:
  - fail2ban actively monitors SSH logins and bans repeated offenders (integrated with UFW).
  - unattended-upgrades automatically installs security updates nightly (reboots disabled by default).
- **Summary output**: At completion, prints and saves `/root/BOOTSTRAP_SUMMARY.txt` detailing user & SSH info, Docker & Portainer status, fail2ban configuration, and unattended upgrade settings.

## Access management
If you lose access after enabling fail2ban, you can unblock known-good clients by running:

```bash
sudo fail2ban-client set sshd unbanip <your-ip>
```

Repeat the command for each workstation or server that should retain SSH access. Replace `<your-ip>` with the actual source address that you want to restore.

After the bootstrap script finishes, the SSH connection process changes slightly. Make sure you are passing in the admin account name as part of the host (set during bootstrap) when connecting:

```bash
ssh someadmin@192.168.x.x
```

Otherwise, a confusing situation may arise where you receive `Connection Refused` errors—particularly when connecting from Windows, where a generic SSH attempt (`ssh 192.168.x.x`) passes your current Windows account name.

## Release history
**v1.0 — “Secure Minimal Baseline” (October 2025)**

- Initial release derived from the full Pi-Ubuntu-Docker bootstrap.
- Focused on universally applicable setup tasks for Ubuntu systems:
  - Root privilege check, non-root admin user creation, and SSH hardening.
  - Apt updates/upgrades with minimal dependencies.
  - Official Docker Engine + Portainer CE installation and auto-start.
  - Basic UFW configuration (SSH + Portainer ports only).
  - Added security automation layer.
