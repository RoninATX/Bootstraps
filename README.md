# Bootstraps
Bootstrap scripts for my various Orange and Raspberry Pi Configs

🧩 bootstrap-secure.sh

bootstrap-secure.sh is a minimal yet production-hardened Ubuntu bootstrap script designed to bring a fresh cloud or homelab instance up to a secure and functional baseline.
It handles user setup, SSH lockdown, system updates, Docker installation, and deploys Portainer CE for container management.
Additionally, it includes automated security layers such as fail2ban (for brute-force protection) and unattended-upgrades (for nightly security patching).

🚀 Features
Category	Description
System Base	Assumes an Ubuntu host (cloud VPS or Raspberry Pi). Performs apt updates and upgrades automatically.
User Creation	Creates a new non-root administrative user with sudo privileges. Prompts for username and password at runtime.
SSH Hardening	- Disables root login
- Disables password authentication (SSH keys only)
- Supports custom SSH port selection
- Optionally copies root’s authorized keys
- Cleans cloud-init SSH overrides
Firewall (UFW)	Enables UFW by default, allowing only:
• SSH (custom port)
• Portainer HTTPS (9443/tcp)
Docker Engine	Installs the latest stable Docker Engine, CLI, and Compose plugins via the official Docker repo.
Portainer CE	Deploys Portainer CE (portainer/portainer-ce:latest) with persistent data volume and HTTPS access on port 9443.
Security Enhancements	- fail2ban: Actively monitors SSH logins and bans repeated offenders (integrated with UFW).
- unattended-upgrades: Automatically installs security updates nightly (reboots disabled by default).
Summary Output	At completion, prints and saves /root/BOOTSTRAP_SUMMARY.txt detailing:
• User & SSH info
• Docker & Portainer status
• fail2ban configuration
• Unattended upgrade settings

v1.0 — “Secure Minimal Baseline” (October 2025)
- Initial release of bootstrap-secure.sh derived from the full Pi-Ubuntu-Docker bootstrap.
- Focused on universally applicable setup tasks for Ubuntu systems:
- Root privilege check, non-root admin user creation, and SSH hardening.
- Apt updates/upgrades with minimal dependencies.
- Official Docker Engine + Portainer CE installation and auto-start.
- Basic UFW configuration (SSH + Portainer ports only).
- Added security automation layer
