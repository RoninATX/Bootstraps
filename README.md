# Bootstraps
Bootstrap scripts for my various Orange and Raspberry Pi Configs.

🧩 bootstrap-secure-pi.sh
Run command: `curl -fsSL https://raw.githubusercontent.com/RoninATX/Bootstraps/main/bootstrap-secure-pi.sh | sudo bash`
* Raspberry Pi allows you to preconfigure things like the admin user at burn time in the Pi Manager software, so this pi version skips the new user creation and simply captures the whoami user.
* The script does not accept positional arguments. It must be run as root (or via `sudo`) and will automatically target the first non-root user.
* Optional environment variable: set `INCLUDE_WAN_URL=1` if you want the summary to include the public Portainer URL. If unset or `0`, only the LAN URL is written to `/root/BOOTSTRAP_SUMMARY.txt`.
  

🧩 bootstrap-secure.sh
Run command: `curl -fsSL https://raw.githubusercontent.com/RoninATX/Bootstraps/main/bootstrap-secure.sh | sudo bash`

bootstrap-secure.sh is a minimal yet production-hardened Ubuntu bootstrap script designed to bring a fresh cloud or homelab instance up to a secure and functional baseline.
It handles user setup, SSH lockdown, system updates, Docker installation, and deploys Portainer CE for container management.
Additionally, it includes automated security layers such as fail2ban (for brute-force protection) and unattended-upgrades (for nightly security patching).

# Whitelisting SSH Sources
If you lose access after enabling fail2ban, you can unblock known-good clients by running:

```bash
sudo fail2ban-client set sshd unbanip <your-ip>
```

Repeat the command for each workstation or server that should retain SSH access. Replace `<your-ip>` with the actual source address that you want to restore.

# Connecting after the script SSH lockdown
After the bootstrap script finishes, the connection process changes slightly. Make sure you are passing in the admin account name as part of the host (you set in the Pi Manager) when SSHing in:
  `ssh someadmin@192.168.x.x`
Otherwise, a confusing situation may arise where you're getting outright `Connection Eefused` errors, particularly when connecting via Windows machines where a generic SSH attempt `ssh 192.168.x.x`  passes your current Windows account name in.

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
