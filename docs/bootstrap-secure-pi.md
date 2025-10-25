# bootstrap-secure-pi.sh

## Quick start
Run the script directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/RoninATX/Bootstraps/main/bootstrap-secure-pi.sh | sudo bash
```

## Overview
The Raspberry Pi platform allows preconfiguring the admin user at burn time in the Pi Imager software. This variant of the bootstrap script skips new user creation and captures the existing `whoami` user instead. It mirrors the security hardening from the main Ubuntu script while adapting defaults for Raspberry Pi environments.

## Usage notes
- The script does not accept positional arguments.
- Run it as `root` or via `sudo`; it automatically targets the first non-root user.
- Optional environment variable: set `INCLUDE_WAN_URL=1` if you want the summary to include the public Portainer URL. If unset or `0`, only the LAN URL is written to `/root/BOOTSTRAP_SUMMARY.txt`.
