# Bootstraps

A growing collection of quality-of-life scripts to bootstrap fresh servers, introduce new services, and automate day-to-day homelab and security tasks. 

Each script focuses on opinionated defaults that make it easy to get started quickly while keeping security and maintainability in mind.

## Documentation
- [bootstrap-secure.sh](docs/bootstrap-secure.md)
- [bootstrap-secure-pi.sh](docs/bootstrap-secure-pi.md)
- [ddns-sync.sh](docs/ddns-sync.md)
- [bootstrap-ddns-sync.sh](docs/bootstrap-ddns-sync.md)
- [voidlink-check.sh](docs/voidlink-check.md)

## herdr coordinator skills
- [herdr/](herdr/README.md) — a portable, project-agnostic template for running a multi-pane [herdr](https://github.com/) workspace with one **Coordinator** session brokering several **child app** sessions over a disciplined message protocol. Drop-in Claude Code skills (coordinator + child sides) with all app-specific bits left as `{placeholder}`s to fill in.
