# ddns-sync.sh

`ddns-sync.sh` synchronizes Cloudflare A records with the host's current public
IPv4 address. Configuration is read from `/etc/ddns-sync.conf` (overridable via
`CONFIG_PATH`) and must define your Cloudflare credentials along with the list
of DNS records to manage.

## Usage

```bash
ddns-sync.sh [options]
```

**Options**

| Flag | Description |
| ---- | ----------- |
| `-t`, `--test` | Dry run. Report the updates that would be performed without modifying Cloudflare. |
| `-h`, `--help` | Show inline usage information. |

When run without `--test`, the script fetches the current public IPv4 address,
compares it to each configured record, and updates records that are out of
sync. Test mode follows the same discovery process but only reports the actions
it would take.
