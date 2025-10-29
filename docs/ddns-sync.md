# ddns-sync.sh

`ddns-sync.sh` synchronizes Cloudflare A records with the host's current public
IPv4 address. By default the script loads configuration from
`/etc/ddns-sync.conf`, but you can override the location by exporting the
`CONFIG_PATH` environment variable before running the script.

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

## Configuration

Create `/etc/ddns-sync.conf` (or the path you export via `CONFIG_PATH`) as a
bash-compatible file that defines the variables the script expects:

- `CLOUDFLARE_API_TOKEN` **or** (`CLOUDFLARE_API_KEY` and `CLOUDFLARE_EMAIL`) for authentication.
- `TYPE` (optional, defaults to `A`) for the DNS record type.
- `TTL` (optional, defaults to `300`) for the record TTL.
- `DNS_RECORDS` as a bash array of the fully qualified record names you want to manage, e.g.
  ```bash
  DNS_RECORDS=(
    "home.example.com"
    "nas.example.com"
  )
  ```

If you would rather generate the configuration interactively, follow the [bootstrap-ddns-sync.md](bootstrap-ddns-sync.md) guide for the companion `bootstrap-ddns-sync.sh` wizard that prompts for the required values and writes the config file for you.

## Scheduling with cron

To keep your Cloudflare records updated automatically, add `ddns-sync.sh` to
your crontab so it runs hourly in live mode (without `--test`). On Debian or
Ubuntu systems:

1. Run `crontab -e` with the user that should execute the sync (root works if the configuration lives in `/etc`).
2. Add an entry similar to the following, updating the script path if necessary:
   ```cron
   0 * * * * /usr/local/bin/ddns-sync.sh >> /var/log/ddns-sync.log 2>&1
   ```

This schedules the script to run at the top of every hour and captures output in
`/var/log/ddns-sync.log`. Adjust the schedule or log handling to suit your
environment.
