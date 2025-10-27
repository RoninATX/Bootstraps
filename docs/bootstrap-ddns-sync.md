# bootstrap-ddns-sync.sh

Installer for the Cloudflare dynamic DNS sync helper. The script downloads the
`ddns-sync.sh` worker, then optionally walks you through configuring Cloudflare
credentials and the list of DNS records to manage.

## Quick start

Create a folder, download the bootstrapper, and run it:

```bash
mkdir -p ddns
cd ddns
curl -fsSL https://raw.githubusercontent.com/RoninATX/Bootstraps/main/bootstrap-ddns-sync.sh -o bootstrap-ddns-sync.sh
chmod +x bootstrap-ddns-sync.sh
sudo ./bootstrap-ddns-sync.sh
```

The script must be run as root (or via `sudo`). It will:

1. download `ddns-sync.sh` into `/usr/local/bin/ddns-sync.sh`,
2. offer to help you create `/etc/ddns-sync.conf`, and
3. print the cron line needed to keep the records updated.

## Environment variables

Several environment variables let you change defaults without editing the
script:

| Variable       | Default value                                      | Description |
| -------------- | -------------------------------------------------- | ----------- |
| `RAW_BASE_URL` | `https://raw.githubusercontent.com/RoninATX/Bootstraps/main` | Base URL for downloading `ddns-sync.sh`. Set `RAW_BASE_URL="file://$(pwd)"` when testing locally. |
| `INSTALL_PATH` | `/usr/local/bin/ddns-sync.sh`                      | Where to install the worker script. |
| `CONFIG_PATH`  | `/etc/ddns-sync.conf`                              | Where to write the configuration file. |

All of the download and configuration steps respect these overrides.

## Interactive configuration wizard

When the configuration file does not exist, the script asks whether you want
help creating it. Answer `Y` (or press Enter) to launch the wizard.

The wizard guides you through:

1. Choosing between a Cloudflare API token or a global API key.
2. Collecting the token/key (and email if using a global key).
3. Selecting the DNS record type (default `A`).
4. Setting the TTL (default `300`, use `1` for "auto").
5. Entering one DNS record per prompt. Press Enter on a blank line to finish.

The answers are written into `$CONFIG_PATH` with permissions `600`.

If you decline the wizard, a commented template configuration is created
instead.

## After installation

Review the generated files, update the configuration if needed, and add a cron
entry similar to:

```
*/5 * * * * /usr/local/bin/ddns-sync.sh >> /var/log/ddns-sync.log 2>&1
```

The bootstrap script prints these next steps at the end of the run for quick
reference.

