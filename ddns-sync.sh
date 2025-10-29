#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# ddns-sync.sh — Cloudflare dynamic DNS synchronizer
# -----------------------------------------------------------------------------
# Reads configuration from /etc/ddns-sync.conf (or CONFIG_PATH) which must define
# the following variables:
#   CLOUDFLARE_EMAIL      - Required when using a global API key.
#   CLOUDFLARE_API_KEY    - Global API key or API token. When using an API token,
#                           CLOUDFLARE_EMAIL may be omitted.
#   CLOUDFLARE_API_TOKEN  - Optional alternative variable for API tokens. Takes
#                           precedence over CLOUDFLARE_API_KEY when set.
#   TYPE                  - DNS record type to manage (default: A).
#   TTL                   - TTL to apply to managed records (default: 300).
#   DNS_RECORDS           - Bash array of fully-qualified DNS record names.
#
# The script fetches the current public IPv4 address, compares it with the
# Cloudflare DNS records listed in DNS_RECORDS, and updates any records whose
# content differs from the detected IP address. Pass -t/--test to perform a dry
# run that reports what would change without updating Cloudflare.
# -----------------------------------------------------------------------------

set -euo pipefail

CONFIG_PATH="${CONFIG_PATH:-/etc/ddns-sync.conf}"
API_BASE="https://api.cloudflare.com/client/v4"
CURL_COMMON_OPTS=(-fsS --retry 3 --retry-delay 2 --retry-connrefused --max-time 15)

SCRIPT_NAME=$(basename "$0")
TEST_MODE=false

errexit() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $*" >&2
  exit 1
}

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $*"
}

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [-t|--test]

Synchronize Cloudflare DNS A records with the host's current public IPv4
address.

  -t, --test    Perform a dry run and report which records would be updated.
  -h, --help    Show this help message and exit.
EOF
}

require_command() {
  local cmd
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      errexit "Required command '$cmd' not found in PATH"
    fi
  done
}

while (($#)); do
  case "$1" in
    -t|--test)
      TEST_MODE=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      usage >&2
      errexit "Unknown option: $1"
      ;;
    *)
      usage >&2
      errexit "Unexpected argument: $1"
      ;;
  esac
  shift
done

if (($#)); then
  usage >&2
  errexit "Unexpected argument: $1"
fi

require_command curl jq

if [[ ! -f "$CONFIG_PATH" ]]; then
  errexit "Configuration file not found: $CONFIG_PATH"
fi

# shellcheck disable=SC1090
source "$CONFIG_PATH"

TYPE="${TYPE:-A}"
TTL="${TTL:-300}"

AUTH_HEADERS=()
if [[ -n ${CLOUDFLARE_API_TOKEN:-} ]]; then
  AUTH_HEADERS=("-H" "Authorization: Bearer $CLOUDFLARE_API_TOKEN")
elif [[ -n ${CLOUDFLARE_API_KEY:-} && -n ${CLOUDFLARE_EMAIL:-} ]]; then
  AUTH_HEADERS=("-H" "X-Auth-Email: $CLOUDFLARE_EMAIL" "-H" "X-Auth-Key: $CLOUDFLARE_API_KEY")
elif [[ -n ${CLOUDFLARE_API_KEY:-} ]]; then
  log "CLOUDFLARE_EMAIL not set; treating CLOUDFLARE_API_KEY as an API token"
  AUTH_HEADERS=("-H" "Authorization: Bearer $CLOUDFLARE_API_KEY")
else
  errexit "Cloudflare credentials not configured. Set CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_KEY and CLOUDFLARE_EMAIL."
fi

declare -a MANAGED_RECORDS=()
DNS_RECORDS_DECLARATION=""

if DNS_RECORDS_DECLARATION=$(declare -p DNS_RECORDS 2>/dev/null); then
  if [[ $DNS_RECORDS_DECLARATION == declare\ -a* ]]; then
    MANAGED_RECORDS=("${DNS_RECORDS[@]}")
  elif [[ -n ${DNS_RECORDS:-} ]]; then
    # Allow whitespace-delimited records when the configuration file exports a string.
    read -r -a MANAGED_RECORDS <<<"${DNS_RECORDS}"
  fi
elif [[ -n ${DNS_RECORDS:-} ]]; then
  read -r -a MANAGED_RECORDS <<<"${DNS_RECORDS}"
fi

if ((${#MANAGED_RECORDS[@]} == 0)); then
  log "DNS_RECORDS is empty; nothing to update"
  exit 0
fi

trim_ip() {
  local ip="$1"
  ip="${ip%%$'\r'}"
  ip="${ip%%$'\n'}"
  echo "$ip"
}

get_public_ip() {
  local service ip
  local services=(
    "https://ipv4.icanhazip.com"
    "https://api.ipify.org"
    "https://checkip.amazonaws.com"
  )
  for service in "${services[@]}"; do
    if ip=$(curl "${CURL_COMMON_OPTS[@]}" "$service" 2>/dev/null); then
      ip=$(trim_ip "$ip")
      if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "$ip"
        return 0
      fi
    fi
  done
  return 1
}

PUBLIC_IP=$(get_public_ip) || errexit "Unable to determine public IPv4 address"
log "Detected public IPv4 address: $PUBLIC_IP"

declare -A ZONE_ID_CACHE=()

cloudflare_get() {
  local endpoint="$1"
  shift
  curl "${CURL_COMMON_OPTS[@]}" "${AUTH_HEADERS[@]}" -H "Content-Type: application/json" --get "$API_BASE$endpoint" "$@"
}

cloudflare_request() {
  local method="$1" endpoint="$2" data="$3"
  shift 3
  curl "${CURL_COMMON_OPTS[@]}" "${AUTH_HEADERS[@]}" -H "Content-Type: application/json" -X "$method" "$API_BASE$endpoint" -d "$data"
}

resolve_zone_id() {
  local record="$1" candidate response zone_id
  candidate="$record"
  while [[ "$candidate" == *"."* ]]; do
    if [[ -n ${ZONE_ID_CACHE[$candidate]:-} ]]; then
      echo "${ZONE_ID_CACHE[$candidate]}"
      return 0
    fi

    response=$(cloudflare_get "/zones" --data-urlencode "name=$candidate" --data-urlencode "status=active" --data-urlencode "per_page=1") || return 1

    if [[ $(jq -r '.success' <<<"$response") != "true" ]]; then
      jq -r '.errors[]?.message' <<<"$response" >&2
      return 1
    fi

    zone_id=$(jq -r '.result[0].id // empty' <<<"$response")
    if [[ -n "$zone_id" ]]; then
      ZONE_ID_CACHE[$candidate]="$zone_id"
      echo "$zone_id"
      return 0
    fi

    candidate="${candidate#*.}"
  done
  return 1
}

normalize_ttl() {
  local ttl="$1"
  if [[ "$ttl" == "auto" || "$ttl" == "Auto" || "$ttl" == "AUTO" ]]; then
    echo 1
  else
    echo "$ttl"
  fi
}

update_record_if_needed() {
  local record="$1" zone_id response current_ip record_id proxied ttl_value payload update_response new_ip

  zone_id=$(resolve_zone_id "$record") || {
    log "Failed to determine zone for $record; skipping"
    return
  }

  response=$(cloudflare_get "/zones/$zone_id/dns_records" --data-urlencode "type=$TYPE" --data-urlencode "name=$record") || {
    log "Failed to fetch DNS record $record";
    return
  }

  if [[ $(jq -r '.success' <<<"$response") != "true" ]]; then
    log "API error while fetching $record: $(jq -r '.errors[]?.message // "unknown error"' <<<"$response")"
    return
  fi

  if [[ $(jq -r '.result | length' <<<"$response") -eq 0 ]]; then
    log "Record $record not found in Cloudflare zone; skipping"
    return
  fi

  record_id=$(jq -r '.result[0].id' <<<"$response")
  current_ip=$(jq -r '.result[0].content' <<<"$response")
  proxied=$(jq -r '.result[0].proxied // false' <<<"$response")

  if [[ "$current_ip" == "$PUBLIC_IP" ]]; then
    log "Record $record already set to $PUBLIC_IP"
    return
  fi

  if [[ $TEST_MODE == true ]]; then
    log "Test mode: would update $record from $current_ip to $PUBLIC_IP"
    return
  fi

  ttl_value=$(normalize_ttl "$TTL")
  if [[ -z "$ttl_value" || ! "$ttl_value" =~ ^[0-9]+$ ]]; then
    log "TTL value '$TTL' is invalid; defaulting to 300"
    ttl_value=300
  fi
  payload=$(jq -n --arg type "$TYPE" --arg name "$record" --arg content "$PUBLIC_IP" --argjson proxied "$proxied" --arg ttl "$ttl_value" '
    {
      type: $type,
      name: $name,
      content: $content,
      ttl: ($ttl | tonumber),
      proxied: $proxied
    }
  ')

  update_response=$(cloudflare_request "PUT" "/zones/$zone_id/dns_records/$record_id" "$payload") || {
    log "Failed to update DNS record $record"
    return
  }

  if [[ $(jq -r '.success' <<<"$update_response") != "true" ]]; then
    log "API error while updating $record: $(jq -r '.errors[]?.message // "unknown error"' <<<"$update_response")"
    return
  fi

  new_ip=$(jq -r '.result.content' <<<"$update_response")
  log "Updated $record from $current_ip to $new_ip"
}

for record in "${MANAGED_RECORDS[@]}"; do
  update_record_if_needed "$record"

done

if [[ $TEST_MODE == true ]]; then
  log "Dry run complete"
else
  log "Sync complete"
fi
