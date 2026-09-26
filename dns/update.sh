#!/usr/bin/env bash
#
# Client script to trigger Cloud DNS update via HTTP POST
# if the current public IPv4 or IPv6 address differs from the DNS record.
#
# Usage:
#   ./update.sh <host> [token] [endpoint_url] [managed_zone]
#   ./update.sh --force <host> [token] [endpoint_url] [managed_zone]
#
# Environment variables:
#   HOST="home.example.com"
#   AUTH_TOKEN="secret"
#   URL="http://localhost:8080"
#   MANAGED_ZONE="zone-name"
#   FORCE=1  (force update regardless of current DNS records)

set -euo pipefail

FORCE="${FORCE:-0}"
if [[ "${1:-}" == "--force" || "${1:-}" == "-f" ]]; then
  FORCE=1
  shift
fi

HOST="${1:-${HOST:-}}"
TOKEN="${2:-${AUTH_TOKEN:-${TOKEN:-}}}"
URL="${3:-${ENDPOINT_URL:-${URL:-http://127.0.0.1:8080}}}"
MANAGED_ZONE="${4:-${MANAGED_ZONE:-}}"

if [[ -z "${HOST}" ]]; then
  echo "Usage: $0 [--force|-f] <host> [token] [endpoint_url] [managed_zone]" >&2
  echo "Example: $0 home.example.com secret-token http://localhost:8080" >&2
  exit 1
fi

normalize_ip() {
  local ip="$1"
  if [[ -z "${ip}" ]]; then
    echo ""
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "import ipaddress, sys; print(ipaddress.ip_address(sys.argv[1]))" "${ip}" 2>/dev/null && return 0
  fi
  echo "${ip}" | tr '[:upper:]' '[:lower:]'
}

get_current_public_ipv4() {
  local ip=""

  # 1. Try Google DNS TXT query (fast, direct IPv4)
  if command -v dig >/dev/null 2>&1; then
    ip=$(dig -4 +short TXT o-o.myaddr.l.google.com @ns1.google.com 2>/dev/null | tr -d '" ' || true)
    if [[ -n "${ip}" && "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "${ip}"
      return 0
    fi
  fi

  # 2. HTTP fallbacks
  local providers=(
    "https://api.ipify.org"
    "https://ifconfig.me/ip"
    "https://checkip.amazonaws.com"
    "https://icanhazip.com"
  )

  for provider in "${providers[@]}"; do
    ip=$(curl -4 -s -m 5 "${provider}" 2>/dev/null | tr -d '[:space:]' || true)
    if [[ -n "${ip}" && "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "${ip}"
      return 0
    fi
  done

  return 1
}

get_current_public_ipv6() {
  local ip=""

  # 1. Try Google DNS TXT query over IPv6
  if command -v dig >/dev/null 2>&1; then
    ip=$(dig -6 +short TXT o-o.myaddr.l.google.com @ns1.google.com 2>/dev/null | tr -d '" ' || true)
    if [[ -n "${ip}" && "${ip}" =~ ^[0-9a-fA-F:]+$ && "${ip}" == *:* ]]; then
      echo "${ip}"
      return 0
    fi
  fi

  # 2. HTTP fallbacks
  local providers=(
    "https://api64.ipify.org"
    "https://ifconfig.co/ip"
    "https://icanhazip.com"
    "https://v6.ident.me"
  )

  for provider in "${providers[@]}"; do
    ip=$(curl -6 -s -m 5 "${provider}" 2>/dev/null | tr -d '[:space:]' || true)
    if [[ -n "${ip}" && "${ip}" =~ ^[0-9a-fA-F:]+$ && "${ip}" == *:* ]]; then
      echo "${ip}"
      return 0
    fi
  done

  return 1
}

get_dns_resolved_ipv4() {
  local target_host="$1"
  local resolved=""

  if command -v dig >/dev/null 2>&1; then
    # Query Google Public DNS directly to bypass local resolver cache
    resolved=$(dig +short A "${target_host}" @8.8.8.8 2>/dev/null | tail -n1 | tr -d '[:space:]' || true)
  elif command -v host >/dev/null 2>&1; then
    resolved=$(host -t A "${target_host}" 8.8.8.8 2>/dev/null | awk '/has address/ {print $NF}' | tail -n1 || true)
  elif command -v nslookup >/dev/null 2>&1; then
    resolved=$(nslookup -type=A "${target_host}" 8.8.8.8 2>/dev/null | awk '/^Address: / {print $2}' | tail -n1 || true)
  fi

  if [[ -n "${resolved}" && "${resolved}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "${resolved}"
  fi
}

get_dns_resolved_ipv6() {
  local target_host="$1"
  local resolved=""

  if command -v dig >/dev/null 2>&1; then
    resolved=$(dig +short AAAA "${target_host}" @8.8.8.8 2>/dev/null | tail -n1 | tr -d '[:space:]' || true)
  elif command -v host >/dev/null 2>&1; then
    resolved=$(host -t AAAA "${target_host}" 8.8.8.8 2>/dev/null | awk '/has IPv6 address/ {print $NF}' | tail -n1 || true)
  elif command -v nslookup >/dev/null 2>&1; then
    resolved=$(nslookup -type=AAAA "${target_host}" 8.8.8.8 2>/dev/null | awk '/^Address: / {print $2}' | tail -n1 || true)
  fi

  if [[ -n "${resolved}" && "${resolved}" =~ ^[0-9a-fA-F:]+$ && "${resolved}" == *:* ]]; then
    echo "${resolved}"
  fi
}

echo "Checking current public IP addresses..."
CURRENT_IPV4=$(get_current_public_ipv4 || true)
CURRENT_IPV6=$(get_current_public_ipv6 || true)
CURRENT_IPV4=$(normalize_ip "${CURRENT_IPV4}")
CURRENT_IPV6=$(normalize_ip "${CURRENT_IPV6}")

if [[ -n "${CURRENT_IPV4}" ]]; then
  echo "Current public IPv4: ${CURRENT_IPV4}"
else
  echo "Current public IPv4: (none detected)"
fi

if [[ -n "${CURRENT_IPV6}" ]]; then
  echo "Current public IPv6: ${CURRENT_IPV6}"
else
  echo "Current public IPv6: (none detected)"
fi

RESOLVED_IPV4=$(get_dns_resolved_ipv4 "${HOST}" || true)
RESOLVED_IPV6=$(get_dns_resolved_ipv6 "${HOST}" || true)
RESOLVED_IPV4=$(normalize_ip "${RESOLVED_IPV4}")
RESOLVED_IPV6=$(normalize_ip "${RESOLVED_IPV6}")

if [[ -n "${RESOLVED_IPV4}" ]]; then
  echo "Current DNS A record for '${HOST}': ${RESOLVED_IPV4}"
else
  echo "Current DNS A record for '${HOST}': (none / unresolvable)"
fi

if [[ -n "${RESOLVED_IPV6}" ]]; then
  echo "Current DNS AAAA record for '${HOST}': ${RESOLVED_IPV6}"
else
  echo "Current DNS AAAA record for '${HOST}': (none / unresolvable)"
fi

NEEDS_UPDATE=0

if [[ "${FORCE}" -eq 1 ]]; then
  echo "Force update requested (--force)."
  NEEDS_UPDATE=1
elif [[ -z "${CURRENT_IPV4}" && -z "${CURRENT_IPV6}" ]]; then
  echo "Warning: Could not determine current public IP addresses locally. Proceeding with endpoint invocation."
  NEEDS_UPDATE=1
else
  if [[ -n "${CURRENT_IPV4}" ]]; then
    if [[ -z "${RESOLVED_IPV4}" || "${CURRENT_IPV4}" != "${RESOLVED_IPV4}" ]]; then
      echo "IPv4 difference detected: ${RESOLVED_IPV4:-(none)} -> ${CURRENT_IPV4}"
      NEEDS_UPDATE=1
    else
      echo "IPv4 record is up to date (${CURRENT_IPV4})."
    fi
  fi

  if [[ -n "${CURRENT_IPV6}" ]]; then
    if [[ -z "${RESOLVED_IPV6}" || "${CURRENT_IPV6}" != "${RESOLVED_IPV6}" ]]; then
      echo "IPv6 difference detected: ${RESOLVED_IPV6:-(none)} -> ${CURRENT_IPV6}"
      NEEDS_UPDATE=1
    else
      echo "IPv6 record is up to date (${CURRENT_IPV6})."
    fi
  fi
fi

if [[ "${NEEDS_UPDATE}" -eq 0 ]]; then
  echo "DNS records for '${HOST}' are already up to date. Skipping update."
  exit 0
fi

# Build JSON payload
json_fields=()
json_fields+=("\"host\":\"${HOST}\"")
if [[ -n "${CURRENT_IPV4:-}" ]]; then
  json_fields+=("\"ipv4\":\"${CURRENT_IPV4}\"")
fi
if [[ -n "${CURRENT_IPV6:-}" ]]; then
  json_fields+=("\"ipv6\":\"${CURRENT_IPV6}\"")
fi
if [[ -n "${TOKEN:-}" ]]; then
  json_fields+=("\"token\":\"${TOKEN}\"")
fi
if [[ -n "${MANAGED_ZONE:-}" ]]; then
  json_fields+=("\"managed_zone\":\"${MANAGED_ZONE}\"")
fi

IFS=","
PAYLOAD="{${json_fields[*]}}"
unset IFS

echo "Sending DNS update request to ${URL} for host '${HOST}'..."
echo "+ curl -i -X POST \"${URL}\" -H \"Content-Type: application/json\" -d '${PAYLOAD}'"
curl -i -X POST "${URL}" \
  -H "Content-Type: application/json" \
  -d "${PAYLOAD}"

echo ""

