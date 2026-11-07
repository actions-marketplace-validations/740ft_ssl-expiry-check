#!/usr/bin/env bash
# SSL certificate expiry check for GitHub Actions (by DomainCat, https://domaincat.app).
# Entry formats:  host   host:port   host@origin-ip   host@origin-ip:port
#   host@origin-ip connects to that IP but asks for the host (SNI): checks the origin
#   certificate behind Cloudflare or another CDN, which normal checkers never see.
set -uo pipefail

DOMAINS="${INPUT_DOMAINS:-}"
WARN_DAYS="${INPUT_WARN_DAYS:-21}"
FAIL_DAYS="${INPUT_FAIL_DAYS:-7}"
TIMEOUT="${INPUT_TIMEOUT:-15}"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
OUTPUT="${GITHUB_OUTPUT:-/dev/null}"

if [[ -z "${DOMAINS//[[:space:],]/}" ]]; then
  echo "::error::No domains given. Set the 'domains' input."
  exit 1
fi
for n in "$WARN_DAYS" "$FAIL_DAYS" "$TIMEOUT"; do
  [[ "$n" =~ ^[0-9]+$ ]] || { echo "::error::warn-days, fail-days and timeout must be whole numbers (got '$n')."; exit 1; }
done

now=$(date -u +%s)
failed=0; warned=0; soonest=""
rows=""

esc() { printf '%s' "$1" | sed 's/|/\\|/g'; }

check_one() {
  local entry="$1" host target port ip="" label
  host="$entry"; port=443
  if [[ "$entry" == *@* ]]; then host="${entry%%@*}"; ip="${entry#*@}"; fi
  if [[ -n "$ip" ]]; then
    if [[ "$ip" =~ ^(.+):([0-9]+)$ && "$ip" != *::* ]]; then ip="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"; fi
    target="$ip"
  else
    if [[ "$host" =~ ^(.+):([0-9]+)$ ]]; then host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"; fi
    target="$host"
  fi
  if ! [[ "$host" =~ ^[A-Za-z0-9.-]+$ ]] || { [[ -n "$ip" ]] && ! [[ "$ip" =~ ^[0-9A-Fa-f.:]+$ ]]; }; then
    rows+="| \`$(esc "$entry")\` | ❌ Invalid entry | | | |"$'\n'
    echo "::error::Invalid entry '$entry'. Use host, host:port, host@ip or host@ip:port."
    failed=$((failed+1)); return
  fi
  label="$host"; [[ -n "$ip" ]] && label="$host (origin $ip)"
  [[ "$port" != 443 ]] && label="$label :$port"
  local connect="$target:$port"; [[ "$target" == *:* ]] && connect="[$target]:$port"

  local out cert
  out=$(timeout "$TIMEOUT" openssl s_client -connect "$connect" -servername "$host" -verify_hostname "$host" -showcerts </dev/null 2>&1)
  cert=$(printf '%s\n' "$out" | awk '/-----BEGIN CERTIFICATE-----/{f=1} f{print} /-----END CERTIFICATE-----/{exit}')
  if [[ -z "$cert" ]]; then
    rows+="| $(esc "$label") | ❌ No certificate (handshake failed or port closed) | | | |"$'\n'
    echo "::error::$label: could not get a certificate (TLS handshake failed, timed out, or nothing on port $port)."
    failed=$((failed+1)); return
  fi

  local end end_s days issuer verify note="" status
  end=$(printf '%s\n' "$cert" | openssl x509 -noout -enddate | cut -d= -f2)
  end_s=$(date -u -d "$end" +%s)
  days=$(( (end_s - now) / 86400 ))
  issuer=$(printf '%s\n' "$cert" | openssl x509 -noout -issuer | sed -n 's/.*O *= *\([^,]*\).*/\1/p')
  [[ -z "$issuer" ]] && issuer=$(printf '%s\n' "$cert" | openssl x509 -noout -issuer | sed 's/^issuer= *//')
  verify=$(printf '%s\n' "$out" | sed -n 's/.*Verify return code: \([0-9]*\) (\(.*\))/\1 \2/p' | tail -1)

  if [[ "$issuer" == *"CloudFlare"* && "$issuer" != *"Cloudflare, Inc."* ]] || printf '%s\n' "$cert" | openssl x509 -noout -issuer | grep -qi "Origin SSL Certificate Authority"; then
    note="Cloudflare Origin CA (trusted by Cloudflare only)"
    verify="0 ok"
  fi

  if [[ -z "$soonest" || "$days" -lt "$soonest" ]]; then soonest="$days"; fi
  local expiry; expiry=$(date -u -d "@$end_s" +%Y-%m-%d)

  if (( days < 0 )); then
    status="❌ Expired $(( -days )) days ago"; failed=$((failed+1))
    echo "::error::$label: certificate EXPIRED on $expiry."
  elif ! printf '%s\n' "$cert" | openssl x509 -noout -checkhost "$host" | grep -q "does match"; then
    status="❌ Hostname not in certificate"; failed=$((failed+1))
    echo "::error::$label: the certificate does not cover $host."
  elif [[ "${verify%% *}" != "0" ]]; then
    status="❌ Not trusted (${verify#* })"; failed=$((failed+1))
    echo "::error::$label: certificate not trusted: ${verify#* }."
  elif (( days <= FAIL_DAYS )); then
    status="❌ Expires in $days days"; failed=$((failed+1))
    echo "::error::$label: certificate expires in $days days ($expiry)."
  elif (( days <= WARN_DAYS )); then
    status="⚠️ Expires in $days days"; warned=$((warned+1))
    echo "::warning::$label: certificate expires in $days days ($expiry)."
  else
    status="✅ OK"
    echo "$label: OK, $days days left ($expiry)."
  fi
  rows+="| $(esc "$label") | $status | $days | $expiry | $(esc "$issuer")${note:+ · $note} |"$'\n'
}

for entry in $(printf '%s' "$DOMAINS" | tr ',' ' '); do
  check_one "$entry"
done

{
  echo "## SSL certificate check"
  echo
  echo "| Domain | Status | Days left | Expires | Issuer |"
  echo "|---|---|---|---|---|"
  printf '%s' "$rows"
  echo
  echo "Warn at ${WARN_DAYS} days, fail at ${FAIL_DAYS} days. ${failed} failed, ${warned} warning."
  echo
  echo "_This only runs when your workflow runs. For email alerts weeks before a cert expires, including the origin cert behind Cloudflare, [DomainCat](https://domaincat.app/?utm_source=github&utm_medium=action&utm_campaign=ssl-expiry-check) monitors it continuously. Free for 5 domains._"
} >> "$SUMMARY"

{
  echo "failed=$failed"
  echo "warned=$warned"
  echo "soonest-days=$soonest"
} >> "$OUTPUT"

if (( failed > 0 )) && [[ "${INPUT_FAIL_ON_ERROR:-true}" == "true" ]]; then
  exit 1
fi
exit 0
