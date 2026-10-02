#!/bin/sh
# Downloads IPGeolocation.io MMDB databases, verifies them and installs them atomically.
#
# usage: ipgeolocation-update.sh [-d DIR] [-i SECONDS] [-w SECONDS] [-r] [URL ...]
#
#   URL         link of a database archive (ZIP) or of a raw .mmdb file: the download links in your
#               IPGeolocation.io account. Links carry your API key, so pass them through $IPGEO_URLS
#               (space-separated) from a secret rather than on the command line. file:// links work too.
#   -d DIR      install directory (default: $IPGEO_DIR, else /usr/local/share/ipgeolocation)
#   -i SECONDS  keep running and update every SECONDS (default: $IPGEO_INTERVAL; unset: run once)
#   -w SECONDS  wait before the first update (for a sidecar next to an init container)
#   -r          run `kong reload` after a database changed (Kong on the same host)
#
# Signature verification, as documented by IPGeolocation.io (openssl dgst -sha256 -verify):
#   IPGEO_PUBLIC_KEY       path of IPGeolocation.io's public key (PEM), or
#   IPGEO_PUBLIC_KEY_PEM   the key itself
#   IPGEO_SIGNATURE_URLS   signature links, space-separated, in the same order as the URLs
# Optional deeper validation, run on each database before it is installed:
#   IPGEO_VALIDATE         a command, e.g. "resty -I /opt/plugin /opt/plugin/tools/mmdb-check.lua"
#
# Each archive's checksum.txt is verified. A database is installed only if it is a valid MMDB file and
# differs from the installed one, by renaming a file from the same directory, so Kong never sees a
# partial file. Exit status is non-zero if any database failed. Requires curl, unzip, sha256sum, and
# openssl for signatures.

set -eu

log() { printf '%s ipgeolocation-update: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { log "error: $*"; exit 1; }

DIR=${IPGEO_DIR:-/usr/local/share/ipgeolocation}
INTERVAL=${IPGEO_INTERVAL:-}
WAIT=0
RELOAD=${IPGEO_RELOAD:-0}

while getopts d:i:w:rh opt; do
  case $opt in
    d) DIR=$OPTARG ;;
    i) INTERVAL=$OPTARG ;;
    w) WAIT=$OPTARG ;;
    r) RELOAD=1 ;;
    h) sed -n '2,29p' "$0"; exit 0 ;;
    *) exit 2 ;;
  esac
done
shift $((OPTIND - 1))
URLS=${*:-${IPGEO_URLS:-}}
SIGS=${IPGEO_SIGNATURE_URLS:-}
[ -n "$URLS" ] || die "no database URL given (arguments or IPGEO_URLS)"

for tool in curl unzip sha256sum find cmp; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done
mkdir -p "$DIR"

KEY=${IPGEO_PUBLIC_KEY:-}
KEY_TMP=""
if [ -n "${IPGEO_PUBLIC_KEY_PEM:-}" ]; then
  KEY_TMP=$(mktemp)
  printf '%s\n' "$IPGEO_PUBLIC_KEY_PEM" > "$KEY_TMP"
  KEY=$KEY_TMP
fi
if [ -n "$KEY" ] || [ -n "$SIGS" ]; then
  [ -n "$KEY" ] && [ -n "$SIGS" ] || die "signature verification needs a public key and IPGEO_SIGNATURE_URLS"
  command -v openssl >/dev/null 2>&1 || die "openssl is required for signature verification"
fi

# Links carry the API key in the query string; never log it.
redact() { printf '%s' "$1" | sed -E 's/[?#].*$/?.../'; }

# Prints the n-th word of the remaining arguments.
nth() {
  _nth_want=$1; shift; _nth_i=0
  for _nth_w in "$@"; do
    _nth_i=$((_nth_i + 1))
    if [ "$_nth_i" -eq "$_nth_want" ]; then printf '%s' "$_nth_w"; return 0; fi
  done
}

valid_mmdb() {
  [ -s "$1" ] || return 1
  # The metadata marker sits in the last 128 KiB of every MaxMind DB file.
  tail -c 131072 "$1" | LC_ALL=C grep -q 'MaxMind\.com' || return 1
  if [ -n "${IPGEO_VALIDATE:-}" ]; then
    # shellcheck disable=SC2086
    $IPGEO_VALIDATE "$1" >&2 || return 1
  fi
}

CHANGED=0

install_url() {  # url signature-url workdir
  _url=$1; _sig=$2; _w=$3; _label=$(redact "$_url")
  mkdir -p "$_w/x"
  log "downloading $_label"
  curl -fsSL --retry 3 --retry-delay 5 --connect-timeout 30 -o "$_w/archive" "$_url" \
    || { log "download failed: $_label"; return 1; }

  if [ -n "$_sig" ]; then
    curl -fsSL --retry 3 --retry-delay 5 --connect-timeout 30 -o "$_w/archive.sig" "$_sig" \
      || { log "signature download failed: $(redact "$_sig")"; return 1; }
    openssl dgst -sha256 -verify "$KEY" -signature "$_w/archive.sig" "$_w/archive" >/dev/null 2>&1 \
      || { log "signature verification FAILED: $_label"; return 1; }
    log "signature verified"
  fi

  if [ "$(head -c 2 "$_w/archive")" = "PK" ]; then
    unzip -q -o "$_w/archive" -d "$_w/x" || { log "cannot extract $_label"; return 1; }
    _sums=$(find "$_w/x" -name checksum.txt | head -n 1)
    if [ -n "$_sums" ]; then
      (cd "$(dirname "$_sums")" && sha256sum -c checksum.txt >/dev/null 2>&1) \
        || { log "checksum verification FAILED: $_label"; return 1; }
      log "checksums verified"
    else
      log "warning: no checksum.txt in $_label"
    fi
  else
    _name=$(basename "$(printf '%s' "$_url" | sed 's/[?#].*//')")
    case $_name in
      *.mmdb) mv "$_w/archive" "$_w/x/$_name" ;;
      *) log "neither a ZIP archive nor a .mmdb file: $_label"; return 1 ;;
    esac
  fi

  _found=0
  for _f in $(find "$_w/x" -name '*.mmdb'); do
    _found=1
    _base=$(basename "$_f")
    valid_mmdb "$_f" || { log "$_base is not a valid MMDB database"; return 1; }
    if [ -f "$DIR/$_base" ] && cmp -s "$_f" "$DIR/$_base"; then
      log "$_base is unchanged"
      continue
    fi
    chmod 0644 "$_f"
    # Same filesystem: rename(2) replaces the file atomically. Running Kong workers keep
    # the old file mapped until they switch to the new one.
    mv -f "$_f" "$DIR/$_base" || { log "cannot install $_base"; return 1; }
    CHANGED=$((CHANGED + 1))
    log "installed $DIR/$_base"
  done
  [ "$_found" -eq 1 ] || { log "no .mmdb file in $_label"; return 1; }
}

run_once() {
  CHANGED=0
  _failed=0
  WORK=$(mktemp -d "$DIR/.ipgeo-update.XXXXXX") || { log "cannot create a temporary directory in $DIR"; return 1; }
  trap 'rm -rf "$WORK" "$KEY_TMP"' EXIT
  trap 'rm -rf "$WORK" "$KEY_TMP"; exit 1' INT TERM
  _n=0
  for _u in $URLS; do
    _n=$((_n + 1))
    # shellcheck disable=SC2086
    _s=$(nth "$_n" $SIGS)
    if [ -n "$SIGS" ] && [ -z "$_s" ]; then
      log "no signature link for $(redact "$_u")"; _failed=$((_failed + 1)); continue
    fi
    install_url "$_u" "$_s" "$WORK/$_n" || _failed=$((_failed + 1))
  done
  rm -rf "$WORK"
  if [ "$CHANGED" -gt 0 ] && [ "$RELOAD" = 1 ]; then
    if kong reload >/dev/null; then log "kong reloaded"; else log "kong reload failed"; _failed=$((_failed + 1)); fi
  fi
  [ "$_failed" -eq 0 ]
}

if [ "$WAIT" -gt 0 ]; then sleep "$WAIT"; fi
if [ -n "$INTERVAL" ]; then
  while :; do
    run_once || log "update incomplete; retrying in ${INTERVAL}s"
    sleep "$INTERVAL"
  done
else
  run_once
fi
