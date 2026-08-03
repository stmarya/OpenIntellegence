#!/usr/bin/env sh
set -eu
: "${DATABASE_URL:?DATABASE_URL must be set}"
out="${1:-openintelligence-$(date -u +%Y%m%dT%H%M%SZ).dump}"
umask 077
pg_dump --format=custom --no-owner --no-acl --file="$out" "$DATABASE_URL"
sha256sum "$out" > "$out.sha256"
printf 'Backup written to %s; restore has not been tested by this command.\n' "$out"
