#!/usr/bin/env sh
set -eu
: "${DATABASE_URL:?DATABASE_URL must be set}"
file="${1:?usage: restore-postgres.sh BACKUP.dump}"
test -f "$file" || { echo "Backup not found: $file" >&2; exit 2; }
test -f "$file.sha256" || { echo "Checksum file missing: $file.sha256" >&2; exit 2; }
sha256sum -c "$file.sha256"
printf 'This replaces objects in the configured database. Type restore to continue: '
read answer
[ "$answer" = restore ] || { echo "Cancelled."; exit 3; }
pg_restore --clean --if-exists --no-owner --no-acl --dbname="$DATABASE_URL" "$file"
echo "Restore command completed; application-level integrity still requires verification."
