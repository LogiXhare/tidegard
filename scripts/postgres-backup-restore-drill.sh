#!/usr/bin/env bash
# The incident database's backup and restore drill (Phase 5F, NFR-2).
#
# Seeds the ephemeral test database through the service, takes a real
# `pg_dump --format=custom` backup, restores it into a fresh database with
# `pg_restore`, compares the two row for row, and then proves the restored
# copy works: see crates/incident-postgres/tests/backup_restore_drill.rs.
#
# This touches ONLY the opt-in, ephemeral test database. It drops and
# recreates the restore target, and the seed resets the source's schema.
# Never point it at a real database.
#
# Environment:
#   TIDEGARD_INCIDENT_POSTGRES_TEST_URL  libpq key=value form; the
#                       source. The restored copy's URL is this with dbname
#                       replaced.
#   DRILL_PG_TOOL       Prefix that runs the PostgreSQL client tools, such as
#                       "docker exec -i <container>" so they match the
#                       server's major version. Empty runs the local ones.
#   DRILL_PG_USER       Role the tools connect as (default tidegard_test).
#   DRILL_SOURCE_DB     Default tidegard_incident_test.
#   DRILL_RESTORED_DB   Default tidegard_incident_drill_restored.
#   DRILL_WORK_DIR      Where the dump and fingerprints go (default a mktemp
#                       directory).
set -euo pipefail

: "${TIDEGARD_INCIDENT_POSTGRES_TEST_URL:?names the ephemeral source database}"
tool=${DRILL_PG_TOOL:-}
user=${DRILL_PG_USER:-tidegard_test}
source_db=${DRILL_SOURCE_DB:-tidegard_incident_test}
restored_db=${DRILL_RESTORED_DB:-tidegard_incident_drill_restored}
work=${DRILL_WORK_DIR:-$(mktemp -d)}
mkdir -p "$work"

# shellcheck disable=SC2086 # $tool is a command prefix and must split.
pg() { $tool "$@"; }

# Runs one test of the drill and fails unless it actually ran and passed:
# a filter that matches nothing would otherwise pass with zero tests.
drill_test() {
  local name=$1 log="$work/$1.log"
  cargo test -p tidegard-incident-postgres --test backup_restore_drill \
    -- --ignored --exact "$name" 2>&1 | tee "$log"
  grep -q "test $name ... ok" "$log" || { echo "drill: $name did not pass"; exit 1; }
}

# Every table's row count and an md5 over its rows in a stable order, plus
# every sequence's position, so a restore that loses, adds or alters a row,
# or rewinds a sequence, differs.
fingerprint() {
  local db=$1
  pg psql -X -v ON_ERROR_STOP=1 -U "$user" -d "$db" -tA -F ' ' <<'SQL'
SELECT format(
         'SELECT %L, count(*), md5(coalesce(string_agg(t::text, E''\n'' ORDER BY t::text), '''')) FROM %I.%I t',
         tablename, schemaname, tablename)
FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename
\gexec
SELECT 'sequence ' || sequencename, coalesce(last_value, 0) FROM pg_sequences
WHERE schemaname = 'public' ORDER BY sequencename;
SQL
}

echo "drill: seeding $source_db"
drill_test drill_seed

echo "drill: fingerprinting the source"
fingerprint "$source_db" > "$work/source.txt"

echo "drill: backing up with pg_dump"
pg pg_dump -U "$user" -d "$source_db" --format=custom --no-owner > "$work/incident.dump"
test -s "$work/incident.dump"
pg pg_restore --list < "$work/incident.dump" > /dev/null
echo "drill: backup is $(wc -c < "$work/incident.dump") bytes"

echo "drill: restoring into a fresh $restored_db"
pg psql -X -v ON_ERROR_STOP=1 -U "$user" -d postgres \
  -c "DROP DATABASE IF EXISTS $restored_db" -c "CREATE DATABASE $restored_db"
pg pg_restore -U "$user" -d "$restored_db" --no-owner --exit-on-error --single-transaction \
  < "$work/incident.dump"

echo "drill: comparing the restored copy with the source"
fingerprint "$restored_db" > "$work/restored.txt"
if ! diff -u "$work/source.txt" "$work/restored.txt"; then
  echo "drill: the restored database differs from the source"
  exit 1
fi
tables=$(grep -vc '^sequence ' "$work/source.txt")
echo "drill: $tables tables identical"

echo "drill: verifying the restored copy works"
# libpq key=value form: the last dbname wins.
export TIDEGARD_INCIDENT_POSTGRES_DRILL_RESTORED_URL="$TIDEGARD_INCIDENT_POSTGRES_TEST_URL dbname=$restored_db"
drill_test drill_verify

echo "drill: passed"
