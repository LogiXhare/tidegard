#!/usr/bin/env bash
# The analytics database's backup and restore drill (Phase 9C, NFR-2).
#
# Fills every Tidegard table in an ephemeral ClickHouse with
# synthetic rows, takes a real `BACKUP TABLE ... TO File(...)`, drops
# the tables, restores them with `RESTORE`, compares every table's row
# count and content hash with the original, and then proves the restored
# copy takes new rows: crates/storage/tests/clickhouse_integration.rs
# writes and reads back every row type.
#
# This touches ONLY CI's throwaway ClickHouse, whose config allows
# backups under /backups/ (docs/operations/backup-and-restore.md). It
# drops tables. Never point it at a real server.
#
# Environment:
#   CLICKHOUSE_URL       http://127.0.0.1:8123 (loopback, plain HTTP)
#   CLICKHOUSE_USER, CLICKHOUSE_PASSWORD
#   DRILL_BACKUP_NAME    Default tidegard-drill-<epoch>.zip
#   DRILL_WORK_DIR       Where the fingerprints go (default a mktemp directory)
#
# Run it from the repository root: it runs a cargo test at the end.
set -euo pipefail

: "${CLICKHOUSE_URL:?names the throwaway ClickHouse}"
: "${CLICKHOUSE_USER:?}" "${CLICKHOUSE_PASSWORD:?}"
backup=${DRILL_BACKUP_NAME:-tidegard-drill-$(date +%s).zip}
work=${DRILL_WORK_DIR:-$(mktemp -d)}
mkdir -p "$work"

ch() {
  curl -sS --fail-with-body --user "$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD" \
    --data-binary "$1" "$CLICKHOUSE_URL/"
}

tables=$(ch "SELECT name FROM system.tables WHERE database = 'default' AND name LIKE 'wetechinetmon_%' ORDER BY name")
[ -n "$tables" ] || { echo "drill: no Tidegard tables; create the schema first"; exit 1; }

echo "drill: filling $(echo "$tables" | wc -l) tables"
for table in $tables; do
  # Synthetic rows of the right shape: ClickHouse fills each column with
  # its type's default, and timestamps spread over the last day.
  ch "INSERT INTO $table (timestamp) SELECT now() - number FROM numbers(1000)"
done

# Every table's row count and a hash over all its rows, order-independent.
fingerprint() {
  for table in $tables; do
    echo "$table $(ch "SELECT count(), groupBitXor(cityHash64(*)) FROM $table" | tr '\t' ' ')"
  done
}
fingerprint > "$work/before.txt"
cat "$work/before.txt"

# Table by table, so the restore recreates exactly these into the existing
# database, as an operator restoring Tidegard's tables would.
list=$(echo "$tables" | sed 's/^/TABLE default./' | paste -sd, -)

echo "drill: backing up to File('$backup')"
ch "BACKUP $list TO File('$backup')"

echo "drill: dropping every table"
for table in $tables; do
  ch "DROP TABLE $table SYNC"
done
[ -z "$(ch "SELECT name FROM system.tables WHERE database = 'default' AND name LIKE 'wetechinetmon_%'")" ]

echo "drill: restoring"
ch "RESTORE $list FROM File('$backup')"

echo "drill: comparing"
fingerprint > "$work/after.txt"
if ! diff -u "$work/before.txt" "$work/after.txt"; then
  echo "drill: the restored tables differ from the originals"
  exit 1
fi
echo "drill: $(wc -l < "$work/after.txt") tables identical"

echo "drill: the collector's writer works against the restored copy"
TIDEGARD_CLICKHOUSE_TEST_URL="$CLICKHOUSE_URL" \
  TIDEGARD_CLICKHOUSE_TEST_USER="$CLICKHOUSE_USER" \
  TIDEGARD_CLICKHOUSE_TEST_PASSWORD="$CLICKHOUSE_PASSWORD" \
  cargo test -p tidegard-storage --test clickhouse_integration -- --nocapture 2>&1 | tee "$work/verify.log"
grep -q "test every_row_type_round_trips_against_a_real_server ... ok" "$work/verify.log"
if grep -q "skipping every_row_type_round_trips_against_a_real_server" "$work/verify.log"; then
  echo "drill: the verification skipped"
  exit 1
fi

echo "drill: passed"
