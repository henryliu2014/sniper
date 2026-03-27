#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <sniper-binary>" >&2
    exit 2
fi

SNIPER_BIN=$1

if [[ ! -x "$SNIPER_BIN" ]]; then
    echo "sniper binary is not executable: $SNIPER_BIN" >&2
    exit 2
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo "SKIP: live functional test requires BPF privileges; current uid is not root" >&2
    exit 77
fi

for cmd in initdb pg_ctl psql; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "SKIP: missing required command: $cmd" >&2
        exit 77
    fi
done

TMP_DIR=$(mktemp -d)
PGDATA="$TMP_DIR/pgdata"
SOCKDIR="$TMP_DIR/socket"
LOGFILE="$TMP_DIR/postgres.log"
SNIPER_OUT="$TMP_DIR/sniper.out"
SNIPER_ERR="$TMP_DIR/sniper.err"

mkdir -p "$SOCKDIR"

cleanup() {
    set +e
    if [[ -f "$PGDATA/postmaster.pid" ]]; then
        pg_ctl -D "$PGDATA" -m immediate stop >/dev/null 2>&1
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

initdb -D "$PGDATA" -A trust -U postgres >/dev/null
cat >>"$PGDATA/postgresql.conf" <<EOF
listen_addresses = ''
unix_socket_directories = '$SOCKDIR'
fsync = off
synchronous_commit = off
full_page_writes = off
EOF

pg_ctl -D "$PGDATA" -l "$LOGFILE" start >/dev/null

PROBE_DURATION_SEC=5 "$SNIPER_BIN" >"$SNIPER_OUT" 2>"$SNIPER_ERR" &
SNIPER_PID=$!

sleep 1

psql -h "$SOCKDIR" -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
create table if not exists t_sniper(a int);
truncate t_sniper;
insert into t_sniper(a) values (1), (2), (3);
select * from t_sniper order by a;
SQL

wait "$SNIPER_PID"

grep -q '^QUERY$' "$SNIPER_OUT"
grep -q 'sql: select \* from t_sniper order by a' "$SNIPER_OUT"
