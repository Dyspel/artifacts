#!/usr/bin/env bash
# Restore a backup produced by scripts/backup.sh into a fresh data dir.
#
# Usage: restore.sh <backup-dir> <data-dir>
#
# The artifacts server MUST NOT be running against <data-dir> when
# restore is in progress — restore truncates whatever already exists
# there. Stop the service, restore, then start it again. (Online
# restore is intentionally unsupported; the server's open file
# handles to the SQLite databases would observe a torn state.)

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <backup-dir> <data-dir>" >&2
    exit 64
fi

BACKUP_DIR="$1"
DATA_DIR="$2"

if [[ ! -d "$BACKUP_DIR" ]]; then
    echo "backup-dir does not exist: $BACKUP_DIR" >&2
    exit 1
fi

mkdir -p "$DATA_DIR"

for db in tokens.db audit.db webhooks.db; do
    src="$BACKUP_DIR/$db"
    if [[ -f "$src" ]]; then
        # WAL/SHM sidecars (if any from a `.backup` snapshot taken while
        # the source DB had an open WAL) are not relevant in the destination
        # — SQLite reconstructs them on first open. Just drop the main file.
        rm -f "$DATA_DIR/${db}-wal" "$DATA_DIR/${db}-shm"
        cp -p "$src" "$DATA_DIR/$db"
        echo "  + $db"
    fi
done

if [[ -f "$BACKUP_DIR/webhook-key.bin" ]]; then
    install -m 0600 "$BACKUP_DIR/webhook-key.bin" "$DATA_DIR/webhook-key.bin"
    echo "  + webhook-key.bin"
fi

if [[ -f "$BACKUP_DIR/repos.tar" ]]; then
    # Remove the existing repos dir before extracting so leftover repos
    # from a previous deployment don't survive a "restore-to-clean-state."
    rm -rf "$DATA_DIR/repos"
    tar -C "$DATA_DIR" -xf "$BACKUP_DIR/repos.tar"
    echo "  + repos/ ($(find "$DATA_DIR/repos" -maxdepth 1 -mindepth 1 -type d | wc -l) repos)"
fi

echo "restore complete: $DATA_DIR"
