#!/usr/bin/env bash
# Online backup of an artifacts data dir.
#
# Usage: backup.sh <data-dir> <backup-dir>
#
# Output (under <backup-dir>):
#   tokens.db          SQLite snapshot via `.backup` (transactional,
#                      no quiesce needed on the source server).
#   audit.db           Same.
#   webhooks.db        Same, if present.
#   webhook-key.bin    File copy, if present (file-backed master key).
#   repos.tar          tar of the bare git repos.
#
# Safe to run while the artifacts server is live — SQLite's `.backup`
# is an online checkpoint that respects WAL-mode concurrent writers,
# and the bare-repo files are atomic per-ref + per-object (a packfile
# in flight wouldn't be referenced by any ref yet, so missing it from
# the backup is fine — git GC would clean it up after a hypothetical
# restore-then-continue anyway).
#
# Restore via scripts/restore.sh. End-to-end round-trip is exercised
# by tests/backup_restore_roundtrip.rs.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <data-dir> <backup-dir>" >&2
    exit 64
fi

DATA_DIR="$1"
BACKUP_DIR="$2"

if [[ ! -d "$DATA_DIR" ]]; then
    echo "data-dir does not exist: $DATA_DIR" >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR"

# SQLite .backup uses the online-backup API: source connection stays
# usable for both reads and writes throughout, and the snapshot is
# transactionally consistent even if writers commit while it runs.
for db in tokens.db audit.db webhooks.db; do
    src="$DATA_DIR/$db"
    if [[ -f "$src" ]]; then
        # Quoting matters — the .backup arg must be a single SQL
        # string. Inner single-quotes survive the shell, outer
        # double-quotes interpolate $BACKUP_DIR.
        sqlite3 "$src" ".backup '$BACKUP_DIR/$db'"
        echo "  + $db"
    fi
done

# Master key, if file-backed (env-pinned deployments don't write this).
if [[ -f "$DATA_DIR/webhook-key.bin" ]]; then
    # Preserve mode (0600) — leaking the master key would un-seal
    # every webhook secret in the backed-up webhooks.db.
    install -m 0600 "$DATA_DIR/webhook-key.bin" "$BACKUP_DIR/webhook-key.bin"
    echo "  + webhook-key.bin"
fi

# Bare repos. tar preserves perms + dir structure + symlinks. We tar
# rather than rsync the live tree so a partial in-progress write (a
# pack file being indexed, say) doesn't appear as a half-extracted
# file after restore — tar reads the source atomically per-entry.
if [[ -d "$DATA_DIR/repos" ]]; then
    tar -C "$DATA_DIR" -cf "$BACKUP_DIR/repos.tar" repos
    echo "  + repos.tar ($(tar -tf "$BACKUP_DIR/repos.tar" | wc -l) entries)"
fi

echo "backup complete: $BACKUP_DIR"
