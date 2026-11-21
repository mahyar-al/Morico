#!/usr/bin/env bash
set -euo pipefail

# Daily off-app backup script for Moricoland (cPanel Cron)
# Recommended Cron schedule: 0 3 * * * /bin/bash /home/USER/morico/scripts/backup-data.sh
# Environment variables (can be exported in cPanel Cron or sourced from .env):
#   DATA_DIR         - Path to persistent JSON data directory (default: ./data)
#   UPLOADS_DIR      - Path to uploaded media directory (default: ./public/uploads)
#   BACKUP_DEST_DIR  - Path to store compressed daily backups (default: $HOME/morico_backups)
#   RETENTION_DAYS   - Days to retain local compressed archives (default: 30)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DATA_DIR="${DATA_DIR:-$APP_ROOT/data}"
UPLOADS_DIR="${UPLOADS_DIR:-$APP_ROOT/public/uploads}"
BACKUP_DEST_DIR="${BACKUP_DEST_DIR:-$HOME/morico_backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
STAMP="$(date +%Y-%m-%d_%H-%M-%S)"
ARCHIVE_PATH="$BACKUP_DEST_DIR/morico_backup_${STAMP}.tar.gz"

mkdir -p "$BACKUP_DEST_DIR"

ITEMS=()
if [ -d "$DATA_DIR" ]; then
  ITEMS+=("$DATA_DIR")
fi
if [ -d "$UPLOADS_DIR" ]; then
  ITEMS+=("$UPLOADS_DIR")
fi

if [ "${#ITEMS[@]}" -eq 0 ]; then
  echo "[MORICO Backup] No data or uploads directories found to back up." >&2
  exit 1
fi

tar -czf "$ARCHIVE_PATH" "${ITEMS[@]}"
echo "[MORICO Backup] Archive created: $ARCHIVE_PATH"

# Remove archives older than RETENTION_DAYS
find "$BACKUP_DEST_DIR" -name 'morico_backup_*.tar.gz' -type f -mtime +"$RETENTION_DAYS" -delete

# Optional: sync off-server via rclone/scp/rsync, e.g.:
# rclone copy "$ARCHIVE_PATH" remote:morico-offsite-backups/
# scp -P 22 "$ARCHIVE_PATH" backupuser@offsite.example.com:/backups/morico/
