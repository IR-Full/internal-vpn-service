#!/bin/sh
set -eu
umask 077
: "${RESTIC_REPOSITORY:?Repository is required}"
: "${RESTIC_PASSWORD_FILE:?Password file is required}"
restic backup --tag vpn-config /etc/vpn-service /etc/wireguard /var/lib/vpn-service --exclude /var/lib/vpn-service/metrics --exclude /var/lib/vpn-service/ssh-rollback
restic forget --tag vpn-config --group-by host,tags --keep-daily 7 --keep-weekly 4 --keep-monthly 3 --prune
restic check
date +%s > /var/lib/vpn-service/backup-success
