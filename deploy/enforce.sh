#!/bin/sh
# Turn aiverify enforcement on or off for aaPanel Apache vhosts.
#   enforce.sh on  <vhost-file-name>   e.g. example.com.conf
#   enforce.sh off <vhost-file-name>|all
#   enforce.sh status
# "on" adds one IncludeOptional line for the generated rules inside every <VirtualHost> of the file; the include
# path itself is the marker (Apache has no end-of-line comments). "off" removes those lines. Every change is
# checked with httpd -t before a graceful reload; a failed check restores the backup and logs the error.
set -eu
VHOST_DIR=${VHOST_DIR:-/www/server/panel/vhost/apache}
HTTPD=${HTTPD:-/www/server/apache/bin/httpd}
CONF=${CONF:-/opt/aiverify/data/enforce.conf}
LOG=${LOG:-/opt/aiverify/data/enforce-events.log}
LINE="IncludeOptional $CONF"

note() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$LOG"; }

apply() {  # $1 = file, $2 = on|off
    f="$VHOST_DIR/$1"
    [ -f "$f" ] || { echo "no such vhost file: $f" >&2; exit 2; }
    cp -p "$f" "$f.aiverify-bak"
    if [ "$2" = on ]; then
        grep -qF "$LINE" "$f" && { note "already on: $1"; return 0; }
        sed -i "s|^\(<VirtualHost[^>]*>\)\$|\1\n    $LINE|" "$f"
    else
        grep -vF "$LINE" "$f.aiverify-bak" > "$f" || true
    fi
}

check_and_reload() {  # $@ = files touched
    if out=$("$HTTPD" -t 2>&1); then
        "$HTTPD" -k graceful
        for f in "$@"; do rm -f "$VHOST_DIR/$f.aiverify-bak"; done
        return 0
    fi
    for f in "$@"; do mv "$VHOST_DIR/$f.aiverify-bak" "$VHOST_DIR/$f"; done
    note "httpd -t failed, restored: $* :: $(echo "$out" | grep -v AH00112 | tail -3 | tr '\n' ' ')"
    exit 1
}

enabled() { grep -lF "$LINE" "$VHOST_DIR"/*.conf 2>/dev/null | xargs -r -n1 basename || true; }

case "${1:-}" in
on)
    [ -s "$CONF" ] || { echo "missing $CONF, run aiverify sync first" >&2; exit 2; }
    apply "$2" on; check_and_reload "$2"; note "on: $2" ;;
off)
    if [ "$2" = all ]; then
        files=$(enabled)
        [ -n "$files" ] || { note "off all: nothing enabled"; exit 0; }
        for f in $files; do apply "$f" off; done
        # shellcheck disable=SC2086
        check_and_reload $files; note "off all: $(echo $files)"
    else
        apply "$2" off; check_and_reload "$2"; note "off: $2"
    fi ;;
status)
    enabled ;;
*)
    echo "usage: enforce.sh on <vhost.conf> | off <vhost.conf>|all | status" >&2; exit 2 ;;
esac
