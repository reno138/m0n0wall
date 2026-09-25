#!/bin/sh
#
# Periodic SNTP time synchronisation.
#
#   $1  pidfile for this script
#   $2  unused, kept so the argument positions do not shift (see below)
#   $3  update interval in MINUTES -- the webGUI validates 6..1440
#   $4  space-separated list of time servers
#
# The old invocation was:
#
#     /usr/sbin/sntp -r -P no -l $2 -x $3 $4
#
# Those are msntp flags, from the sntp that shipped with FreeBSD 8 and earlier.
# FreeBSD 15 carries the ntp-4.2.8 rewrite, which has no -P and no -x at all, and
# where -r means "use the reserved port" and -l is a LOGFILE rather than a lock
# file. AutoOpts treats an unknown option as a fatal usage error, so sntp exited
# immediately every time -- and because the loop below slept only one second, the
# result was a permanent once-a-second respawn that never set the clock and never
# stopped trying. Both halves are fixed here: the flags sntp actually has, and a
# sleep of the interval the admin configured.
#
#   -S   step the clock with settimeofday(2). Without it sntp only reports the
#        offset; this is a time CLIENT, so it has to be allowed to set the time.
#   -t   give up on a server after this many seconds rather than hanging.
#   -K   kiss-o'-death history file. /dev/null because there is nowhere sensible
#        to keep it on a ramdisk root, and without it sntp complains on every run
#        that it cannot open /var/db/ntp-kod.
#
# $2 is no longer used because sntp is a one-shot here and writes no pidfile of
# its own; the argument is retained so system_ntp_configure() does not have to
# change position, and so an older config's call still lines up.

echo $$ > "$1"

INTERVAL_MIN="$3"
SERVERS="$4"

case "$INTERVAL_MIN" in
	''|*[!0-9]*) INTERVAL_MIN=300 ;;
esac
[ "$INTERVAL_MIN" -lt 6 ] && INTERVAL_MIN=6
INTERVAL_SEC=$(( INTERVAL_MIN * 60 ))

# At boot the WAN usually has no address yet, so retry briskly until the clock is
# set once, then settle into the configured interval. Without this the first
# sync could be hours late on a DHCP WAN -- and the clock being wrong at boot is
# exactly what stops a self-signed certificate from being generated.
FIRST=1
while true; do
	if /usr/sbin/sntp -S -t 10 -K /dev/null $SERVERS > /dev/null 2>&1; then
		FIRST=0
	fi
	if [ "$FIRST" = "1" ]; then
		sleep 30
	else
		sleep "$INTERVAL_SEC"
	fi
done
