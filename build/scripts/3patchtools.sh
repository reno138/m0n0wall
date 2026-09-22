#!/bin/sh
#
# Stage 3 -- locally patched base-system tools.
#
# This stage used to build four binaries from patched FreeBSD sources. All
# four patches are now either upstream or unnecessary, so it builds nothing.
# Kept as a stage so the pipeline's shape is unchanged and so this record of
# what happened to each patch has somewhere to live.
#
#   ifconfig  -- patched for r222728, an IPv6 default-route bug in FreeBSD 8.
#                Fixed upstream long ago. The base binary is used, and had to
#                be ADDED to minibsd/m0n0wall.files: because stage 3 used to
#                install it by hand, the manifest never listed it, so dropping
#                this stage without noticing would produce an image with no
#                ifconfig at all -- which interfaces.inc calls 59 times.
#
#   rtadvd    -- patched only to quieten DHCP-PD logging. Cosmetic; dropped.
#
#   syslogd   -- patched to add ring-buffer ("circular") log support, paired
#                with clog(8) from a bundled tarball. That patch had to be
#                forward-ported to every FreeBSD release, and clog is not in
#                base. Replaced by ordinary log files bounded by newsyslog(8),
#                which is in base and does the same job. The webGUI now reads
#                logs with tail(1); 9 call sites were updated.
#
#   dhclient-script -- m0n0wall's own script, not a patch. Still copied.
#
# The one thing lost is that a ring buffer never rotates: it overwrites its
# oldest entries in place, so a log file has exactly one name. newsyslog
# rotates to .0, .1 and so on. For "show me the last N lines", which is all
# the GUI ever did, the two are equivalent.

set -e

if [ -z "$MW_BUILDPATH" ] || [ ! -d "$MW_BUILDPATH" ]; then
	echo "\$MW_BUILDPATH is not set"; exit 1
fi
SRC="$MW_BUILDPATH/freebsd15"
FS="$MW_BUILDPATH/m0n0fs"

echo "Installing m0n0wall's own helper scripts..."
if [ -f "$SRC/build/tools/dhclient-script" ]; then
	cp "$SRC/build/tools/dhclient-script" "$FS/sbin/"
	chmod a+rx "$FS/sbin/dhclient-script"
	echo "  sbin/dhclient-script"
fi

# Strip anything stages 1 and 2 left unstripped. Harmless errors are expected
# on scripts and data files.
echo "Stripping..."
find "$FS" -type f 2>/dev/null | xargs strip -s 2>/dev/null || true

echo "Finished Stage 3"
