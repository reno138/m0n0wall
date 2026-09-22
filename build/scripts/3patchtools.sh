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

# ---------------------------------------------------------------------------
# m0n0wall's own tools.
#
# These are small C programs and scripts that live in this tree, not packages.
# The old build compiled them in stage 2 alongside the third-party ports; they
# belong here, with the other things that are ours.
#
#   minicron   a tiny periodic runner -- drives the captive portal pruner
#   croen      the scheduler behind the Services > Scheduler pages
#   voucher    captive portal voucher generation and validation
#   dnswatch   re-resolves dynamic IPsec peer names
#   verifysig  checks the firmware signature on upgrade
#   choparp    proxy ARP, for the Services > Proxy ARP pages
#   stats      the throughput figures on the status page
# ---------------------------------------------------------------------------
echo "Building m0n0wall's own tools..."
mkdir -p "$FS/usr/local/bin" "$FS/usr/local/sbin" "$FS/sbin"

build_tool() {
	src="$SRC/build/tools/$1.c"
	dest="$2"
	extra="$3"
	[ -f "$src" ] || { echo "  $1: source missing, skipped"; return 0; }
	if cc -O2 -pipe -o "$FS/$dest/$1" "$src" $extra 2>/tmp/mw-$1.log; then
		strip "$FS/$dest/$1" 2>/dev/null || true
		echo "  $dest/$1"
	else
		echo "  $1: FAILED to build"
		sed 's/^/      /' /tmp/mw-$1.log | head -5
		return 1
	fi
}

build_tool minicron  usr/local/bin
build_tool croen     usr/local/bin
build_tool voucher   usr/local/bin  "-lcrypto"
build_tool dnswatch  usr/local/bin
build_tool verifysig usr/local/bin  "-lcrypto"
build_tool stats     usr/local/bin
build_tool choparp   usr/local/sbin

echo "Installing m0n0wall's own scripts..."
for s in dhclient-script; do
	[ -f "$SRC/build/tools/$s" ] && { cp "$SRC/build/tools/$s" "$FS/sbin/"; chmod a+rx "$FS/sbin/$s"; echo "  sbin/$s"; }
done
for s in ppp-linkup vpn-linkup vpn-linkdown; do
	[ -f "$SRC/build/tools/$s" ] && { cp "$SRC/build/tools/$s" "$FS/usr/local/sbin/"; chmod a+rx "$FS/usr/local/sbin/$s"; echo "  usr/local/sbin/$s"; }
done
for s in runsntp.sh; do
	[ -f "$SRC/build/tools/$s" ] && { cp "$SRC/build/tools/$s" "$FS/usr/local/bin/"; chmod a+rx "$FS/usr/local/bin/$s"; echo "  usr/local/bin/$s"; }
done

# Strip anything stages 1 and 2 left unstripped. Harmless errors are expected
# on scripts and data files.
echo "Stripping..."
find "$FS" -type f 2>/dev/null | xargs strip -s 2>/dev/null || true

echo "Finished Stage 3"
