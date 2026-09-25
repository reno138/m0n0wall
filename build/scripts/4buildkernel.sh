#!/bin/sh
#
# Stage 4 -- build the kernel.
#
# Rewritten for FreeBSD 15.x. The old stage applied EIGHTEEN patches to the
# kernel source before building. Every one of them is now either upstream or
# irrelevant, so it applies none:
#
#   ipfilter_kernel_update_to_4.1.34, ip_ftp_pxy.c, ip_nat.c, fil.c,
#   ip_state.c, mlfk_ipl.c, ip_fil_freebsd.c, dummynet_with_ipnat
#                       -- all ipfilter. pf replaces it; ipfilter is not built.
#   stf_6rd_20100923-1  -- 6rd support, upstream since FreeBSD 9.
#   r222728_defroute    -- IPv6 default-route bug, fixed upstream.
#   ip6_input.c         -- part of the same 6rd/defroute work.
#   pfil.c              -- pfil hook ordering, superseded by pfilctl(8).
#   g_part_bsd.c        -- BSD disklabel handling; the image is GPT now.
#   vm_machdep.c, if_em.c, if_fxp.c, Makefile, options
#                       -- FreeBSD 8-era fixes, all long since upstream.
#   ipsec-tools.kern146190 -- for racoon, which strongSwan replaces.
#
# Not applying them is the point: the old stage could not survive a FreeBSD
# upgrade, because every patch had to be rebased against new source. This one
# builds stock source with a custom config, which is the supported path.

set -e

if [ -z "$MW_BUILDPATH" ] || [ ! -d "$MW_BUILDPATH" ]; then
	echo "\$MW_BUILDPATH is not set"; exit 1
fi
: "${MW_ARCH:=amd64}"
: "${MW_SRC:=/usr/src}"
: "${MW_JOBS:=$(sysctl -n hw.ncpu 2>/dev/null || echo 2)}"

SRC="$MW_BUILDPATH/freebsd15"
FS="$MW_BUILDPATH/m0n0fs"
CONFDIR="$MW_SRC/sys/$MW_ARCH/conf"
KERNCONF=M0N0WALL_GENERIC

[ -d "$CONFDIR" ] || { echo "$CONFDIR missing -- is /usr/src installed?"; exit 1; }

echo "Installing the kernel configuration..."
cp "$SRC/build/kernelconfigs/${KERNCONF}.${MW_ARCH}" "$CONFDIR/$KERNCONF"
[ -f "$SRC/build/kernelconfigs/${KERNCONF}.hints" ] && \
	cp "$SRC/build/kernelconfigs/${KERNCONF}.hints" "$CONFDIR/"

echo "Running config(8)..."
cd "$CONFDIR"
config "$KERNCONF"

echo "Compiling (-j$MW_JOBS) -- this is the slow stage..."
cd "$MW_SRC/sys/$MW_ARCH/compile/$KERNCONF"
make cleandepend > /dev/null 2>&1 || true
make depend > /dev/null
make -j"$MW_JOBS" > /dev/null

echo "Stripping and compressing..."
strip kernel
strip --remove-section=.note --remove-section=.comment kernel 2>/dev/null || true
rm -f "$MW_BUILDPATH/tmp/kernel" "$MW_BUILDPATH/tmp/kernel.gz"
mkdir -p "$MW_BUILDPATH/tmp"
cp kernel "$MW_BUILDPATH/tmp/kernel"
gzip -9f "$MW_BUILDPATH/tmp/kernel"

echo "Installing modules into the image..."
mkdir -p "$FS/boot/kernel"
MODDIR="$MW_SRC/sys/$MW_ARCH/compile/$KERNCONF/modules$MW_SRC/sys/modules"

# The list comes from MODULES_OVERRIDE in the kernel config, not from a second
# copy of it here.
#
# There used to be a hardcoded "for m in dummynet ipfw if_vlan aesni padlock
# glxsb", and it silently disagreed with the config the moment anything was
# added: coretemp and amdtemp were added to MODULES_OVERRIDE for the System
# status page's temperature readings, built correctly, and were then simply not
# installed -- so the sensors feature could not work and the build said nothing.
# Two lists that must agree is one list too many.
MODULES=$(sed -n 's/^makeoptions[[:space:]]*MODULES_OVERRIDE="\([^"]*\)".*/\1/p' \
          "$SRC/build/kernelconfigs/${KERNCONF}.${MW_ARCH}")
[ -n "$MODULES" ] || { echo "ERROR: no MODULES_OVERRIDE in the kernel config -- refusing to guess"; exit 1; }
echo "  from MODULES_OVERRIDE: $MODULES"

for m in $MODULES; do
	[ -d "$MODDIR/$m" ] || { echo "ERROR: module '$m' is in MODULES_OVERRIDE but was not built"; exit 1; }
	find "$MODDIR/$m" -name '*.ko' 2>/dev/null | while read -r ko; do
		strip "$ko" 2>/dev/null || true
		cp "$ko" "$FS/boot/kernel/"
	done
done
echo "  $(ls "$FS/boot/kernel"/*.ko 2>/dev/null | wc -l | tr -d ' ') modules"

echo "  kernel: $(ls -la "$MW_BUILDPATH/tmp/kernel.gz" | awk '{printf "%.1f MB compressed", $5/1048576}')"
echo "Finished Stage 4"
