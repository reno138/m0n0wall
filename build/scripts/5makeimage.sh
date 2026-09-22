#!/bin/sh
#
# Stage 5 -- build the installable images.
#
# Rewritten for FreeBSD 15.x. The original targeted FreeBSD 8.4 and produced
# BIOS-only, MBR-less images that will not boot on anything UEFI, which today
# means most hardware. What changed and why:
#
#   BOOT.  The old firmware.img had no partition table at all: bsdlabel wrote
#   a BSD disklabel straight onto the raw disk ("dangerously dedicated") and
#   /boot/boot provided BIOS bootstrap. That cannot express an EFI System
#   Partition, so UEFI machines see an unbootable disk. The image is now GPT
#   with three partitions -- an ESP for UEFI, a freebsd-boot partition for
#   legacy BIOS, and the UFS root -- so ONE image boots both ways.
#
#   TOOLING.  disklabel(8) is gone and bsdlabel(8) is deprecated. mkisofs came
#   from cdrtools, which has been removed from ports. Both are replaced by
#   base-system tools: makefs(8) builds filesystems from a directory tree and
#   mkimg(1) assembles the partition table.
#
#   NO ROOT REQUIRED.  The old script needed mdconfig(8) and mount(8), so the
#   build had to run as root and left mounted images behind when it failed
#   mid-way. makefs and mkimg work entirely on files, so stage 5 is now an
#   unprivileged, side-effect-free step.
#
#   UFS2.  The old image used "newfs -O 1" (UFS1). UFS2 is the default and has
#   been the sensible choice for twenty years.
#
# The hybrid-ISO recipe follows FreeBSD's own release/amd64/mkisoimages.sh.

set -e

if [ -z "$MW_BUILDPATH" ] || [ ! -d "$MW_BUILDPATH" ]; then
	echo "\$MW_BUILDPATH is not set"
	exit 1
fi
: "${MW_ARCH:=amd64}"
: "${MW_SRC:=/usr/src}"

VERSION=$(cat "$MW_BUILDPATH/m0n0fs/etc/version")
if [ "$MW_ARCH" = "amd64" ]; then
	VERSION="$VERSION.$MW_ARCH"
fi

TMP="$MW_BUILDPATH/tmp"
IMAGES="$MW_BUILDPATH/images"
SRCROOT="$MW_BUILDPATH/freebsd15"
mkdir -p "$IMAGES"

# ---------------------------------------------------------------------------
# mfsroot: the RAM-disk root, unchanged in concept.
#
# This is still the heart of m0n0wall -- a compressed filesystem image the
# loader unpacks into memory, which is what lets the installed root stay
# read-only. Only the construction changed: makefs instead of
# mdconfig + disklabel + newfs + mount.
# ---------------------------------------------------------------------------
makemfsroot() {
	platform=$1
	spare=$2

	printf 'Making mfsroot for %s...' "$platform"
	echo "$platform" > "$MW_BUILDPATH/m0n0fs/etc/platform"

	# -b/-f are free blocks and free inodes, as PERCENTAGES. Two traps, both
	# of which present identically as
	#   "makefs: Writing inode N (...): No space left on device"
	# naming whichever file happened to be next -- so it reads like
	# corruption rather than a sizing problem.
	#
	# 1. An absolute suffix ("4096k") is not interpreted the way you would
	#    expect and silently under-sizes the filesystem.
	# 2. 10% is not enough margin. With optimization=space, 1K fragments and
	#    several hundred small files, real overhead exceeds makefs's own
	#    estimate. 25% builds reliably; 10% started failing once the tree
	#    passed ~65 MB, which made it look intermittent.
	rm -f "$TMP/mfsroot-$platform" "$TMP/mfsroot-$platform.gz"
	makefs -t ffs \
	    -o version=2,bsize=8192,fsize=1024,optimization=space \
	    -b 25% -f 25% \
	    "$TMP/mfsroot-$platform" "$MW_BUILDPATH/m0n0fs" > /dev/null

	gzip -9f "$TMP/mfsroot-$platform"
	echo ' done'
}

# ---------------------------------------------------------------------------
# The EFI System Partition.
#
# A small FAT image holding the UEFI bootloader at the removable-media path
# the firmware looks for without any NVRAM entry: /EFI/BOOT/BOOTX64.EFI.
# ---------------------------------------------------------------------------
makeesp() {
	out=$1
	espdir="$TMP/espstage"

	rm -rf "$espdir"
	mkdir -p "$espdir/EFI/BOOT"
	cp "$MW_SRC/../boot/loader.efi" "$espdir/EFI/BOOT/BOOTX64.EFI" 2>/dev/null \
	    || cp /boot/loader.efi "$espdir/EFI/BOOT/BOOTX64.EFI"

	# 2 MB, matching what FreeBSD's own release build uses. FAT12 below 4 MB
	# is what firmware expects on a partition this size.
	makefs -t msdos \
	    -o fat_type=12,sectors_per_cluster=1,volume_label=EFISYS \
	    -s 2m "$out" "$espdir" > /dev/null
	rm -rf "$espdir"
}

# ---------------------------------------------------------------------------
# The installable disk image.
#
# GPT, three partitions:
#   p1  efi           -- UEFI boots BOOTX64.EFI from here
#   p2  freebsd-boot  -- gptboot, for legacy BIOS; pmbr in the protective MBR
#                        chains to it
#   p3  freebsd-ufs   -- kernel.gz, mfsroot.gz, loader and the config
#
# One image, both firmware types. This is what the installer dd's onto the
# target disk, so the installed system inherits the same dual bootability.
# ---------------------------------------------------------------------------
makeimage() {
	platform=$1
	spare=$2

	printf 'Making image for %s...' "$platform"

	root="$TMP/rootstage"
	rm -rf "$root"
	mkdir -p "$root/boot/kernel" "$root/conf"

	cp "$TMP/kernel.gz"                      "$root/"
	cp "$TMP/mfsroot-$platform.gz"           "$root/mfsroot.gz"
	cp /boot/loader                          "$root/boot/"
	cp /boot/loader.efi                      "$root/boot/" 2>/dev/null || true
	cp "$SRCROOT/build/boot/$platform/loader.rc" "$root/boot/"
	if [ -r "$SRCROOT/build/boot/$platform/boot.config" ]; then
		cp "$SRCROOT/build/boot/$platform/boot.config" "$root/"
	fi
	cp "$MW_BUILDPATH/m0n0fs/conf.default/config.xml" "$root/conf/"

	rm -f "$TMP/root-$platform.ufs"
	makefs -t ffs \
	    -o version=2,bsize=8192,fsize=1024,optimization=space,label=m0n0wall \
	    -b 25% -f 25% \
	    "$TMP/root-$platform.ufs" "$root" > /dev/null
	rm -rf "$root"

	rm -f "$TMP/esp-$platform.img"
	makeesp "$TMP/esp-$platform.img"

	# -b pmbr: protective MBR carrying the BIOS bootstrap that chains to the
	# freebsd-boot partition. Without it a GPT disk is UEFI-only.
	rm -f "$TMP/image-$platform.bin" "$TMP/image-$platform.bin.gz"
	mkimg -s gpt \
	    -b /boot/pmbr \
	    -p efi:="$TMP/esp-$platform.img" \
	    -p freebsd-boot:=/boot/gptboot \
	    -p freebsd-ufs:="$TMP/root-$platform.ufs" \
	    -o "$TMP/image-$platform.bin"

	rm -f "$TMP/esp-$platform.img" "$TMP/root-$platform.ufs"
	gzip -9f "$TMP/image-$platform.bin"
	mv "$TMP/image-$platform.bin.gz" "$IMAGES/$platform-$VERSION.img"

	echo ' done'
}

# ---------------------------------------------------------------------------
# The ISO: live system plus installer, bootable on BIOS and UEFI.
#
# Two El Torito entries in one image -- cdboot for BIOS, an ESP image flagged
# platformid=efi for UEFI. firmware.img rides along so that console menu
# option 7 ("Install on Hard Drive") has something to write to the disk.
# ---------------------------------------------------------------------------
makeiso() {
	printf 'Making ISO...'

	cdroot="$TMP/cdroot"
	rm -rf "$cdroot"
	mkdir -p "$cdroot/boot/kernel"

	cp /boot/cdboot                     "$cdroot/boot/"
	cp /boot/loader                     "$cdroot/boot/"
	cp "$SRCROOT/build/boot/generic-pc/loader.rc" "$cdroot/boot/"
	cp "$TMP/kernel.gz"                 "$cdroot/"
	cp "$TMP/mfsroot-generic-pc-cdrom.gz" "$cdroot/mfsroot.gz"
	cp "$IMAGES/generic-pc-$VERSION.img"  "$cdroot/firmware.img"

	rm -f "$TMP/efiboot.img"
	makeesp "$TMP/efiboot.img"

	rm -f "$TMP/m0n0wall.iso"
	makefs -t cd9660 \
	    -o rockridge \
	    -o label="m0n0wall_cd" \
	    -o publisher="m0n0.ch" \
	    -o bootimage="i386;$cdroot/boot/cdboot" -o no-emul-boot \
	    -o bootimage="i386;$TMP/efiboot.img" -o no-emul-boot -o platformid=efi \
	    "$TMP/m0n0wall.iso" "$cdroot"

	rm -f "$TMP/efiboot.img"
	rm -rf "$cdroot"
	mv "$TMP/m0n0wall.iso" "$IMAGES/generic-pc-$VERSION.iso"

	echo ' done'
}

# --- mfsroots, 4 MB spare ---
makemfsroot generic-pc-cdrom  4096
makemfsroot generic-pc        4096
makemfsroot generic-pc-serial 4096

# --- disk images, 2 MB spare ---
makeimage generic-pc        2048
makeimage generic-pc-serial 2048

# --- the installable ISO ---
makeiso

echo "Finished Stage 5"
echo
echo "Images in $IMAGES:"
ls -la "$IMAGES"
