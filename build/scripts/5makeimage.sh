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

# ---------------------------------------------------------------------------
# Append a firmware signature, in the layout verifysig(1) expects:
#
#   | gzip image | signature | siglen (2 bytes LE) | magic 0xe14d77cb (4 LE) |
#
# RSA over a SHA-1 digest, because that is what verifysig verifies
# (EVP_VerifyInit with EVP_sha1). gzip ignores the trailing bytes, which is
# what lets the same file be both the upgrade artifact and the firmware.img on
# the CD.
#
# perl does the two integers: printf in sh cannot emit a NUL byte, and a
# 256-byte signature length is 0x0100 -- low byte zero.
# ---------------------------------------------------------------------------
sign_image() {
	_img="$1"
	_key="$MW_BUILDPATH/keys/private.pem"
	[ -f "$_key" ] || { echo "ERROR: no signing key at $_key (run stage 1)"; exit 1; }

	openssl dgst -sha1 -sign "$_key" -out "$TMP/sig.bin" "$_img" || {
		echo "ERROR: signing $_img failed"; exit 1; }
	_len=$(stat -f %z "$TMP/sig.bin")
	cat "$TMP/sig.bin" >> "$_img"
	perl -e 'print pack("v", $ARGV[0]), pack("V", 0xe14d77cb)' "$_len" >> "$_img"
	rm -f "$TMP/sig.bin"

	# Verify with the very binary the firewall will use, against the very key
	# the image carries -- a signature this build cannot check is worse than
	# no signature, because the failure would only appear on someone's upgrade.
	_fs="$MW_BUILDPATH/m0n0fs"
	cp "$_img" "$_fs/tmp/verify.img"
	if chroot "$_fs" /usr/local/bin/verifysig /etc/pubkey.pem /tmp/verify.img; then
		echo "  signed and verified: $(basename "$_img") (${_len}-byte signature)"
	else
		rm -f "$_fs/tmp/verify.img"
		echo "ERROR: $_img does not verify against the public key in the image"
		exit 1
	fi
	rm -f "$_fs/tmp/verify.img"
}

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
# WHICH LOADER.
#
# FreeBSD's /boot/loader and /boot/loader.efi are the LUA loader (confirmed by
# inode: they are hardlinks to loader_lua). It reads /boot/lua/loader.lua and
# ignores loader.rc, so booting m0n0wall with it stops at
#
#     ERROR: cannot open /boot/lua/loader.lua: no such file or directory
#
# m0n0wall's loader.rc is Forth -- "load /kernel", "load -t mfs_root /mfsroot",
# "boot -h" -- so the image ships loader_4th and loader_4th.efi instead. Both
# are in FreeBSD 15 base. The alternative would be rewriting the boot
# configuration as loader.conf and shipping the whole /boot/lua tree, which is
# more moving parts for no gain: the Forth loader does exactly what is needed
# and is still supported.

makeesp() {
	out=$1
	espdir="$TMP/espstage"

	rm -rf "$espdir"
	mkdir -p "$espdir/EFI/BOOT"
	cp /boot/loader_4th.efi "$espdir/EFI/BOOT/BOOTX64.EFI"

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
	cp /boot/loader_4th                      "$root/boot/loader"
	cp /boot/loader_4th.efi                  "$root/boot/loader.efi" 2>/dev/null || true
	cp "$SRCROOT/build/boot/$platform/loader.rc" "$root/boot/"
	# loader.efi refuses a device without one of a few marker files -- see
	# build/boot/defaults/loader.conf for why this must exist.
	mkdir -p "$root/boot/defaults"
	cp "$SRCROOT/build/boot/defaults/loader.conf" "$root/boot/defaults/"
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
	sign_image "$IMAGES/$platform-$VERSION.img"

	echo ' done'
}

# ---------------------------------------------------------------------------
# The ISO: live system plus installer, bootable on BIOS and UEFI.
#
# Two El Torito entries in one image -- cdboot for BIOS, an ESP image flagged
# platformid=efi for UEFI. firmware.img rides along so that console menu
# option 7 ("Install on Hard Drive") has something to write to the disk.
# ---------------------------------------------------------------------------
# $1 is the platform whose mfsroot and loader.rc go on the CD:
#   generic-pc-cdrom         console on VGA (the normal image)
#   generic-pc-serial-cdrom  console on COM1 at 115200
#
# A serial install image is the normal thing to want for a headless appliance,
# and it is what lets a boot be read over a VM's serial port rather than a
# framebuffer -- which matters when the thing being tested has no keyboard.
makeiso() {
	platform=${1:-generic-pc-cdrom}
	suffix=""
	[ "$platform" = "generic-pc-serial-cdrom" ] && suffix="-serial"

	printf 'Making ISO (%s)...' "$platform"

	cdroot="$TMP/cdroot"
	rm -rf "$cdroot"
	mkdir -p "$cdroot/boot/kernel"

	cp /boot/cdboot                     "$cdroot/boot/"
	cp /boot/loader_4th                 "$cdroot/boot/loader"
	cp "$SRCROOT/build/boot/$platform/loader.rc" "$cdroot/boot/"
	mkdir -p "$cdroot/boot/defaults"
	cp "$SRCROOT/build/boot/defaults/loader.conf" "$cdroot/boot/defaults/"
	cp "$TMP/kernel.gz"                 "$cdroot/"
	cp "$TMP/mfsroot-$platform.gz" "$cdroot/mfsroot.gz"
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
	mv "$TMP/m0n0wall.iso" "$IMAGES/generic-pc${suffix}-$VERSION.iso"

	echo ' done'
}

# --- mfsroots, 4 MB spare ---
makemfsroot generic-pc-cdrom  4096
makemfsroot generic-pc        4096
makemfsroot generic-pc-serial 4096
makemfsroot generic-pc-serial-cdrom 4096

# --- disk images, 2 MB spare ---
makeimage generic-pc        2048
makeimage generic-pc-serial 2048

# --- the installable ISOs: VGA and serial console ---
makeiso generic-pc-cdrom
makeiso generic-pc-serial-cdrom

echo "Finished Stage 5"
echo
echo "Images in $IMAGES:"
ls -la "$IMAGES"
