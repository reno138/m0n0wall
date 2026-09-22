#!/bin/sh
#
# Build everything.
#
# Usage:
#   env MW_BUILDPATH=/path/to/buildroot sh doall.sh
#
# See BUILDING.md for how to prepare a build host. This script checks its
# prerequisites before doing anything, because every one of them has bitten
# during development and each produces a failure that names something other
# than the real cause.

set -e

fail() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "  $*"; }

echo "=== Checking prerequisites ==="

# --- the build host itself ------------------------------------------------
[ "$(uname -s)" = "FreeBSD" ] || fail "this must be built on FreeBSD (found $(uname -s)).
       buildworld, makefs and mkimg are FreeBSD tools; there is no cross path."

OSREL=$(freebsd-version -u 2>/dev/null | cut -d- -f1)
OSMAJ=${OSREL%%.*}
[ "${OSMAJ:-0}" -ge 15 ] || fail "FreeBSD 15.0 or later required (found ${OSREL:-unknown}).
       Earlier releases lack tooling and drivers this build assumes."
note "FreeBSD $OSREL on $(uname -m)"

: "${MW_ARCH:=$(uname -m)}"
[ "$MW_ARCH" = "amd64" ] || fail "only amd64 is supported (MW_ARCH=$MW_ARCH).
       i386 was dropped: FreeBSD is retiring it and the 8.4-era config is gone."

# --- the build root -------------------------------------------------------
[ -n "$MW_BUILDPATH" ] || fail "\$MW_BUILDPATH is not set.
       Point it at a working directory, e.g. env MW_BUILDPATH=\$HOME/mw-build"
[ -d "$MW_BUILDPATH" ] || fail "\$MW_BUILDPATH ($MW_BUILDPATH) does not exist"

SRC="$MW_BUILDPATH/freebsd15"
[ -e "$SRC" ] || fail "$SRC does not exist.
       Symlink it at the source tree:  ln -s /path/to/checkout $SRC"
[ -f "$SRC/build/scripts/doall.sh" ] || fail "$SRC does not look like the source tree"
note "source: $(readlink -f "$SRC" 2>/dev/null || echo "$SRC")"
note "output: $MW_BUILDPATH/images"

# --- root -----------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || fail "must run as root.
       Stages 1-3 install into a staging root and chown files;
       stage 5 alone would be fine unprivileged."

# --- the FreeBSD source tree ----------------------------------------------
[ -d /usr/src/sys/amd64/conf ] || fail "/usr/src is missing or incomplete.
       The kernel is built from source. Fetch it with:
         git clone -b releng/${OSMAJ}.$(echo "$OSREL" | cut -d. -f2) \\
             https://git.freebsd.org/src.git /usr/src"
note "/usr/src present"

# --- tools ----------------------------------------------------------------
for t in makefs mkimg pkg perl strip file; do
	command -v "$t" >/dev/null 2>&1 || \
		fail "$t not found. makefs/mkimg/strip/file are base;
       perl and pkg come from packages (pkg install perl5)."
done
note "makefs, mkimg, pkg, perl present"

# --- boot components stage 5 copies from the HOST -------------------------
# These end up IN the image, so the host's versions are what ship.
for f in /boot/loader.efi /boot/gptboot /boot/pmbr /boot/cdboot /boot/loader; do
	[ -f "$f" ] || fail "$f missing.
       Stage 5 copies the boot chain from the running system into the image."
done
note "boot components present"

# --- network --------------------------------------------------------------
pkg -N >/dev/null 2>&1 || fail "the pkg database is not initialised. Run: pkg bootstrap"

echo
echo "=== Building ==="
cd "$SRC/build/scripts"

for stage in 1makebuildenv 2makebinaries 3patchtools 4buildkernel 5makeimage; do
	[ -f "$stage.sh" ] || continue
	printf '### %-18s ' "$stage"
	if sh "$stage.sh" > "$MW_BUILDPATH/tmp-$stage.log" 2>&1; then
		echo "ok"
	else
		echo "FAILED"
		echo "--- last 20 lines of $MW_BUILDPATH/tmp-$stage.log:"
		tail -20 "$MW_BUILDPATH/tmp-$stage.log"
		exit 1
	fi
done

echo
echo "=== Images ==="
ls -la "$MW_BUILDPATH/images"
