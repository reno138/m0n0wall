#!/bin/sh
#
# Stage 1 -- build the image root from the FreeBSD base system.
#
# Rewritten for FreeBSD 15.x. The structure is unchanged, because it was
# sound: take a manifest of base-system files, copy them into a staging root,
# then resolve their shared-library closure with ldd. Only the details that
# rotted have been fixed.
#
#   pkg_add -r              -> pkg install        (pkg_add gone since 10.0)
#   cdrtools/mkisofs        -> not needed         (stage 5 uses makefs now)
#   autoconf213/autoconf    -> not needed         (nothing is built from source)
#   $MW_BUILDPATH/freebsd8  -> $MW_BUILDPATH/freebsd15
#   sbin/atacontrol         -> sbin/camcontrol    (ATA driver replaced by CAM)
#   usr/sbin/ancontrol      -> dropped            (Aironet driver removed)
#   usr/bin/nsupdate        -> supplied by stage 2 from bind-tools, not base
#
# The manifest itself held up remarkably well: 65 of its 68 entries still
# exist unchanged on FreeBSD 15.1.

set -e

if [ -z "$MW_BUILDPATH" ] || [ ! -d "$MW_BUILDPATH" ]; then
	echo "\$MW_BUILDPATH is not set"; exit 1
fi
: "${MW_ARCH:=amd64}"

SRC="$MW_BUILDPATH/freebsd15"
FS="$MW_BUILDPATH/m0n0fs"

[ -d "$SRC" ] || { echo "$SRC does not exist (symlink it to the source tree)"; exit 1; }

echo "Creating the image root..."
# Base libraries copied from /lib carry the schg (system immutable) flag, and
# cp -p preserves it. rm -rf cannot remove such a file, so a second build
# died on "Operation not permitted" against the previous root. Clear the
# flags first; stage 2 also strips them at copy time.
[ -d "$FS" ] && chflags -R noschg,nouchg "$FS" 2>/dev/null
rm -rf "$FS"
mkdir -p "$FS"
cd "$FS"

# Directory skeleton. /conf is a symlink to /cf/conf so that the writable
# configuration partition is the only thing the running system can change.
mkdir -p etc/rc.d bin cf conf.default dev etc/mpd-modem ftmp mnt proc root \
         sbin tmp libexec lib var/etc/dnsmasq var/run var/db var/log \
         usr/bin usr/lib usr/libexec usr/local usr/sbin usr/share \
         usr/local/bin usr/local/captiveportal usr/local/lib usr/local/sbin \
         usr/local/www usr/share/misc boot/kernel

echo "Copying m0n0wall's own files..."
cp -R "$SRC"/phpconf/rc.*        etc/
cp -R "$SRC"/phpconf/inc         etc/
cp -R "$SRC"/etc/*               etc/ 2>/dev/null || true
cp -R "$SRC"/webgui/             usr/local/www/
cp -R "$SRC"/captiveportal       usr/local/

chmod -R 0755 usr/local/www/* usr/local/captiveportal/* 2>/dev/null || true
chmod a+rx etc/rc.reboot 2>/dev/null || true

# /conf -> /cf/conf : the config partition. /usr/local/www/.htpasswd is
# generated at runtime by system_password_configure().
ln -sf /cf/conf conf
ln -sf /var/run/htpasswd usr/local/www/.htpasswd

echo "Setting version..."
date > etc/version.buildtime
date +%s > etc/version.buildtime.unix
VERSION=$(cat "$SRC/version" 2>/dev/null || echo "1.9.0-dev%")
# The original substituted an svn revision for the '%' placeholder. Use git.
# If there is no repo -- an exported tarball, say -- substitute the build date
# rather than leaving a bare '%', which used to leak into image FILENAMES as
# "generic-pc-1.8.2b%.amd64.iso".
REV=""
if command -v git >/dev/null 2>&1 && [ -d "$SRC/.git" ]; then
	REV=$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || true)
fi
[ -n "$REV" ] || REV=$(date +%Y%m%d)
VERSION=$(echo "$VERSION" | sed "s/%/$REV/g")
echo "$VERSION" > etc/version
echo "  version: $VERSION"

echo "Installing the default configuration..."
cp "$SRC/phpconf/config.xml" conf.default/config.xml

echo "Copying base-system support files..."
cp /usr/share/misc/termcap usr/share/misc/ 2>/dev/null || true
# pf.os is pf's passive OS fingerprint table. pfctl loads it unconditionally
# when reading a ruleset and refuses the whole ruleset without it, so its
# absence meant the firewall ran with NO rules loaded ("Generated pf ruleset
# is invalid, keeping the previous one: pfctl: /etc/pf.os: No such file").
# Taken from the build host so it tracks the release rather than a copy
# frozen in the repository.
cp /etc/pf.os etc/ || { echo "ERROR: /etc/pf.os missing on the build host"; exit 1; }
# Development builds get a root shell on the console menu (option 8, see
# etc/rc.initial). Off unless the build asks for it; release images never
# carry the marker.
[ -n "$MW_DEVBUILD" ] && { touch etc/devbuild; echo "  development build: console shell enabled"; }
[ -f "$SRC/build/files/zoneinfo.tgz" ] && cp "$SRC/build/files/zoneinfo.tgz" usr/share/
[ -f "$SRC/build/files/login.conf" ]   && cp "$SRC/build/files/login.conf" etc/
# php.ini goes in /usr/local/etc, which is where the php84 PACKAGE looks.
# The old build put it in /usr/local/lib because PHP 4 was compiled from
# source with a default prefix. Wrong place means no configuration at all --
# see the header of build/files/php.ini.
[ -f "$SRC/build/files/php.ini" ]      && { mkdir -p usr/local/etc; cp "$SRC/build/files/php.ini" usr/local/etc/; }
[ -f "$SRC/build/files/etcadditional.tgz" ] && tar -xzf "$SRC/build/files/etcadditional.tgz" -C "$FS/"
[ -f "$SRC/build/files/mpd-modem.script" ]  && cp "$SRC/build/files/mpd-modem.script" etc/mpd-modem/mpd.script
# Log rotation replaces the old circular-log scheme -- see the file's header.
[ -f "$SRC/build/files/newsyslog.conf" ]    && cp "$SRC/build/files/newsyslog.conf" etc/
# After the tarball on purpose: it replaces the clog-era syslog.conf in there.
[ -f "$SRC/build/files/syslog.conf" ]       && cp "$SRC/build/files/syslog.conf" etc/

echo "Populating the base system from the manifest..."
perl "$SRC/build/minibsd/mkmini.pl" "$SRC/build/minibsd/m0n0wall.files" / "$FS/"

echo "Resolving the base-system library closure..."
cd "$MW_BUILDPATH/tmp" 2>/dev/null || { mkdir -p "$MW_BUILDPATH/tmp"; cd "$MW_BUILDPATH/tmp"; }
perl "$SRC/build/minibsd/mklibs.pl" "$FS" > m0n0wall.libs
perl "$SRC/build/minibsd/mkmini.pl" m0n0wall.libs / "$FS"
echo "  $(wc -l < m0n0wall.libs | tr -d ' ') libraries"

echo
echo "  image root: $(du -sh "$FS" | cut -f1)"
echo "Finished Stage 1"
