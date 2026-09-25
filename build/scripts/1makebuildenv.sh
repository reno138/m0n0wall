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
#   usr/local/bin/nsupdate  -> supplied by stage 2 from bind-tools, not base
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
# MW_REV first: the build host usually holds a plain copy of the tree, not a
# git clone, so the git branch below never fires there and the version fell
# back to the DATE. That silently renames every artifact at midnight -- a
# deploy script pinned to yesterday's filename keeps shipping yesterday's
# image, which cost a full verification cycle. Pass MW_REV=$(git rev-parse
# --short HEAD) from wherever the tree is synced.
REV="${MW_REV:-}"
if [ -z "$REV" ] && command -v git >/dev/null 2>&1 && [ -d "$SRC/.git" ]; then
	REV=$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || true)
fi
[ -n "$REV" ] || REV=$(date +%Y%m%d)
VERSION=$(echo "$VERSION" | sed "s/%/$REV/g")
echo "$VERSION" > etc/version
echo "  version: $VERSION"

# ---------------------------------------------------------------------------
# Firmware signing key.
#
# The image carries the PUBLIC key and will only accept an upgrade signed by
# the matching private one, so this keypair is the trust root of every image
# this tree builds. It lives in $MW_BUILDPATH, deliberately NOT in the
# repository: a signing key in version control is not a signing key.
#
# Generated on first use. Whoever builds their own ISO therefore gets their
# own trust root and can only upgrade with images they built themselves, which
# is the property wanted -- and is why the key m0n0wall used to ship was
# useless to anyone but its author. That was a 1024-bit key whose private half
# nobody here has; this is 2048.
#
# Keep $MW_BUILDPATH/keys. Losing private.pem means no future build can produce
# an upgrade for an already-installed system.
# ---------------------------------------------------------------------------
KEYDIR="$MW_BUILDPATH/keys"
mkdir -p "$KEYDIR"
chmod 0700 "$KEYDIR"
if [ ! -f "$KEYDIR/private.pem" ]; then
	echo "Generating a firmware signing key (first build)..."
	openssl genrsa -out "$KEYDIR/private.pem" 2048 2>/dev/null || {
		echo "ERROR: could not generate a signing key with openssl"; exit 1; }
	chmod 0600 "$KEYDIR/private.pem"
	rm -f "$KEYDIR/public.pem"
fi
if [ ! -f "$KEYDIR/public.pem" ]; then
	openssl rsa -in "$KEYDIR/private.pem" -pubout -out "$KEYDIR/public.pem" 2>/dev/null || {
		echo "ERROR: could not derive the public key"; exit 1; }
fi
cp "$KEYDIR/public.pem" etc/pubkey.pem
echo "  signing key: $KEYDIR/private.pem ($(openssl rsa -in "$KEYDIR/private.pem" -noout -text 2>/dev/null | sed -n 's/.*Private-Key: (\([0-9]*\) bit.*/\1/p') bit)"

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
# Also after the tarball: adds the address-change guard to the hook.
[ -f "$SRC/build/files/dhclient-exit-hooks" ] && { cp "$SRC/build/files/dhclient-exit-hooks" etc/; chmod 0755 etc/dhclient-exit-hooks; }
# Accounts. Also after the tarball, for the same reason, and then pwd_mkdb to
# regenerate passwd/pwd.db/spwd.db -- a master.passwd the databases do not
# match is worse than the old one, because getpwnam() reads the databases.
if [ -f "$SRC/build/files/master.passwd" ]; then
	cp "$SRC/build/files/master.passwd" etc/master.passwd
	[ -f "$SRC/build/files/group" ] && cp "$SRC/build/files/group" etc/group
	chmod 0600 etc/master.passwd
	pwd_mkdb -p -d "$FS/etc" "$FS/etc/master.passwd" || {
		echo "ERROR: pwd_mkdb failed -- pflogd and dhclient would not resolve their users"; exit 1; }
	echo "  accounts: $(grep -c . etc/master.passwd) entries, databases rebuilt"
fi
# pflogd chroots here, so it must exist and be empty.
mkdir -p var/empty && chmod 0555 var/empty

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
