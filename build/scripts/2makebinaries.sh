#!/bin/sh
#
# Stage 2 -- third-party components.
#
# Rewritten for FreeBSD 15.x.
#
# THE IMPORTANT DESIGN DECISION. Packages are NOT installed into the image.
# They are installed into a throwaway staging root, and only the binaries we
# actually need are copied across, together with their real shared-library
# closure resolved by ldd(1). Everything else -- headers, static libraries,
# documentation, locale data, package metadata, and the dependency packages
# that exist only to build something -- is left behind.
#
# This is not a micro-optimisation. Installing the package set directly into
# the image produced a 1.1 GB root, which is larger than the pfSense and
# OPNsense installers this project exists to be an alternative to, and it
# cannot work at all: m0n0wall's root is a compressed filesystem unpacked into
# RAM at boot, so image size is memory cost.
#
# The mechanism is m0n0wall's own. Stage 1 already trims the FreeBSD base
# system this way with minibsd/mklibs.pl. This applies the same discipline to
# the third-party components.
#
#   was                      now                    why
#   ------------------------ ---------------------- -------------------------
#   php-4.4.9                php84                  EOL 2008
#   ip_fil4.1.34             (none -- pf in base)   upstream dead 2014
#   mini_httpd-1.21 +patch   lighttpd               563-line local patch gone
#   ucd-snmp-4.2.7.1         net-snmp               2002 vintage
#   ez-ipupdate-3.0.11b8     inadyn                 dead 2002
#   isc-dhcp41-server        dnsmasq --dhcp         see below
#   racoon / ipsec-tools     strongswan             upstream dead 2014
#   dnsmasq-2.66             dnsmasq                alive; just newer
#
# DHCP: Kea was the obvious successor to ISC DHCP and was the plan, until its
# dependency closure turned out to be boost-libs, icu, python312 and a full
# gcc -- about 400 MB for a DHCP server. dnsmasq is already present for DNS
# forwarding and does DHCP: ranges, static mappings, options, PXE. What Kea
# adds over it is HA failover and client classing, which a single firewall
# appliance does not need. One daemon instead of two.

set -e

if [ -z "$MW_BUILDPATH" ] || [ ! -d "$MW_BUILDPATH" ]; then
	echo "\$MW_BUILDPATH is not set"; exit 1
fi
: "${MW_ARCH:=amd64}"

FS="$MW_BUILDPATH/m0n0fs"
STAGE="$MW_BUILDPATH/tmp/pkgstage"
[ -d "$FS" ] || { echo "$FS does not exist -- run stage 1 first"; exit 1; }

PKGS="php84 php84-filter php84-mbstring php84-session php84-sockets
      php84-xml php84-zlib php84-pcntl php84-posix
      lighttpd dnsmasq mpd5 strongswan net-snmp inadyn
      bind-tools wireguard-tools libqrencode"

# ---------------------------------------------------------------------------
# What actually goes in the image.
#
# Every line is a daemon or tool the firewall invokes. If m0n0wall's PHP does
# not exec it, it does not belong here.
#
# Paths verified against the real package manifests, not assumed. strongswan 6
# puts charon in libexec/ipsec, not sbin, and has no 'ipsec' wrapper any more
# (swanctl replaced it). inadyn is in sbin, not bin.
#
# pkg(8) is included deliberately: the image ships only what the firewall
# needs, but the repositories stay configured so an operator can add what they
# want. See the note at the end of this script about persistence.
# ---------------------------------------------------------------------------
WANT_BIN="
usr/local/bin/php-cgi
usr/local/bin/php
usr/local/sbin/lighttpd
usr/local/sbin/dnsmasq
usr/local/sbin/mpd5
usr/local/libexec/ipsec/charon
usr/local/libexec/ipsec/_updown
usr/local/sbin/swanctl
usr/local/bin/pki
usr/local/sbin/snmpd
usr/local/sbin/snmptrapd
usr/local/sbin/inadyn
usr/local/sbin/pkg
usr/local/sbin/pkg-static
usr/local/bin/wg
usr/local/bin/wg-quick
usr/local/bin/qrencode
usr/local/bin/nsupdate
usr/local/bin/dig
usr/local/bin/host
"

# Loadable modules have no ldd-discoverable referrer, so they are named here
# and their own library closure is resolved too.
WANT_GLOB="
usr/local/lib/php/*/[a-z]*.so
usr/local/lib/lighttpd/mod_*.so
usr/local/lib/ipsec/*.so
usr/local/libexec/ipsec/*
"

echo "Installing the component set into a throwaway staging root..."
rm -rf "$STAGE"
mkdir -p "$STAGE/usr/share/keys/pkg/trusted" "$STAGE/etc/pkg" "$STAGE/etc" \
         "$STAGE/var/run" "$STAGE/tmp"
cp -R /usr/share/keys/pkg/trusted/. "$STAGE/usr/share/keys/pkg/trusted/" 2>/dev/null || true
cp /etc/pkg/*.conf "$STAGE/etc/pkg/" 2>/dev/null || true
# post-install scripts run pw(8) and edit /etc/shells inside the root
for f in passwd master.passwd group shells login.conf; do
	cp "/etc/$f" "$STAGE/etc/$f" 2>/dev/null || true
done
pwd_mkdb -p -d "$STAGE/etc" "$STAGE/etc/master.passwd" 2>/dev/null || true
chmod 1777 "$STAGE/tmp"

# shellcheck disable=SC2086
pkg -r "$STAGE" install -y $PKGS >/dev/null 2>&1 || \
	pkg -r "$STAGE" install -y $PKGS   # rerun visibly if it failed

echo "  staging root: $(du -sh "$STAGE" | cut -f1)"

# ---------------------------------------------------------------------------
# Copy across only what is wanted, plus its library closure.
# ---------------------------------------------------------------------------
copy_one() {
	src="$1"                       # path relative to $STAGE
	[ -e "$STAGE/$src" ] || return 0
	mkdir -p "$FS/$(dirname "$src")"
	cp -p "$STAGE/$src" "$FS/$src"
}

# Resolve the shared libraries a file needs, following into the staging root.
resolve_libs() {
	f="$1"
	ldd "$f" 2>/dev/null | awk '{print $3}' | grep '^/' | while read -r lib; do
		# ldd prints host paths; the same library lives under $STAGE
		rel="${lib#/}"
		if [ -e "$STAGE/$rel" ]; then
			if [ ! -e "$FS/$rel" ]; then
				mkdir -p "$FS/$(dirname "$rel")"
				cp -p "$STAGE/$rel" "$FS/$rel"
				echo "$FS/$rel" >> "$MW_BUILDPATH/tmp/newlibs"
			fi
		fi
	done
}

echo "Copying wanted binaries..."
: > "$MW_BUILDPATH/tmp/newlibs"
for b in $WANT_BIN; do copy_one "$b"; done
for g in $WANT_GLOB; do
	for f in $STAGE/$g; do
		[ -e "$f" ] || continue
		copy_one "${f#$STAGE/}"
	done
done

echo "Resolving shared-library closure..."
# Iterate: libraries pull in further libraries.
pass=0
while [ $pass -lt 12 ]; do
	pass=$((pass+1))
	: > "$MW_BUILDPATH/tmp/newlibs"
	find "$FS/usr/local" -type f \( -perm -u+x -o -name '*.so*' \) 2>/dev/null | \
	while read -r f; do resolve_libs "$f"; done
	[ -s "$MW_BUILDPATH/tmp/newlibs" ] || break
done
echo "  closure settled after $pass pass(es)"

# ---------------------------------------------------------------------------
# Configuration and data files the daemons genuinely read at runtime.
# ---------------------------------------------------------------------------
echo "Copying runtime data..."
for d in usr/local/etc/strongswan.d usr/local/share/strongswan \
         usr/local/etc/rc.d/nothing; do
	[ -d "$STAGE/$d" ] && { mkdir -p "$FS/$d"; cp -Rp "$STAGE/$d/." "$FS/$d/"; }
done
# CA bundle -- inadyn and strongswan validate TLS with it
[ -f "$STAGE/usr/local/etc/ssl/cert.pem" ] && {
	mkdir -p "$FS/usr/local/etc/ssl"
	cp -p "$STAGE/usr/local/etc/ssl/cert.pem" "$FS/usr/local/etc/ssl/"
}

echo "Stripping..."
find "$FS/usr/local" -type f 2>/dev/null | while read -r f; do
	case $(file -b "$f" 2>/dev/null) in
		*ELF*executable*|*ELF*shared\ object*) strip "$f" 2>/dev/null || true ;;
	esac
done

rm -rf "$STAGE" "$MW_BUILDPATH/tmp/newlibs"

echo
echo "In the image:"
for b in $WANT_BIN; do
	[ -e "$FS/$b" ] && printf "  %s\n" "$b"
done | head -20
echo
echo "  libraries: $(find "$FS/usr/local/lib" -name '*.so*' 2>/dev/null | wc -l | tr -d ' ')"
echo "  m0n0fs:    $(du -sh "$FS" | cut -f1)"
echo
echo "NOTE: pkg(8) is present and the repositories are left configured, so"
echo "      'pkg install' works. On the read-only ramdisk root that is a"
echo "      RUNTIME change only -- it does not survive a reboot. Anything"
echo "      meant to persist belongs in the image or on the config partition."
echo "Finished Stage 2"
