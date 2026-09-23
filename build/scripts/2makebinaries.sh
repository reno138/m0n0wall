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
#   ez-ipupdate-3.0.11b8     (none -- PHP over HTTPS) dead 2002; see dyndns.inc
#   isc-dhcp41-server        dnsmasq --dhcp         see below
#   isc-dhcp41-relay         isc-dhcp44-relay       still maintained
#   dhcp6 (wide-dhcpv6)      dhcp6                  unchanged; DHCPv6 only
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

PKGS="php84 php84-filter php84-session php84-sockets
      php84-xml php84-zlib php84-pcntl php84-posix php84-pecl-radius
      lighttpd dnsmasq mpd5 strongswan net-snmp wol
      dhcp6 isc-dhcp44-relay
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
usr/local/sbin/snmpd
usr/local/sbin/pkg
usr/local/sbin/pkg-static
usr/local/bin/wg
usr/local/bin/wg-quick
usr/local/bin/qrencode
usr/local/bin/wol
usr/local/sbin/dhcp6c
usr/local/sbin/dhcp6s
usr/local/sbin/dhcrelay
usr/local/bin/nsupdate
"
# nsupdate is the one bind-tools binary anything calls (services_dnsupdate_process,
# RFC 2136 dynamic DNS update). It costs about 8 MB uncompressed on its own:
# the four bind libraries, MIT krb5 from base, libuv, urcu, nghttp2, idn2,
# protobuf-c, fstrm, libedit and ncurses. dig and host used to ride along for
# free and were dropped because nothing invokes them. The way to get the 8 MB
# back is an RFC 2136 UPDATE in PHP over the sockets extension -- the same
# reasoning that replaced ez-ipupdate with dyndns.inc.

# Loadable modules have no ldd-discoverable referrer, so they are named here
# and their own library closure is resolved too.
# lighttpd modules are listed individually, not globbed: mod_magnet alone
# pulls in Lua, and webgui_lighttpd.inc / captiveportal_lighttpd.inc name
# exactly these six.
WANT_GLOB="
usr/local/lib/php/*/[a-z]*.so
usr/local/lib/lighttpd/mod_auth.so
usr/local/lib/lighttpd/mod_authn_file.so
usr/local/lib/lighttpd/mod_fastcgi.so
usr/local/lib/lighttpd/mod_accesslog.so
usr/local/lib/lighttpd/mod_alias.so
usr/local/lib/lighttpd/mod_openssl.so
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

# Resolve the shared libraries a file needs.
#
# This runs the HOST's ldd, and that is the trap the first version fell into:
# ldd only finds what the build host has installed. A package library that
# exists only in the staging root came back as "not found", was silently
# dropped, and the image shipped with lighttpd, dnsmasq, mpd5, charon and
# snmpd all unable to load -- 32 libraries missing across 25 binaries. Two
# distinct gaps:
#
#   1. package libraries the host lacks   -> ldd could not resolve them at all
#   2. BASE libraries only a package needs -> resolved fine, then skipped
#      because the old code copied only from the staging root (libdl,
#      libexecinfo, libcrypt, libdevstat, the krb5 family ...)
#
# LD_LIBRARY_PATH pointed at every directory in the staging root that holds
# a shared object closes gap 1: rtld now loads the package libraries from
# there, which also means it can descend into THEIR dependencies. Copying
# base libraries from the host closes gap 2; stage 1 takes its base
# libraries from this same host, so the provenance is identical.
#
# None of this is trusted on its own. The stage ends by tracing every ELF
# object with the image's OWN linker inside a chroot and fails if anything
# is still missing. That check is the one that actually matters.
STAGE_LIBPATH=$(find "$STAGE" -name '*.so*' -type f 2>/dev/null | xargs -n1 dirname | sort -u | tr '\n' ':')

resolve_libs() {
	f="$1"
	LD_LIBRARY_PATH="$STAGE_LIBPATH" ldd "$f" 2>/dev/null | awk '$2 == "=>" {print $3}' | while read -r lib; do
		case "$lib" in
		"$STAGE"/*)        rel="${lib#$STAGE/}"; src="$STAGE/$rel" ;;      # package library
		/lib/*|/usr/lib/*) rel="${lib#/}";       src="/$rel" ;;            # base library, from the host
		/usr/local/*)      rel="${lib#/}";       src="$STAGE/$rel"          # host has it installed too;
		                   [ -e "$src" ] || src="$lib" ;;                   # prefer the staging copy
		*)                 continue ;;                                      # "not found" -- the gate reports it
		esac
		[ -e "$src" ] || continue
		if [ ! -e "$FS/$rel" ]; then
			mkdir -p "$FS/$(dirname "$rel")"
			cp -p "$src" "$FS/$rel"
			# /lib and /usr/lib libraries are schg on the host; -p keeps the
			# flag, and an immutable file in the image root breaks the next
			# build's rm -rf (and would ship immutable into the UFS image).
			chflags noschg,nouchg "$FS/$rel" 2>/dev/null || true
			echo "$FS/$rel" >> "$MW_BUILDPATH/tmp/newlibs"
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

# ---------------------------------------------------------------------------
# The gate. Trace every ELF object with the image's own dynamic linker, inside
# the image root, and refuse to finish if anything cannot load. This is the
# check that reflects what will happen at boot; everything above is a best
# effort to make it pass.
#
# Only dynamically linked objects are traced. With LD_TRACE_LOADED_OBJECTS
# set, rtld prints the dependency list and exits before main() -- the program
# never runs. A statically linked binary has no rtld, so exec'ing it would
# RUN it, and this tree contains /sbin/halt.
# ---------------------------------------------------------------------------
echo "Verifying every object in the image loads with the image's own linker..."
# rtld searches only /lib and /usr/lib on its own; /usr/local/lib is reached
# through the hints file that etc/rc builds with ldconfig at boot. Run the
# image's own ldconfig line, inside the image, so the trace sees exactly the
# search path the booted system will have -- taken from etc/rc itself so the
# two cannot drift apart. The first version of this gate skipped that step
# and reported every /usr/local/lib dependency of lighttpd and dnsmasq as
# missing while they sat right there in the image.
LDCONFIG_LINE=$(grep -m1 '^/sbin/ldconfig' "$FS/etc/rc")
[ -n "$LDCONFIG_LINE" ] || { echo "ERROR: no ldconfig line in etc/rc -- nothing in /usr/local/lib would load at boot"; exit 1; }
chroot "$FS" /bin/sh -c "$LDCONFIG_LINE"
: > "$MW_BUILDPATH/tmp/ldmissing"
find "$FS/bin" "$FS/sbin" "$FS/usr/bin" "$FS/usr/sbin" "$FS/libexec" \
     "$FS/usr/libexec" "$FS/usr/local" "$FS/lib" "$FS/usr/lib" -type f 2>/dev/null |
while read -r f; do
	rel="${f#$FS}"
	case "$(file -b "$f" 2>/dev/null)" in
	*ELF*executable*dynamically\ linked*|*ELF*pie\ executable*dynamically\ linked*)
		chroot "$FS" /bin/sh -c "LD_TRACE_LOADED_OBJECTS=1 exec $rel" 2>&1 ;;
	*ELF*shared\ object*dynamically\ linked*)
		chroot "$FS" /bin/sh -c "LD_TRACE_LOADED_OBJECTS=1 exec /libexec/ld-elf.so.1 $rel" 2>&1 ;;
	*)	continue ;;
	esac | grep "not found" | sed "s|^|$rel: |" >> "$MW_BUILDPATH/tmp/ldmissing"
done
if [ -s "$MW_BUILDPATH/tmp/ldmissing" ]; then
	echo
	echo "ERROR: these objects cannot load in the image:"
	sed 's/^/  /' "$MW_BUILDPATH/tmp/ldmissing"
	echo
	echo "Distinct libraries missing:"
	awk '{print $2}' "$MW_BUILDPATH/tmp/ldmissing" | sort | uniq -c | sort -rn | sed 's/^/  /'
	exit 1
fi
echo "  all objects load"
# etc/rc regenerates this at every boot; don't ship a stale one.
rm -f "$FS/var/run/ld-elf.so.hints"

rm -rf "$STAGE" "$MW_BUILDPATH/tmp/newlibs" "$MW_BUILDPATH/tmp/ldmissing"

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
