#!/bin/sh
#
# Gate: every dynamically linked object in the image must actually LOAD.
#
# Trace every ELF object with the image's OWN dynamic linker, inside the image
# root, and refuse to finish if anything cannot resolve. This is the check that
# reflects what happens at boot; the library copying in stage 2 is a best effort
# to make it pass.
#
# Lives in its own script because it has to run in stage 3, not stage 2: stage 3
# is where m0n0wall's own tools are compiled and installed (voucher, minicron,
# croen, dnswatch, verifysig, stats, choparp), and voucher is linked against
# libcrypto. Run only at the end of stage 2, the gate walked usr/local before
# any of them existed, so their library dependencies were never verified -- the
# image could ship a voucher binary rtld cannot load and every gate would pass.
# Stage 3 also strips, so running after that tests exactly the objects that ship.
#
# Usage: checkelf.sh <image-root> <scratch-dir>
# ---------------------------------------------------------------------------
set -e

FS="$1"
MW_BUILDPATH_TMP="$2"
[ -d "$FS" ] || { echo "checkelf.sh: no such image root: $FS"; exit 2; }
mkdir -p "$MW_BUILDPATH_TMP"

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
: > "$MW_BUILDPATH_TMP/ldmissing"
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
	esac | grep "not found" | sed "s|^|$rel: |" >> "$MW_BUILDPATH_TMP/ldmissing"
done
if [ -s "$MW_BUILDPATH_TMP/ldmissing" ]; then
	echo
	echo "ERROR: these objects cannot load in the image:"
	sed 's/^/  /' "$MW_BUILDPATH_TMP/ldmissing"
	echo
	echo "Distinct libraries missing:"
	awk '{print $2}' "$MW_BUILDPATH_TMP/ldmissing" | sort | uniq -c | sort -rn | sed 's/^/  /'
	exit 1
fi
echo "  all objects load"
