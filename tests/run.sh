#!/bin/sh
# Run every m0n0wall test suite. Exits non-zero if any suite fails.
# Deliberately plain sh + php: runs on the build host and on the image.
cd "$(dirname "$0")/.." || exit 1
PHP=${PHP:-php}
rc=0
echo "PHP: $($PHP -r 'echo PHP_VERSION;')"
echo

# Syntax first: a file that does not parse cannot be unit-tested, and one that
# ships broken can take a whole subsystem with it -- a parse error in a
# scheduler .cjob aborts every scheduled job, not just its own. The build has
# the same gate against the image's php; this is the fast local copy.
bad=0
for f in phpconf/inc/*.inc phpconf/rc.* webgui/*.php webgui/*.inc \
         captiveportal/*.php captiveportal/*.inc etc/croen_jobs/*.cjob \
         tests/*.php build/scripts/*.php; do
    [ -f "$f" ] || continue
    head -1 "$f" | grep -q '<?php' || continue
    $PHP -l "$f" >/dev/null 2>&1 || { echo "PARSE ERROR: $f"; $PHP -l "$f" 2>&1 | sed 's/^/  /'; bad=1; }
done
if [ $bad -ne 0 ]; then
    echo
    echo "FAILURES PRESENT (syntax)"
    exit 1
fi
echo "syntax: all files parse"
echo

for t in tests/t_*.php; do
    $PHP -d error_reporting=E_ALL -d display_errors=1 "$t" || rc=1
done
echo
[ $rc -eq 0 ] && echo "ALL SUITES PASSED" || echo "FAILURES PRESENT"
exit $rc
