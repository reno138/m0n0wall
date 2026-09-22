#!/bin/sh
# Run every m0n0wall test suite. Exits non-zero if any suite fails.
# Deliberately plain sh + php: runs on the build host and on the image.
cd "$(dirname "$0")/.." || exit 1
PHP=${PHP:-php}
rc=0
echo "PHP: $($PHP -r 'echo PHP_VERSION;')"
echo
for t in tests/t_*.php; do
    $PHP -d error_reporting=E_ALL -d display_errors=1 "$t" || rc=1
done
echo
[ $rc -eq 0 ] && echo "ALL SUITES PASSED" || echo "FAILURES PRESENT"
exit $rc
