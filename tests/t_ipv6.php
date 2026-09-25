<?php
/* Net_IPv6 -- vendored PEAR library. Two real bugs were fixed here during the
   PHP 8 migration; these tests exist so they stay fixed. */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/IPv6.php';
/* is_ipaddr6() lives in util.inc, and the point of the regressions at the end
   of this file is that a malformed address reaches the VALIDATOR as a clean
   false rather than as an exception -- so the validator has to be loaded. */
require MW_ROOT . '/phpconf/inc/xmlparse.inc';
require MW_ROOT . '/phpconf/inc/util.inc';

is_same('uncompress',        Net_IPv6::Uncompress('2001:db8::1'), '2001:db8:0:0:0:0:0:1');
is_same('compress',          Net_IPv6::Compress('2001:0db8:0000:0000:0000:0000:0000:0001'), '2001:db8::1');
is_same('round trip',        Net_IPv6::Compress(Net_IPv6::Uncompress('fe80::215:5dff:fe00:401')), 'fe80::215:5dff:fe00:401');

is_true ('checkIPv6 full',   Net_IPv6::checkIPv6('2001:db8::1'));
is_true ('checkIPv6 loopbk', Net_IPv6::checkIPv6('::1'));
/* Regression: this used to raise a hexdec() deprecation on non-hex input. */
is_false('checkIPv6 garbage',Net_IPv6::checkIPv6('zzzz::1'));

is_same('removeNetmaskSpec', Net_IPv6::removeNetmaskSpec('2001:db8::1/64'), '2001:db8::1');
is_same('getNetmaskSpec',    Net_IPv6::getNetmaskSpec('2001:db8::1/64'), '64');

/* Regression: getNetmask() used to hang and exhaust memory (17 GB) because
   pstr_split() looped forever -- it terminated on substr() returning false,
   and PHP 8 returns "" instead. */
is_same('getNetmask /64',    Net_IPv6::getNetmask('2001:db8::1/64'), '2001:db8:0:0:0:0:0:0');
is_same('getNetmask /48',    Net_IPv6::getNetmask('2001:db8:1:2::1/48'), '2001:db8:1:0:0:0:0:0');
is_same('pstr_split 8x16',   count(Net_IPv6::pstr_split(str_repeat('0', 128), 16)), 8);

is_true ('isInNetmask hit',  Net_IPv6::isInNetmask('fe80::1', 'fe80::', 10));
is_false('isInNetmask miss', Net_IPv6::isInNetmask('2001:db8::1', 'fe80::', 10));

/* Regression: SplitV64() on a bare IPv4 address. It contains '.' so it takes
   the v4-mapped branch, but has no ':' -- strrpos() then returned false and
   PHP read $ip[false] as $ip[0], silently eating the first character and
   emitting a "String offset cast" warning. */
is_same('SplitV64 on bare IPv4 keeps every digit',
        Net_IPv6::SplitV64('10.77.0.1'), array('', '10.77.0.1'));
is_same('SplitV64 still splits a v4-mapped address',
        Net_IPv6::SplitV64('::ffff:10.0.0.1'), array('0:0:0:0:0:ffff', '10.0.0.1'));

/* --- REGRESSION: a malformed address must be an input error, not a fatal ---
 *
 * Uncompress() works out how many zero groups a '::' stands for. An address
 * with more groups than the '::' leaves room for makes that count NEGATIVE, and
 * str_repeat() with a negative count throws a ValueError in PHP 8 -- it was a
 * warning returning "" in PHP 5. Nothing catches it, so typing a too-long IPv6
 * address into ANY IPv6 field on ANY page killed the page outright instead of
 * saying the value was invalid. */
$malformed = array(
    '1:2:3:4:5:6:7:8::9:10:11:12',   /* 8 groups before '::', 4 after */
    '::1:2:3:4:5:6:7:8:9',           /* 9 groups after a leading '::' */
    '1:2:3:4:5:6:7:8:9::',           /* 9 groups before a trailing '::' */
);
foreach ($malformed as $bad) {
    $threw = false;
    try { Net_IPv6::Uncompress($bad); } catch (Throwable $e) { $threw = true; }
    is_false("Uncompress('$bad') does not throw", $threw);

    $threw = false;
    try { $ok = is_ipaddr6($bad); } catch (Throwable $e) { $threw = true; $ok = null; }
    is_false("is_ipaddr6('$bad') does not throw", $threw);
    is_false("is_ipaddr6('$bad') rejects it", $ok);
}

/* and the valid forms must still expand exactly as before */
is_same('::1 still expands',          Net_IPv6::Uncompress('::1'), '0:0:0:0:0:0:0:1');
is_same('trailing :: still expands',  Net_IPv6::Uncompress('2001:db8::'), '2001:db8:0:0:0:0:0:0');
is_same('middle :: still expands',    Net_IPv6::Uncompress('2001:db8::1'), '2001:db8:0:0:0:0:0:1');
is_same(':: alone still expands',     Net_IPv6::Uncompress('::'), '0:0:0:0:0:0:0:0');
is_true ('a scoped address survives', strpos(Net_IPv6::Uncompress('fe80::1%em0'), '%em0') !== false);

exit(mw_report('IPv6.php'));
