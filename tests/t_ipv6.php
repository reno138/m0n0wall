<?php
/* Net_IPv6 -- vendored PEAR library. Two real bugs were fixed here during the
   PHP 8 migration; these tests exist so they stay fixed. */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/IPv6.php';

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

exit(mw_report('IPv6.php'));
