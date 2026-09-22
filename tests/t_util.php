<?php
/* util.inc -- IP maths and input validation. Everything else leans on these. */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/xmlparse.inc';
require MW_ROOT . '/phpconf/inc/util.inc';

/* subnet maths */
is_same('gen_subnet /24',        gen_subnet('192.168.1.55', 24),    '192.168.1.0');
is_same('gen_subnet /8',         gen_subnet('192.0.2.77', 8),       '192.0.0.0');
is_same('gen_subnet /30',        gen_subnet('10.0.0.6', 30),        '10.0.0.4');
is_same('gen_subnet /32',        gen_subnet('10.0.0.6', 32),        '10.0.0.6');
is_same('gen_subnet_max /24',    gen_subnet_max('192.168.1.1', 24), '192.168.1.255');
is_same('gen_subnet_max /30',    gen_subnet_max('10.0.0.4', 30),    '10.0.0.7');
is_same('gen_subnet_mask /24',   gen_subnet_mask(24),               '255.255.255.0');
is_same('gen_subnet_mask /30',   gen_subnet_mask(30),               '255.255.255.252');
is_same('gen_subnet_mask /0',    gen_subnet_mask(0),                '0.0.0.0');
is_same('gen_subnet_mask /32',   gen_subnet_mask(32),               '255.255.255.255');

/* IPv4 validation */
is_true ('is_ipaddr valid',      is_ipaddr('192.0.2.1'));
is_true ('is_ipaddr 0.0.0.0',    is_ipaddr('0.0.0.0'));
is_false('is_ipaddr octet>255',  is_ipaddr('999.1.1.1'));
is_false('is_ipaddr garbage',    is_ipaddr('garbage'));
is_false('is_ipaddr empty',      is_ipaddr(''));
is_false('is_ipaddr 3 octets',   is_ipaddr('10.1.10'));

/* IPv6 validation */
is_true ('is_ipaddr6 valid',     is_ipaddr6('2001:db8::1'));
is_true ('is_ipaddr6 loopback',  is_ipaddr6('::1'));
is_false('is_ipaddr6 garbage',   is_ipaddr6('zzzz::1'));

/* subnets */
is_true ('is_subnet /24',        is_subnet('192.0.2.0/24'));
is_false('is_subnet /33',        is_subnet('192.0.2.0/33'));
is_false('is_subnet no prefix',  is_subnet('192.0.2.0'));
is_true ('is_subnet6',           is_subnet6('2001:db8::/64'));

/* other validators */
is_true ('is_macaddr valid',     is_macaddr('00:11:22:33:44:55'));
is_false('is_macaddr bad hex',   is_macaddr('zz:11:22:33:44:55'));
is_true ('is_port 443',          is_port('443'));
is_true ('is_port 1',            is_port('1'));
is_false('is_port 70000',        is_port('70000'));
is_false('is_port 0',            is_port('0'));
is_true ('is_hostname',          is_hostname('m0n0wall'));
is_false('is_hostname w/ dot',   is_hostname('a.b'));
is_true ('is_domain',            is_domain('example.org'));
is_true ('is_numericint',        is_numericint('42'));
is_false('is_numericint float',  is_numericint('4.2'));
is_true ('is_validaliasname',    is_validaliasname('myalias'));

exit(mw_report('util.inc'));
