<?php
/*
 * Whole-ruleset assembly.
 *
 * pf.conf's section order is not a style preference -- pfctl rejects a file
 * whose sections are out of order, and a table declared inside the filter
 * section is a parse error. These tests assert the order holds for a ruleset
 * built from the real shipped config.
 */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/xmlparse.inc';
require MW_ROOT . '/phpconf/inc/util.inc';

function get_real_wan_interface($ipv6 = false) { return 'em0'; }
function get_current_wan_address($ipv6 = false) { return '203.0.113.5'; }
/* ipv6enabled() normally comes from system.inc, which reads the running
   kernel. Drive it from a global so both paths can be exercised. */
function ipv6enabled() { return !empty($GLOBALS['MW_TEST_V6']); }

require MW_ROOT . '/phpconf/inc/filter_pf.inc';

$config = parse_xml_config(MW_ROOT . '/phpconf/config.xml', 'm0n0wall');
$GLOBALS['aliastable'] = array();

/* add a couple of user rules and turn on private-network blocking so the
   interesting paths are exercised */
$config['interfaces']['wan']['blockpriv'] = true;
/* Pin the NIC names. The shipped config uses sis0 (a Soekris board), and a
   test should not silently depend on 2015 hardware naming. */
$config['interfaces']['lan']['if'] = 'em1';
$config['filter']['rule'] = array(
    array('type'=>'pass','interface'=>'lan','protocol'=>'tcp',
          'source'=>array('network'=>'lan'),'destination'=>array('any'=>true)),
    array('type'=>'block','interface'=>'wan','protocol'=>'tcp','log'=>true,
          'source'=>array('any'=>true),
          'destination'=>array('network'=>'lan','port'=>'3389')),
    array('type'=>'pass','interface'=>'opt9','protocol'=>'tcp',
          'source'=>array('any'=>true),'destination'=>array('any'=>true)),
);

$out = pf_rules_generate();
$lines = explode("\n", $out);

is_true('produces a ruleset', strlen($out) > 200);

/* section order, by first occurrence of each marker */
function firstline($out, $re) {
    return preg_match($re, $out, $m, PREG_OFFSET_CAPTURE) ? $m[0][1] : PHP_INT_MAX;
}
$macros = firstline($out, '/^wan_if = /m');
$tables = firstline($out, '/^table </m');
$opts   = firstline($out, '/^set block-policy/m');
$scrub  = firstline($out, '/^scrub in/m');
$trans  = firstline($out, '/^(binat|rdr|nat) on/m');
$filter = firstline($out, '/^block in/m');

is_true('macros before tables',        $macros < $tables);
is_true('tables before options',       $tables < $opts);
is_true('options before scrub',        $opts   < $scrub);
is_true('scrub before translation',    $scrub  < $trans);
is_true('translation before filtering',$trans  < $filter);

/* the <priv> table must be declared, and declared outside the filter section */
is_true('priv table declared',  strpos($out, 'table <priv> const') !== false);
is_true('priv table precedes its use',
        strpos($out, 'table <priv> const') < strpos($out, 'from <priv> to any'));

/* essentials */
is_true('sets block-policy',    strpos($out, 'set block-policy drop') !== false);
is_true('skips lo0',            strpos($out, 'set skip on lo0') !== false);
is_true('scrubs + reassembles', strpos($out, 'scrub in all fragment reassemble') !== false);
is_true('default deny in',      preg_match('/^block in log all$/m', $out) === 1);
is_true('default deny out',     preg_match('/^block out log all$/m', $out) === 1);
is_true('anti-lockout present', strpos($out, 'anti-lockout') !== false);
is_true('LAN anti-spoof',       strpos($out, 'LAN anti-spoof') !== false);

/* user rules: the two valid ones emit, the one on a non-existent interface
   is dropped rather than emitted broken */
/* Rules now carry an explicit address family: pf filters v4 and v6 from one
   ruleset, so "any" has to be qualified or it would match both. */
is_true('lan user rule emitted',
        strpos($out, 'pass in quick on em1 inet proto tcp from 192.168.1.0/24 to any keep state') !== false);
is_true('wan user rule emitted',
        strpos($out, 'block in log quick on em0 inet proto tcp from any to 192.168.1.0/24 port 3389') !== false);
is_false('rule on missing opt9 dropped', strpos($out, 'opt9') !== false);

/* nothing should carry an unexpanded PHP variable or stray brace */
is_false('no unexpanded variables', preg_match('/\$\{|\$[a-z_]+\[/i', $out) === 1);

/* ---- IPv6: one unified ruleset, not a second one ---------------------- */
$GLOBALS['MW_TEST_V6'] = true;
$config['interfaces']['lan']['ipaddr6'] = '2001:db8:1::1';
$config['interfaces']['lan']['subnet6'] = '64';
$config['filter']['rule6'] = array(
    array('type'=>'pass','interface'=>'lan','protocol'=>'tcp',
          'source'=>array('any'=>true),'destination'=>array('any'=>true,'port'=>'443')),
);
$v6 = pf_rules_generate();

is_true('v6 rules share the one ruleset', strpos($v6, 'IPv6 base rules') !== false);
is_true('neighbour discovery passed',
        strpos($v6, 'icmp6-type { 133, 134, 135, 136 }') !== false);
is_true('PMTUD types passed',  strpos($v6, 'icmp6-type { 1, 2, 3 }') !== false);
is_true('link-local passed',   strpos($v6, 'from fe80::/10 to fe80::/10') !== false);
is_true('DHCPv6 passed',       strpos($v6, 'port 546 to ff02::1:2 port 547') !== false);
is_true('priv6 table declared',strpos($v6, 'table <priv6> const') !== false);
is_true('v4 user rule carries inet',
        strpos($v6, 'pass in quick on em1 inet proto tcp') !== false);
is_true('v6 user rule carries inet6',
        strpos($v6, 'inet6 proto tcp from any to any port 443') !== false);

/* the v6 table must still be declared before it is used */
is_true('priv6 table precedes its use',
        strpos($v6, 'table <priv6> const') < strpos($v6, 'from <priv6> to any'));

/* and the section order must survive the v6 additions */
$t6 = firstline($v6, '/^table </m');
$o6 = firstline($v6, '/^set block-policy/m');
$x6 = firstline($v6, '/^(binat|rdr|nat) on/m');
$f6 = firstline($v6, '/^block in/m');
is_true('v6: tables before options',      $t6 < $o6);
is_true('v6: options before translation', $o6 < $x6);
is_true('v6: translation before filter',  $x6 < $f6);

$GLOBALS['MW_TEST_V6'] = false;

exit(mw_report('filter_pf assembly'));
