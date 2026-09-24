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

/* Mirrors interfaces.inc: a tunnelled IPv6 WAN is a different interface from
   the physical one, which is exactly what the protocol-41 rules depend on. */
function get_real_wan_interface($ipv6 = false) {
    global $config;
    if (!$ipv6)
        return 'em0';
    $m = $config['interfaces']['wan']['ipaddr6'] ?? '';
    if ($m == '6to4')  return 'stf0';
    if ($m == 'aiccu') return 'gif0';
    if (!empty($config['interfaces']['wan']['tunnel6'])) return 'gif0';
    return 'em0';
}
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

/* ------------------------------------------------------------------------
 * Regressions from the subsystem audit. Each of these shipped broken.
 * --------------------------------------------------------------------- */

/* 1. ICMP type names. ipfilter's 'echo' is pf's 'echoreq', and pfctl rejects
 *    the WHOLE file over one unknown name -- so this single rule used to leave
 *    the firewall with no ruleset at all. */
$config['filter']['rule'] = array(
    array('type'=>'pass','interface'=>'wan','protocol'=>'icmp','icmptype'=>'echo',
          'source'=>array('any'=>true),'destination'=>array('any'=>true)),
);
$out = pf_rules_generate();
is_true('legacy ICMP "echo" is emitted as pf "echoreq"',
        strpos($out, 'icmp-type echoreq') !== false);
is_true('the ipfilter spelling never reaches pf.conf',
        strpos($out, 'icmp-type echo ') === false
        && !preg_match('/icmp-type echo$/m', $out));

$config['filter']['rule'][0]['icmptype'] = 'timestrep';
is_true('legacy "timestrep" becomes "timerep"',
        strpos(pf_rules_generate(), 'icmp-type timerep') !== false);

$config['filter']['rule'][0]['icmptype'] = 'echoreq';
is_true('a pf name passes through unchanged',
        strpos(pf_rules_generate(), 'icmp-type echoreq') !== false);

/* An unknown name must drop the qualifier, never emit it: emitting it would
 * cost the entire ruleset. */
$config['filter']['rule'][0]['icmptype'] = 'nonsense';
$out = pf_rules_generate();
is_true('an unknown ICMP type drops the qualifier rather than breaking pfctl',
        strpos($out, 'nonsense') === false && strpos($out, 'proto icmp') !== false);

/* 2. ICMPv6 needs its own keyword. */
$GLOBALS['MW_TEST_V6'] = true;
$config['filter']['rule'] = array();
$config['filter']['rule6'] = array(
    array('type'=>'pass','interface'=>'wan','protocol'=>'ipv6-icmp','icmptype'=>'128',
          'source'=>array('any'=>true),'destination'=>array('any'=>true)),
);
$out = pf_rules_generate();
is_true('ICMPv6 rules use icmp6-type', strpos($out, 'icmp6-type 128') !== false);
is_true('ICMPv6 rules do not use the v4 keyword',
        !preg_match('/proto ipv6-icmp[^\n]* icmp-type /', $out));
$config['filter']['rule6'] = array();
$GLOBALS['MW_TEST_V6'] = false;

/* 3. IPsec: the IKE/ESP/AH passes existed but were never called, so every
 *    inbound IKE packet met the default block. */
$config['ipsec']['enable'] = true;
$out = pf_rules_generate();
is_true('IKE/NAT-T is passed in on the WAN',
        preg_match('/pass in quick on em0 proto udp from any to 203\.0\.113\.5 port \{ 500 4500 \}/', $out) === 1);
is_true('ESP and AH are passed in on the WAN',
        strpos($out, 'proto { esp ah } from any to 203.0.113.5') !== false);
unset($config['ipsec']['enable']);
is_true('no IPsec passes when IPsec is off',
        strpos(pf_rules_generate(), 'esp ah') === false);

/* 4. WireGuard: interfaces were brought up and then everything they carried
 *    was dropped by 'block in/out all'. */
$config['wireguard']['tunnel'] = array(
    array('if'=>'wg0','descr'=>'mesh','privatekey'=>'x','listenport'=>'51820'),
    array('if'=>'wg1','descr'=>'off','disabled'=>true),
);
$out = pf_rules_generate();
is_true('an enabled tunnel is passed out', strpos($out, 'pass out quick on wg0 all') !== false);
is_true('an enabled tunnel is passed in',  strpos($out, 'pass in quick on wg0 all') !== false);
is_true('a disabled tunnel gets no rules', strpos($out, 'wg1') === false);

/* ...but the moment the admin writes a wg rule, the blanket inbound pass is
 * withheld so their rule is what decides. */
$config['filter']['rule'] = array(
    array('type'=>'pass','interface'=>'wg0','protocol'=>'tcp',
          'source'=>array('any'=>true),'destination'=>array('any'=>true,'port'=>'22')),
);
$out = pf_rules_generate();
is_true('a user wg rule withholds the blanket inbound pass',
        strpos($out, 'pass in quick on wg0 all') === false);
is_true('the firewall can still send on the tunnel',
        strpos($out, 'pass out quick on wg0 all') !== false);
is_true('the user rule binds to the tunnel',
        preg_match('/pass in quick on wg0 .*port 22/', $out) === 1);

/* A rule naming a tunnel that no longer exists must be skipped, not emitted
 * against a bare interface name. */
$config['filter']['rule'][0]['interface'] = 'wg7';
is_true('a rule for a deleted tunnel is skipped',
        strpos(pf_rules_generate(), 'on wg7') === false);
$config['wireguard'] = array();
$config['filter']['rule'] = array();

/* 5. L2TP served only the first client. */
$config['l2tp'] = array('mode'=>'server','remoteip'=>'10.9.9.0','nunits'=>'3');
$config['filter']['rule'] = array(
    array('type'=>'pass','interface'=>'l2tp','protocol'=>'tcp',
          'source'=>array('any'=>true),'destination'=>array('any'=>true)),
);
$out = pf_rules_generate();
is_true('an L2TP rule covers every client interface',
        strpos($out, 'on { l2tp0 l2tp1 l2tp2 }') !== false);
$config['l2tp'] = array();
$config['filter']['rule'] = array();

/* 6. A restored config's PPTP rules must be skipped, not bound to ng0:
 *    PPTP is removed from this port. */
$config['pptpd'] = array('mode'=>'server','remoteip'=>'10.8.8.0','nunits'=>'16');
$config['filter']['rule'] = array(
    array('type'=>'pass','interface'=>'pptp','protocol'=>'tcp',
          'source'=>array('any'=>true),'destination'=>array('any'=>true)),
);
$out = pf_rules_generate();
is_true('a restored PPTP rule is skipped', strpos($out, 'ng0') === false);
$config['pptpd'] = array();
$config['filter']['rule'] = array();

/* 7. The TCP idle timeout was doubled on the way from the GUI to pf. */
$config['filter']['tcpidletimeout'] = '3600';
is_true('the TCP idle timeout is passed through in seconds, not doubled',
        strpos(pf_rules_generate(), 'set timeout tcp.established 3600') !== false);
unset($config['filter']['tcpidletimeout']);

/* 8. A tunnelled IPv6 WAN was blocked outright: protocol 41 never passed. */
$GLOBALS['MW_TEST_V6'] = true;
$config['interfaces']['wan']['ipaddr6'] = '6to4';
$out = pf_rules_generate();
is_true('protocol 41 is passed in on the physical WAN',
        strpos($out, 'pass in quick on em0 inet proto ipencap') !== false);
is_true('protocol 41 is passed out on the physical WAN',
        strpos($out, 'pass out quick on em0 inet proto ipencap') !== false);
is_true('the tunnel broker may ping the endpoint',
        strpos($out, 'icmp-type echoreq') !== false);
is_true('decapsulated traffic on the tunnel interface is passed',
        strpos($out, 'pass quick on stf0 all') !== false);
unset($config['interfaces']['wan']['ipaddr6']);
$GLOBALS['MW_TEST_V6'] = false;
is_true('a native WAN gets no tunnel rules',
        strpos(pf_rules_generate(), 'ipencap') === false);

/* 9. filter_configure6() reported success while doing nothing. */
$rc = new ReflectionFunction('filter_configure6');
is_true('filter_configure6() is no longer a return-0 stub',
        strpos(file_get_contents($rc->getFileName()), 'function filter_configure6()                 { return 0;') === false);

/* 10. The firewall log mangled every IPv6 packet. */
$parsed = array();
foreach (array(
    '2001:db8::1.54321 > 2001:db8::2.80: tcp 0',
    '192.0.2.30.54321 > 192.0.2.240.65001: tcp 0',
) as $rest) {
    preg_match('/^(\S+) > (\S+):\s*(\S*)/', $rest, $r);
    $parsed[] = pf_log_split_endpoint($r[2]);
}
is_true('an IPv6 destination survives intact', $parsed[0][0] === '2001:db8::2' && $parsed[0][1] === '80');
is_true('an IPv4 destination still parses',    $parsed[1][0] === '192.0.2.240' && $parsed[1][1] === '65001');

exit(mw_report('filter_pf assembly'));
