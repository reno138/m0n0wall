<?php
/*
 * pf translation rules (binat / rdr / nat).
 *
 * Ordering matters as much as syntax here: pf evaluates translation rules
 * first-match, so binat must precede rdr, and rdr must precede nat or
 * inbound redirects get eaten by an outbound mapping.
 */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/xmlparse.inc';
require MW_ROOT . '/phpconf/inc/util.inc';

/* Stand in for the parts of interfaces.inc that shell out to ifconfig. */
function get_real_wan_interface($ipv6 = false) { return 'em0'; }
function get_current_wan_address($ipv6 = false) {
    /* drivable: the whole point of the regression below is the case where the
       WAN has no address yet */
    return empty($GLOBALS['MW_NO_LEASE']) ? '203.0.113.5' : null;
}

require MW_ROOT . '/phpconf/inc/filter_pf.inc';

$GLOBALS['aliastable'] = array('webserver' => '192.168.1.10');

/* --- a single outbound mapping ------------------------------------------ */
$config = array('nat' => array());
is_same('nat uses ($if) for the interface address',
        pf_nat_rule_generate_if('em0', '192.168.1.0/24', '', null),
        "nat on em0 from 192.168.1.0/24 to any -> (em0) port 1024:64535\n");

is_same('nat with port mapping disabled keeps the source port',
        pf_nat_rule_generate_if('em0', '192.168.1.0/24', '', null, false),
        "nat on em0 from 192.168.1.0/24 to any -> (em0) static-port\n");

is_same('nat to an explicit target',
        pf_nat_rule_generate_if('em0', '192.168.1.0/24', '', '203.0.113.9'),
        "nat on em0 from 192.168.1.0/24 to any -> 203.0.113.9 port 1024:64535\n");

$config = array('nat' => array('portrange-low' => 40000, 'portrange-high' => 50000));
is_same('nat honours a custom port range',
        pf_nat_rule_generate_if('em0', '192.168.1.0/24', '', null),
        "nat on em0 from 192.168.1.0/24 to any -> (em0) port 40000:50000\n");

/* --- a full ruleset, checking section order ----------------------------- */
$config = array(
  'interfaces' => array(
     'wan' => array('if' => 'em0'),
     'lan' => array('if' => 'em1', 'ipaddr' => '192.168.1.1', 'subnet' => '24'),
  ),
  'pptpd' => array(), 'staticroutes' => array(),
  'nat' => array(
     'onetoone' => array(
        array('interface'=>'wan','internal'=>'192.168.1.50','external'=>'203.0.113.50','subnet'=>'32'),
     ),
     'rule' => array(
        array('interface'=>'wan','protocol'=>'tcp','external-address'=>'wan',
              'external-port'=>'443','local-port'=>'443','target'=>'webserver'),
        array('interface'=>'wan','protocol'=>'tcp','external-address'=>'',
              'external-port'=>'8000-8010','local-port'=>'8000','target'=>'webserver'),
     ),
  ),
);
$out = pf_nat_rules_generate();

is_true('emits binat for 1:1',
        strpos($out, 'binat on em0 from 192.168.1.50/32 to any -> 203.0.113.50/32') !== false);
/* "WAN address" is emitted as pf's interface-address form, not as the address
   the WAN happened to have when the ruleset was built.
   
   This used to assert 'to 203.0.113.5'. That was a snapshot, and
   get_current_wan_address() returns NULL on a DHCP/PPPoE/PPTP/modem WAN with no
   lease -- at boot, before the lease, or any time the link is down. The null was
   interpolated straight in, producing "from any to  port 443", which pfctl
   rejects; and pfctl rejects the FILE, so one port forward on a dynamic WAN left
   the firewall with NO RULESET AT ALL.
   
   '(em0:0)' is the first address on the interface, resolved by pf at match time,
   so it is also correct across a lease change without a reload. Verified to load
   with pfctl -n -f on FreeBSD 15.1. */
is_true('a WAN-address rdr uses the interface, not a snapshot',
        strpos($out, 'rdr on em0 proto tcp from any to (em0:0) port 443 -> 192.168.1.10 port 443') !== false);
is_false('and never interpolates a bare/empty address',
         strpos($out, 'from any to  port') !== false);
is_true('rdr port range is inclusive pf syntax',
        strpos($out, 'port 8000:8010') !== false);
is_true('emits nat for the LAN',
        strpos($out, 'nat on em0 from 192.168.1.0/24 to any -> (em0)') !== false);
is_true('emits the ftp-proxy anchor',
        strpos($out, 'anchor "ftp-proxy/*"') !== false);

/* pf evaluates translation first-match: binat, then rdr, then nat. */
/* Anchor to line starts: the literal "binat on" contains "nat on", so a
   naive strpos() finds the binat rule and the ordering check passes for the
   wrong reason. */
preg_match('/^binat on/m', $out, $m, PREG_OFFSET_CAPTURE); $pos_binat = $m[0][1];
preg_match('/^rdr on/m',   $out, $m, PREG_OFFSET_CAPTURE); $pos_rdr   = $m[0][1];
preg_match('/^nat on/m',   $out, $m, PREG_OFFSET_CAPTURE); $pos_nat   = $m[0][1];
is_true('binat precedes rdr', $pos_binat < $pos_rdr);
is_true('rdr precedes nat',   $pos_rdr < $pos_nat);

/* An unresolvable alias must drop the rule, not emit a broken one. */
$config['nat']['rule'][] = array('interface'=>'wan','protocol'=>'tcp',
    'external-address'=>'','external-port'=>'9999','local-port'=>'9999','target'=>'nosuchalias');
$out2 = pf_nat_rules_generate();
is_false('unresolvable rdr target is dropped', strpos($out2, '9999') !== false);

/* --- REGRESSION: a dynamic WAN with no lease must still produce a valid file ---
 *
 * This is the failure that cost the entire ruleset. Nothing about the config
 * changes here except that the WAN has not got an address yet. */
$GLOBALS['MW_NO_LEASE'] = true;
$nolease = pf_nat_rules_generate();
$GLOBALS['MW_NO_LEASE'] = false;

is_true ('no-lease: the rdr rule is still emitted',
         strpos($nolease, 'rdr on em0 proto tcp') !== false);
is_true ('no-lease: it still names the interface address',
         strpos($nolease, 'to (em0:0)') !== false);
/* the shapes pfctl rejects: an empty address, or a doubled space where one was */
is_false('no-lease: no empty destination',  strpos($nolease, 'to  port') !== false);
is_false('no-lease: no trailing "to" ',     preg_match('/to\s*$/m', $nolease) === 1);
is_false('no-lease: no literal null',       stripos($nolease, 'to null') !== false);
/* and every emitted line must still have both endpoints */
foreach (explode("\n", $nolease) as $ln) {
    if (strpos($ln, 'rdr on') !== 0) continue;
    is_true('no-lease: "' . trim($ln) . '" has a destination',
            preg_match('/from \S+ to \S+/', $ln) === 1);
}

exit(mw_report('filter_pf NAT'));
