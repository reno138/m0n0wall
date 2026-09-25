<?php
/*
 * Optional interfaces: OPTn as a STABLE IDENTIFIER.
 *
 * Deleting an OPT used to close the hole -- opt3 was shifted down into opt2 --
 * and it shifted $config['interfaces'] only. Every other reference to the name
 * stayed put and quietly changed meaning: $config['dhcpd']['opt1'] went on
 * serving the range configured for the interface that had just been deleted,
 * now on whichever interface had moved into its place, and a filter rule naming
 * opt2 matched nothing at all because pf_rule_interface() found no such
 * interface and dropped the rule from the ruleset.
 *
 * Nothing shifts now, so optN belongs to its interface for as long as the
 * interface exists and every reference to optN stays correct. What that costs is
 * gaps in the numbering, which is why util.inc's opt_interfaces() exists and why
 * every enumeration in the tree goes through it -- a counting loop stops dead at
 * the first missing number.
 *
 * This suite asserts the whole claim, in two halves:
 *
 *   1. the helpers, called directly against gapless, gapped and degenerate
 *      configs;
 *   2. the two pages that mutate interface identity, each run as the REAL page
 *      file in a child PHP process behind a test double for guiconfig.inc --
 *      the same technique tests/t_vlan.php uses, and for the same reason: what
 *      matters is what the page writes to the config, which ifconfig commands
 *      it runs and whether it demands a reboot, and none of that can be seen by
 *      calling a function.
 *
 * The double cannot simply require util.inc -- that pulls in the real mwexec(),
 * which would run ifconfig for real -- so it requires phpconf/inc/optif.inc,
 * which holds the two OPT helpers and nothing else for exactly this reason. It
 * is the real shipping code, so the double cannot drift from it. The PARENT
 * process here does load the real util.inc, because part 1 needs nothing else
 * from it.
 */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/xmlparse.inc';
require MW_ROOT . '/phpconf/inc/util.inc';

/* The real dnsmasq DHCP generator, for the one assertion that closes the loop
   on the whole change: that after a delete, the range configured for OPT3 is
   still served on OPT3. Everything else here is about what the config LOOKS
   like; this is about what the running service does with it. */
function get_real_wan_interface($ipv6 = false) { return 'em0'; }
require MW_ROOT . '/phpconf/inc/dhcp_dnsmasq.inc';

/* =======================================================================
 * Part 1: the helpers.
 * ======================================================================= */

$base = array(
	'lan' => array('if' => 'em1', 'ipaddr' => '10.0.0.1', 'subnet' => '24'),
	'wan' => array('if' => 'em0', 'ipaddr' => 'dhcp'),
);

/* --- gapless ------------------------------------------------------------ */
$config = array('interfaces' => $base + array(
	'opt1' => array('if' => 'em2', 'descr' => 'LAN-B'),
	'opt2' => array('if' => 'em3', 'descr' => 'DMZ'),
	'opt3' => array('if' => 'em4', 'descr' => 'GUEST'),
));
is_same('gapless: every OPT, keyed by its number',
        opt_interfaces(), array(1 => 'opt1', 2 => 'opt2', 3 => 'opt3'));
is_same('gapless: the next free number is one past the last', opt_next_free(), 4);
is_same('gapless: the count is the number of OPTs', count(opt_interfaces()), 3);

/* --- gapped: what a delete now leaves behind ---------------------------
 *
 * The point of the whole change. A counting loop
 * (for ($i = 1; isset($config['interfaces']['opt' . $i]); $i++)) returns opt1
 * and stops, so OPT3 and OPT7 are invisible to it -- no address, no DHCP, no
 * firewall rules, and absent from every dropdown. */
$config['interfaces'] = $base + array(
	'opt1' => array('if' => 'em2', 'descr' => 'LAN-B'),
	'opt3' => array('if' => 'em4', 'descr' => 'GUEST'),
	'opt7' => array('if' => 'em5', 'descr' => 'LAB'),
);
is_same('gapped: a config with holes is enumerated COMPLETELY',
        opt_interfaces(), array(1 => 'opt1', 3 => 'opt3', 7 => 'opt7'));
is_same('gapped: the number is still the key, so labels stay right',
        array_keys(opt_interfaces()), array(1, 3, 7));
is_same('gapped: the next free number is the LOWEST unused one, not the highest + 1',
        opt_next_free(), 2);

/* and the old loop really did stop at the hole -- asserted, so that this suite
   still means something if someone reintroduces one */
$old = array();
for ($i = 1; isset($config['interfaces']['opt' . $i]); $i++)
	$old[$i] = 'opt' . $i;
is_same('a counting loop over the same config sees only OPT1', $old, array(1 => 'opt1'));

/* --- a hole below every OPT --------------------------------------------- */
$config['interfaces'] = $base + array('opt2' => array('if' => 'em3'),
                                      'opt3' => array('if' => 'em4'));
is_same('a config whose lowest OPT is not 1 is still enumerated',
        opt_interfaces(), array(2 => 'opt2', 3 => 'opt3'));
is_same('and opt1 is the free slot', opt_next_free(), 1);
$old = array();
for ($i = 1; isset($config['interfaces']['opt' . $i]); $i++)
	$old[$i] = 'opt' . $i;
is_same('where a counting loop saw nothing at all', $old, array());

/* --- numeric order, not insertion or string order -----------------------
 *
 * Reusing a freed number APPENDS to $config['interfaces'], so the array order
 * after a delete-then-add is opt1, opt3, opt2. And a string sort would put
 * opt10 before opt2. */
$config['interfaces'] = $base + array(
	'opt12' => array('if' => 'em6'),
	'opt2'  => array('if' => 'em3'),
	'opt10' => array('if' => 'em5'),
	'opt1'  => array('if' => 'em2'),
);
is_same('out-of-order keys come back in NUMERIC order',
        array_keys(opt_interfaces()), array(1, 2, 10, 12));

/* --- degenerate configs ------------------------------------------------- */
$config['interfaces'] = $base;
is_same('no OPTs at all: an empty list, not a warning', opt_interfaces(), array());
is_same('and the first number is free', opt_next_free(), 1);

$config['interfaces'] = array();
is_same('an empty interfaces section: an empty list', opt_interfaces(), array());
is_same('and the first number is free', opt_next_free(), 1);

unset($config['interfaces']);
is_same('no interfaces section at all: an empty list', opt_interfaces(), array());
is_same('and the first number is free', opt_next_free(), 1);

$config = array();
is_same('an empty config: an empty list', opt_interfaces(), array());

/* A hand-edited <opt2/> parses to the empty string, not an array. Skipped, so
   that it cannot be iterated as if it had ['if'] and ['descr']. */
$config['interfaces'] = $base + array('opt1' => array('if' => 'em2'),
                                      'opt2' => '',
                                      'opt3' => array('if' => 'em4'));
is_same('a malformed OPT section is skipped, not enumerated',
        opt_interfaces(), array(1 => 'opt1', 3 => 'opt3'));

/* Only optN is an OPT. optical0 or opt as a bare word is not. */
$config['interfaces'] = $base + array('opt1' => array('if' => 'em2'),
                                      'opt'  => array('if' => 'em3'),
                                      'optx' => array('if' => 'em4'));
is_same('only opt<digits> counts', opt_interfaces(), array(1 => 'opt1'));


/* --- the console wizard's port mapping ----------------------------------
 *
 * phpconf/rc.initial.setports asks for LAN's port, WAN's port and then the
 * optional ports in order. It used to write them straight to opt1..optN, which
 * RENAMED the interfaces: enter GUEST's port before the DMZ's and GUEST became
 * opt1, inheriting the DMZ's DHCP range and every rule written for the DMZ.
 * opt_assign_map() gives the entered ports to the interfaces that already
 * exist, in number order, so each keeps its name. */
$config['interfaces'] = $base + array('opt1' => array('if' => 'em3', 'descr' => 'DMZ'),
                                      'opt2' => array('if' => 'em4', 'descr' => 'GUEST'));

$a = opt_assign_map(array('em4', 'em3'));
is_same('wizard: the ports swap over, the NAMES stay put',
        $a['map'], array('opt1' => 'em4', 'opt2' => 'em3'));
is_same('wizard: nothing is surplus when the counts match', $a['surplus'], array());

/* A gapped config -- the ordinary state after a delete. The old cleanup loop
   stopped at the hole and left opt3 alive holding a port the wizard had just
   given away; the old assignment loop would have called it opt1. */
$config['interfaces'] = $base + array('opt1' => array('if' => 'em3', 'descr' => 'DMZ'),
                                      'opt3' => array('if' => 'em5', 'descr' => 'LAB'));

$a = opt_assign_map(array('em3', 'em5'));
is_same('wizard: a gap is preserved -- OPT3 is not renamed to OPT2',
        $a['map'], array('opt1' => 'em3', 'opt3' => 'em5'));

$a = opt_assign_map(array('em3'));
is_same('wizard: one port for two interfaces assigns the first',
        $a['map'], array('opt1' => 'em3'));
is_same('wizard: and the other is surplus, PAST the hole -- not missed',
        $a['surplus'], array('opt3'));

$a = opt_assign_map(array('em3', 'em5', 'em4'));
is_same('wizard: a third port fills the hole, at the lowest free number',
        $a['map'], array('opt1' => 'em3', 'opt3' => 'em5', 'opt2' => 'em4'));
is_same('wizard: and nothing is surplus', $a['surplus'], array());

$a = opt_assign_map(array('em3', 'em5', 'em4', 'em2'));
is_same('wizard: a fourth goes above the hole, not into it twice',
        array_keys($a['map']), array('opt1', 'opt3', 'opt2', 'opt4'));

/* No optional interfaces yet: the first-run case. */
$config['interfaces'] = $base;
$a = opt_assign_map(array('em3', 'em4'));
is_same('wizard: a fresh config numbers from 1',
        $a['map'], array('opt1' => 'em3', 'opt2' => 'em4'));

$a = opt_assign_map(array());
is_same('wizard: no optional ports entered at all', $a['map'], array());
is_same('wizard: and nothing to remove', $a['surplus'], array());

/* Every interface removed. */
$config['interfaces'] = $base + array('opt1' => array('if' => 'em3'),
                                      'opt2' => array('if' => 'em4'));
$a = opt_assign_map(array());
is_same('wizard: entering no ports marks every OPT surplus',
        $a['surplus'], array('opt1', 'opt2'));


/* =======================================================================
 * Part 2: the pages.
 * ======================================================================= */

$drv = mw_sandbox() . '/optdrv';
@mkdir($drv, 0755, true);

/* The double for guiconfig.inc: everything interfaces_assign.php and
   interfaces_vlan.php touch.
   
   The REAL scheduler.inc is loaded rather than stubbed, because whether a
   scheduled interface-enable job goes away with its interface is one of the
   things under test, and that function is self-contained apart from
   write_config(). */
file_put_contents($drv . '/guiconfig.inc', <<<'STUB'
<?php
/* test double -- see tests/t_optiface.php */
$g = array('booting' => false, 'wireless_regex' => '/^(ath|an|wi|ral|ndis)/',
           'varrun_path' => '/var/run');
$d_sysrebootreqd_path = getenv('MW_FLAG');

function mwexec($command) {
	file_put_contents(getenv('MW_CMDS'), $command . "\n", FILE_APPEND);
	return (int) getenv('MW_RC');
}
function mwexec_bg($command) { return mwexec($command); }
function get_interface_list($ethernet = true, $wireless = true, $serial = true) {
	$list = array();
	foreach (explode(",", getenv('MW_PORTS')) as $p)
		if ($p !== '') $list[$p] = array('mac' => '00:00:00:00:00:00', 'drvname' => 'em');
	return $list;
}
function do_input_validation($postdata, $reqdfields, $reqdfieldsn, &$input_errors) {
	foreach ($reqdfields as $i => $f)
		if (empty($postdata[$f])) $input_errors[] = $reqdfieldsn[$i] . " is required.";
}
function is_numericint($arg) { return preg_match("/^\d+$/", (string)$arg) ? true : false; }
function write_config() {
	global $config;
	file_put_contents(getenv('MW_CFG'), serialize($config));
	/* the real write_config() re-reads config.xml and reassigns $config, which
	   leaves a page's $a_vlans reference pointing at the pre-write copy */
	$config = unserialize(serialize($config));
}
function config_lock() {}
function config_unlock() {}
function log_error($text) { file_put_contents(getenv('MW_LOG'), $text . "\n", FILE_APPEND); }
function print_input_errors($errs) { echo "INPUT_ERRORS: " . implode(" | ", $errs) . "\n"; }
function print_info_box($msg) { echo "INFO: " . $msg . "\n"; }
function print_info_box_np($msg) { print_info_box($msg); }
function get_std_save_message($ok) {
	global $d_sysrebootreqd_path;
	if ($ok != 0) return "ERROR: the changes could not be applied (error code $ok).";
	if (file_exists($d_sysrebootreqd_path))
		return "The changes have been saved. You must reboot your firewall for changes to take effect.";
	return "The changes have been applied successfully.";
}

/* The pages enumerate the OPT interfaces with opt_interfaces(). util.inc as a
   whole cannot be loaded here for the reason at the top of this file -- its
   mwexec() would run ifconfig for real -- but the OPT helpers live in their own
   file precisely so this stub can require the REAL code and never drift. */
/* interfaces_opt.php needs these. IPv6 OFF, so the page takes its v4-only
   path -- the v6 half is interfaces_opt.php's business, not this suite's. The
   apply functions are captured rather than run: what matters here is WHETHER
   the page applies and what it writes, and interfaces.inc's real
   interfaces_optional_configure() is already exercised through
   interfaces_assign.php above. */
function ipv6enabled() { return false; }
function captiveportal_configure() { $GLOBALS['mw_cmds'][] = 'captiveportal_configure'; return 0; }
function services_dhcpd_configure() { $GLOBALS['mw_cmds'][] = 'services_dhcpd_configure'; return 0; }
function filter_configure() { $GLOBALS['mw_cmds'][] = 'filter_configure'; return 0; }
function killbyname() { return 0; }
function system_routing_configure() { return 0; }
function shaper_configure() { return 0; }
function vpn_ipsec_configure() { return 0; }
function services_dhcp6s_configure() { return 0; }
function is_ipaddr($a) { return (bool) filter_var($a, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4); }
function is_ipaddr6($a) { return (bool) filter_var($a, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6); }

require getenv('MW_TREE') . '/phpconf/inc/optif.inc';

require getenv('MW_TREE') . '/phpconf/inc/scheduler.inc';
require getenv('MW_TREE') . '/phpconf/inc/interfaces.inc';

$config = unserialize(file_get_contents(getenv('MW_CFG')));
STUB
);

file_put_contents($drv . '/fbegin.inc', "<?php \$mandfldhtml = \"\"; ?>\n");
file_put_contents($drv . '/fend.inc', "<?php /* test double */ ?>\n");

file_put_contents($drv . '/driver.php', <<<'DRV'
<?php
set_include_path(__DIR__ . PATH_SEPARATOR . getenv('MW_TREE') . '/tests/stubs');
$_POST = json_decode(file_get_contents(getenv('MW_POST')), true);
$_GET = json_decode(getenv('MW_GET') ?: '[]', true);
require getenv('MW_PAGE');
DRV
);

/* A child that calls one interfaces.inc function instead of running a page, so
   the exact ifconfig command line can be asserted. The parent process cannot do
   it: it has the real util.inc loaded, so mwexec() here is the real one. */
file_put_contents($drv . '/callfn.php', <<<'FN'
<?php
set_include_path(__DIR__ . PATH_SEPARATOR . getenv('MW_TREE') . '/tests/stubs');
require 'guiconfig.inc';
$fn = getenv('MW_FN');
file_put_contents(getenv('MW_OUT'), (string) $fn(getenv('MW_ARG')));
FN
);

/* The PHP diagnostics in a captured page render, if any.
   
   TWO patterns, because the two kinds of message do not look alike and one
   pattern for both had a hole in it.
   
   Warning/Notice/Deprecated are matched on PHP's own " ... on line N" suffix
   rather than on the word alone, because interfaces_assign.php's footer prose
   contains "Warning:" itself and so does half the webGUI.
   
   A fatal has no such suffix on the line that names it: PHP writes
       PHP Fatal error:  Uncaught Error: Call to undefined function f() in /x.inc:1376
   ending in ":1376", and the later "thrown in ... on line 1376" line carries
   neither keyword. Requiring " on line N" of these too therefore matched
   NOTHING, and this suite reported a clean render over a page that had died
   half way down -- which is exactly what it did, until the stubs below were
   completed. These three words never appear in the webGUI's own prose, so they
   need no suffix to disambiguate. */
function mw_diags($out) {
	$d = array();
	foreach (explode("\n", $out) as $line) {
		if (preg_match('/\b(Warning|Notice|Deprecated)\b.* on line \d+/', $line) ||
		    preg_match('/\b(Fatal error|Parse error|Uncaught)\b/', $line))
			$d[] = trim($line);
	}
	return $d;
}

/* Run one page POST, or one function call. Returns the commands run, the reboot
   flag, the saved config, the syslog lines, the output and the redirect. */
function mw_drive($page, $post, $config, $opts = array()) {
	global $drv;

	$flag = $drv . '/sysreboot.reqd';
	foreach (array('/cmds', '/log', '/post.json', '/config.ser', '/fnout') as $f) @unlink($drv . $f);
	@unlink($flag);
	touch($drv . '/cmds');
	touch($drv . '/log');
	if (!empty($opts['rebootpending'])) touch($flag);

	file_put_contents($drv . '/post.json', json_encode($post));
	file_put_contents($drv . '/config.ser', serialize($config));

	$env = array(
		'MW_TREE'  => MW_ROOT,
		'MW_PAGE'  => MW_ROOT . '/webgui/' . $page,
		'MW_FLAG'  => $flag,
		'MW_CMDS'  => $drv . '/cmds',
		'MW_LOG'   => $drv . '/log',
		'MW_POST'  => $drv . '/post.json',
		'MW_CFG'   => $drv . '/config.ser',
		'MW_OUT'   => $drv . '/fnout',
		'MW_FN'    => $opts['fn'] ?? '',
		'MW_ARG'   => (string) ($opts['arg'] ?? ''),
		'MW_PORTS' => $opts['ports'] ?? 'em0,em1,em2,em3,em4,em5',
		'MW_RC'    => (string) ($opts['rc'] ?? 0),
		'MW_GET'   => json_encode($opts['get'] ?? array()),
	);
	$cmd = '';
	foreach ($env as $k => $v) $cmd .= $k . '=' . escapeshellarg($v) . ' ';
	$cmd .= escapeshellarg(PHP_BINARY) . ' -d error_reporting=E_ALL -d display_errors=1 ' .
		escapeshellarg($drv . (empty($opts['fn']) ? '/driver.php' : '/callfn.php')) . ' 2>&1';

	$out = array();
	exec($cmd, $out);
	$out = implode("\n", $out);

	/* The pages redirect with header(), which a CLI SAPI discards -- but it also
	   prints nothing, so capture the Location out of the page source path
	   instead: header() is a no-op here, so the only evidence is that nothing
	   was rendered. Rather than guess, the redirect target is read back from the
	   status token the page appends, which is asserted directly below. */
	return array(
		'cmds'   => array_values(array_filter(explode("\n", file_get_contents($drv . '/cmds')), 'strlen')),
		'flag'   => file_exists($flag),
		'config' => unserialize(file_get_contents($drv . '/config.ser')),
		'log'    => file_get_contents($drv . '/log'),
		'out'    => $out,
		'fnout'  => @file_get_contents($drv . '/fnout'),
	);
}

/* A config with three OPTs, each with its own DHCP server, DHCP relay entry and
   scheduled enable/disable job, plus rules that name OPT1 and OPT3 -- so that
   deleting OPT2 can be shown to leave all of OPT1's and OPT3's belongings
   exactly where they were. */
function optcfg() {
	return array(
		'interfaces' => array(
			'lan'  => array('if' => 'em1', 'ipaddr' => '10.0.0.1', 'subnet' => '24'),
			'wan'  => array('if' => 'em0', 'ipaddr' => 'dhcp'),
			'opt1' => array('if' => 'em2', 'descr' => 'LAN-B', 'enable' => true,
			                'ipaddr' => '10.0.1.1', 'subnet' => '24'),
			'opt2' => array('if' => 'em3', 'descr' => 'DMZ', 'enable' => true,
			                'ipaddr' => '10.0.2.1', 'subnet' => '24'),
			'opt3' => array('if' => 'em4', 'descr' => 'GUEST', 'enable' => true,
			                'ipaddr' => '10.0.3.1', 'subnet' => '24'),
		),
		'dhcpd' => array(
			'lan'  => array('enable' => true, 'range' => array('from' => '10.0.0.100', 'to' => '10.0.0.200')),
			'opt1' => array('enable' => true, 'range' => array('from' => '10.0.1.100', 'to' => '10.0.1.200')),
			'opt2' => array('enable' => true, 'range' => array('from' => '10.0.2.100', 'to' => '10.0.2.200'),
			                'staticmap' => array(array('mac' => '00:11:22:33:44:55', 'ipaddr' => '10.0.2.50'))),
			'opt3' => array('enable' => true, 'range' => array('from' => '10.0.3.100', 'to' => '10.0.3.200')),
		),
		'dhcrelay' => array(
			'server'    => '10.0.0.9',
			'proxydhcp' => false,
			'opt2'      => array('enable' => true),
			'opt3'      => array('enable' => true),
		),
		/* ['if'] here holds an INTERFACE NAME, not a device name -- the one
		   place in the config where that field means that. */
		'secondaries' => array('secondary' => array(
			array('if' => 'opt2', 'ipaddr' => '192.168.99.1', 'prefix' => '24',
			      'descr' => 'DMZ alias'),
			array('if' => 'opt3', 'ipaddr' => '192.168.98.1', 'prefix' => '24',
			      'descr' => 'GUEST alias'),
		)),
		'croen' => array('interval' => '10', 'jobset' => array(
			array('repeat' => 'daily', 'job' => array(
				array('name' => 'interface-enable',  'target' => 'opt2'),
				array('name' => 'interface-disable', 'target' => 'opt3'),
			)),
		)),
		'filter' => array('rule' => array(
			array('type' => 'pass', 'interface' => 'opt1', 'descr' => 'LAN-B out',
			      'source' => array('network' => 'opt1'), 'destination' => array('any' => true)),
			array('type' => 'pass', 'interface' => 'opt3', 'descr' => 'GUEST out',
			      'source' => array('network' => 'opt3'), 'destination' => array('any' => true)),
		)),
	);
}

/* A browser submits a form in DOCUMENT order, so every row's <select> arrives
   before that row's delete button and the add button arrives last. The update
   loop walks $_POST in order, so that ordering is load-bearing: a del_optN_x
   seen BEFORE optN's own select would delete the interface and the select would
   then recreate it. These POSTs are built in document order for that reason. */
function assign_post($extra = array(), $ifs = array('lan' => 'em1', 'wan' => 'em0',
                                                    'opt1' => 'em2', 'opt2' => 'em3', 'opt3' => 'em4')) {
	$p = array();
	foreach ($ifs as $k => $v) {
		$p[$k] = $v;
		if (isset($extra['del']) && $extra['del'] === $k) {
			$p['del_' . $k . '_x'] = '17';
			$p['del_' . $k . '_y'] = '8';
		}
	}
	if (!empty($extra['add'])) { $p['add_x'] = '9'; $p['add_y'] = '9'; }
	if (!empty($extra['raw'])) $p = array_merge($p, $extra['raw']);
	$p['Submit'] = 'Save';
	return $p;
}

/* --- DELETE a middle OPT: only that one goes ---------------------------- */
$r = mw_drive('interfaces_assign.php', assign_post(array('del' => 'opt2')), optcfg());
$ifs = $r['config']['interfaces'];

is_same('delete: every other interface keeps its own key, in place',
        array_keys($ifs), array('lan', 'wan', 'opt1', 'opt3'));
is_same('delete: OPT3 is still opt3 -- NOT shifted down into opt2',
        $ifs['opt3'], array('if' => 'em4', 'descr' => 'GUEST', 'enable' => true,
                            'ipaddr' => '10.0.3.1', 'subnet' => '24'));
is_same('delete: OPT1, below the hole, is untouched too',
        $ifs['opt1'], array('if' => 'em2', 'descr' => 'LAN-B', 'enable' => true,
                            'ipaddr' => '10.0.1.1', 'subnet' => '24'));
is_false('delete: the deleted interface is gone', isset($ifs['opt2']));
/* NO reboot. A delete is applied live: the deleted interface's device is taken
   down, the surviving OPTs are reconfigured, and dnsmasq and the ruleset are
   regenerated (its DHCP section and any rule naming it have just left the
   config). Only re-plugging LAN's or WAN's port still demands a reboot. */
is_false('delete: NO reboot is demanded -- it is applied live', $r['flag']);
is_true ('delete: the deleted interface\'s device is taken down',
         in_array("/sbin/ifconfig 'em3' delete down", $r['cmds']));
is_true ('delete: OPT1, which survived, is reconfigured',
         in_array("/sbin/ifconfig 'em2' '10.0.1.1/24'", $r['cmds']));
is_true ('delete: OPT3, above the hole, is reconfigured too',
         in_array("/sbin/ifconfig 'em4' '10.0.3.1/24'", $r['cmds']));
is_false('delete: the surviving interfaces are NOT taken down',
         in_array("/sbin/ifconfig 'em2' delete down", $r['cmds']) ||
         in_array("/sbin/ifconfig 'em4' delete down", $r['cmds']));

/* The description was rewritten by the shift ("OPT3" became "OPT2"), which is
   how an admin first noticed their interfaces had been renamed under them. */
is_same('delete: no description is rewritten', $ifs['opt3']['descr'], 'GUEST');

/* --- the dependent config goes with it --------------------------------- */
is_false('delete: the deleted interface\'s DHCP server is gone',
         isset($r['config']['dhcpd']['opt2']));
is_same('delete: OPT3 keeps ITS OWN range -- the bug this whole change is about',
        $r['config']['dhcpd']['opt3']['range'],
        array('from' => '10.0.3.100', 'to' => '10.0.3.200'));
is_same('delete: OPT1 keeps its range',
        $r['config']['dhcpd']['opt1']['range'],
        array('from' => '10.0.1.100', 'to' => '10.0.1.200'));
is_same('delete: the LAN DHCP server is not touched',
        $r['config']['dhcpd']['lan']['range'],
        array('from' => '10.0.0.100', 'to' => '10.0.0.200'));
is_same('delete: nothing else is left in the dhcpd section',
        array_keys($r['config']['dhcpd']), array('lan', 'opt1', 'opt3'));

is_false('delete: the DHCP RELAY entry is gone too',
         isset($r['config']['dhcrelay']['opt2']));
is_true ('delete: another interface\'s relay entry survives',
         isset($r['config']['dhcrelay']['opt3']['enable']));
is_same('delete: the relay section\'s own settings survive -- it is not keyed by ' .
        'interface all the way down',
        $r['config']['dhcrelay']['server'], '10.0.0.9');

/* Scheduler jobs, through the REAL croen_update_job(). */
$jobs = array_values($r['config']['croen']['jobset'][0]['job']);
is_same('delete: a scheduled job targeting the interface is removed', count($jobs), 1);
is_same('delete: and a job targeting a DIFFERENT interface is kept',
        $jobs[0], array('name' => 'interface-disable', 'target' => 'opt3'));

/* --- and the running DHCP server agrees -------------------------------
 *
 * The heart of the bug, at the only level where it actually bit: with the old
 * shift-down, deleting OPT2 (DMZ) moved GUEST into the opt2 slot while
 * $config['dhcpd']['opt2'] still held the DMZ's range -- so dnsmasq was handed
 * "dhcp-range=set:opt2,10.0.2.100,10.0.2.200" for an interface addressed
 * 10.0.3.1/24, and GUEST's own range vanished from the file entirely. */
$config = $r['config'];
$config['system'] = array('domain' => 'example.lan', 'dnsserver' => array('9.9.9.9'));
$dnsmasq = dhcp_dnsmasq_config_generate();
$ranges = array();
foreach (explode("\n", $dnsmasq) as $line)
	if (preg_match('/^dhcp-range=set:(\w+),([\d.]+),([\d.]+)/', trim($line), $m))
		$ranges[$m[1]] = $m[2] . "-" . $m[3];
is_same('dnsmasq: every surviving interface still serves ITS OWN range',
        $ranges, array('lan'  => '10.0.0.100-10.0.0.200',
                       'opt1' => '10.0.1.100-10.0.1.200',
                       'opt3' => '10.0.3.100-10.0.3.200'));
is_false('dnsmasq: and the deleted interface serves nothing',
         isset($ranges['opt2']));

/* --- the freed number comes back --------------------------------------- */
$gapped = $r['config'];
$r2 = mw_drive('interfaces_assign.php',
	assign_post(array('add' => true), array('lan' => 'em1', 'wan' => 'em0',
	                                        'opt1' => 'em2', 'opt3' => 'em4')),
	$gapped);
is_true ('add: the freed number is reused, not skipped',
         isset($r2['config']['interfaces']['opt2']));
is_same('add: and it is named after the number it got',
        $r2['config']['interfaces']['opt2']['descr'], 'OPT2');
is_same('add: it takes the first port nothing else is using',
        $r2['config']['interfaces']['opt2']['if'], 'em3');
is_same('add: the surviving interfaces are still where they were',
        array($r2['config']['interfaces']['opt1']['descr'],
              $r2['config']['interfaces']['opt3']['descr']),
        array('LAN-B', 'GUEST'));
is_false('add: reusing the number does NOT bring back the old DHCP config, ' .
         'because the delete took it',
         isset($r2['config']['dhcpd']['opt2']));

/* with no gap, an add still appends */
$r3 = mw_drive('interfaces_assign.php', assign_post(array('add' => true)), optcfg());
is_true ('add: with no gap, the next number is one past the last',
         isset($r3['config']['interfaces']['opt4']));
is_same('add: and it gets the remaining port', $r3['config']['interfaces']['opt4']['if'], 'em5');

/* --- when a reboot is ACTUALLY required --------------------------------
 *
 * This page used to touch the reboot flag on every save, which is how adding an
 * optional interface came to demand one -- an add writes an entry with no
 * address that is not enabled, so nothing on the running system changes. And
 * that flag is global: exec_rc_script() returns early while it exists, so one
 * needless flag puts the whole webGUI into save-only mode until a reboot.
 *
 * Only re-plugging LAN's or WAN's port needs one now, and that one is real: the
 * management session is on lan, and wan carries dhclient/pppoe/modem state. */

is_false('add: no reboot -- the new interface has no address and is not enabled',
         $r3['flag']);

/* Posting the form back unchanged is the commonest save of all: every <select>
   is submitted every time, so without a before/after comparison every save
   would look like a re-plug. */
$rn = mw_drive('interfaces_assign.php', assign_post(), optcfg());
is_false('unchanged save: no reboot', $rn['flag']);
is_false('unchanged save: nothing is taken down',
         (bool) preg_grep('/delete down/', $rn['cmds']));

/* LAN re-plugged onto a different NIC. */
$rl = mw_drive('interfaces_assign.php',
	assign_post(array(), array('lan' => 'em5', 'wan' => 'em0',
	                           'opt1' => 'em2', 'opt2' => 'em3', 'opt3' => 'em4')),
	optcfg());
is_true ('re-plugging LAN DOES demand a reboot', $rl['flag']);
is_same('re-plugging LAN applies nothing -- the session is on it', $rl['cmds'], array());
is_same('re-plugging LAN is still saved', $rl['config']['interfaces']['lan']['if'], 'em5');

/* WAN likewise. */
$rw = mw_drive('interfaces_assign.php',
	assign_post(array(), array('lan' => 'em1', 'wan' => 'em5',
	                           'opt1' => 'em2', 'opt2' => 'em3', 'opt3' => 'em4')),
	optcfg());
is_true ('re-plugging WAN DOES demand a reboot', $rw['flag']);

/* An OPT moved to a different NIC is a delete of the old device plus a
   configure of the new one, so it goes live like any other OPT change. */
$ro = mw_drive('interfaces_assign.php',
	assign_post(array(), array('lan' => 'em1', 'wan' => 'em0',
	                           'opt1' => 'em5', 'opt2' => 'em3', 'opt3' => 'em4')),
	optcfg());
is_false('re-plugging an OPT does NOT demand a reboot', $ro['flag']);
is_true ('re-plugging an OPT takes the device it left down',
         in_array("/sbin/ifconfig 'em2' delete down", $ro['cmds']));
is_true ('re-plugging an OPT brings its address up on the new device',
         in_array("/sbin/ifconfig 'em5' '10.0.1.1/24'", $ro['cmds']));

/* --- THE GATE: a successful delete leaves the name NOWHERE -------------
 *
 * The delete has to unset every section KEYED BY the interface name, and the
 * only list of which sections those are is the one inside opt_iface_delete().
 * A list is exactly the thing that goes stale: add a new per-interface section
 * to the schema one day, forget to add it there, and the orphan sits in the
 * config until opt_next_free() hands its number to an unrelated interface and
 * silently attaches it.
 *
 * So instead of checking against a list, check the invariant the list exists to
 * produce: after a delete that was ACCEPTED, the deleted name appears nowhere
 * in $config at all -- not as a key, not as a value. Anything a future section
 * leaves behind fails this and names its own path. Nothing to keep in step.
 *
 * The complement is the refusal, asserted above: when the name IS still held as
 * a value somewhere, the delete does not happen at all. Between the two, a
 * delete can never leave a dangling reference. */
function config_mentions($node, $name, $path = '') {
	$hits = array();
	if (is_array($node)) {
		foreach ($node as $k => $v) {
			$p = $path . '[' . $k . ']';
			if ($k === $name)
				$hits[] = $p . ' (key)';
			$hits = array_merge($hits, config_mentions($v, $name, $p));
		}
	} else if (is_string($node) && $node === $name) {
		$hits[] = $path . ' (value)';
	}
	return $hits;
}

/* The fixture holds opt2 in four places: interfaces, dhcpd (with a static
   mapping), dhcrelay, and a scheduler job's target. Prove the search finds them
   all before trusting it to prove they are gone. */
is_same('gate: the search finds every mention before the delete',
        config_mentions(optcfg(), 'opt2'),
        array('[interfaces][opt2] (key)', '[dhcpd][opt2] (key)',
              '[dhcrelay][opt2] (key)', '[secondaries][secondary][0][if] (value)',
              '[croen][jobset][0][job][0][target] (value)'));

$rg = mw_drive('interfaces_assign.php', assign_post(array('del' => 'opt2')), optcfg());
is_same('gate: after an accepted delete, the name is nowhere in the config',
        config_mentions($rg['config'], 'opt2'), array());
/* opt3's six mentions all survive, at the same paths: its interface, its DHCP
   server, its DHCP relay, its scheduler job, and its filter rule naming it both
   as the interface and as the source network. It stays at job[1] even though
   opt2's job at job[0] was removed from the same list, because croen_update_job()
   unsets rather than repacks -- harmless here, since nothing addresses a job by
   its index, and xmlparse.inc packs the list on the next save anyway. */
is_same('gate: and everything belonging to the OPTs it did not delete survives',
        config_mentions($rg['config'], 'opt3'),
        array('[interfaces][opt3] (key)', '[dhcpd][opt3] (key)',
              '[dhcrelay][opt3] (key)', '[secondaries][secondary][0][if] (value)',
              '[croen][jobset][0][job][1][target] (value)',
              '[filter][rule][1][interface] (value)',
              '[filter][rule][1][source][network] (value)'));

/* --- secondary (alias) addresses go with the interface ------------------
 *
 * These are owned config, like the DHCP range, but they are not KEYED by the
 * name: they are a flat list carrying it in ['if'] -- the one field in the
 * config where ['if'] is an interface name rather than a device name, which is
 * how this section came to be missed. Leaving one behind is worse than an
 * ordinary orphan: interfaces_secondaries_configure() matches on the name
 * alone, so once opt_next_free() reuses the number the new interface silently
 * comes up carrying the deleted one's alias address, and filter.inc emits pass
 * rules for its subnet. And it is invisible while it waits -- the only webGUI
 * route to it is on interfaces_opt.php, which reports no such interface. */
$rs = mw_drive('interfaces_assign.php', assign_post(array('del' => 'opt2')), optcfg());
is_same('secondaries: the deleted interface\'s alias address is gone with it',
        array_column($rs['config']['secondaries']['secondary'], 'if'), array('opt3'));
is_same('secondaries: the surviving interface keeps its own',
        $rs['config']['secondaries']['secondary'][0]['ipaddr'], '192.168.98.1');
is_same('secondaries: the list is repacked, not left with a hole',
        array_keys($rs['config']['secondaries']['secondary']), array(0));

/* Delete the only one and the empty container goes too, rather than leaving
   <secondaries><secondary/></secondaries> for the parser to read back as "". */
$c = optcfg();
$c['secondaries']['secondary'] = array(array('if' => 'opt2', 'ipaddr' => '192.168.99.1',
                                             'prefix' => '24'));
$rs2 = mw_drive('interfaces_assign.php', assign_post(array('del' => 'opt2')), $c);
is_false('secondaries: the last one leaves no empty list behind',
         isset($rs2['config']['secondaries']['secondary']));

/* --- a stale ?index= cannot resurrect a deleted interface ---------------
 *
 * interfaces_opt.php is addressed by number, and a number is a stable
 * identifier now -- so a delete leaves its index permanently valid-LOOKING. A
 * tab left open across the delete, a bookmark, or a back-button Save posts it.
 *
 * $optcfg there is taken by REFERENCE, and =& creates the key it is given, so
 * without a guard the POST handler writes descr/ipaddr/subnet/enable straight
 * through it and saves -- an interface with no ['if'] at all, holding a number
 * back out of the pool opt_next_free() reuses and making
 * interfaces_optional_configure_if() run ifconfig with an empty device name. */
$c = optcfg();
unset($c['interfaces']['opt2'], $c['dhcpd']['opt2'], $c['dhcrelay']['opt2']);

$rz = mw_drive('interfaces_opt.php',
	array('index' => '2', 'descr' => 'GHOST', 'ipaddr' => '10.9.9.1',
	      'subnet' => '24', 'enable' => 'yes', 'Submit' => 'Save'),
	$c, array('get' => array('index' => '2')));
is_false('stale index: the deleted interface is NOT recreated',
         array_key_exists('opt2', $rz['config']['interfaces']));
is_same('stale index: and nothing else was written either',
        array_keys($rz['config']['interfaces']), array('lan', 'wan', 'opt1', 'opt3'));
is_false('stale index: no reboot demanded for a bounced request', $rz['flag']);

/* The control: an index that IS there saves normally. Without this the guard
   could be refusing everything and the test above would still pass. */
$rz2 = mw_drive('interfaces_opt.php',
	array('index' => '3', 'descr' => 'GUEST RENAMED', 'ipaddr' => '10.0.3.1',
	      'subnet' => '24', 'enable' => 'yes', 'Submit' => 'Save'),
	$c, array('get' => array('index' => '3')));
is_same('stale index control: a real index still saves',
        $rz2['config']['interfaces']['opt3']['descr'], 'GUEST RENAMED');

/* --- REFUSED: an IPsec tunnel carrying the interface's network ----------
 *
 * The ORDINARY shape, not an exotic one: a tunnel's ['interface'] is the
 * OUTSIDE interface and defaults to wan, so "tunnel over WAN carrying the OPT1
 * network" names opt1 only in ['local-subnet']['network']. Dangling, it makes
 * ipsec_ss_local_ts() return null, ipsec_strongswan.inc omits local_ts and
 * swanctl substitutes its own default; once the number is reused the tunnel
 * offers the NEW interface's subnet to the remote peer. */
$c = optcfg();
$c['ipsec']['tunnel'] = array(array('interface' => 'wan', 'descr' => 'to branch office',
                                    'local-subnet' => array('network' => 'opt1'),
                                    'remote-subnet' => '10.9.0.0/24'));
$r = mw_drive('interfaces_assign.php', assign_post(array('del' => 'opt1')), $c);
is_true ('refusal: a tunnel whose LOCAL SUBNET is the interface net refuses it',
         strpos($r['out'], 'VPN: IPsec (id 0, "to branch office")') !== false);
is_true ('refusal: and the interface is still there', isset($r['config']['interfaces']['opt1']));

/* the outside-interface case still refuses, and must not double-report */
$c['ipsec']['tunnel'][0]['interface'] = 'opt1';
$r = mw_drive('interfaces_assign.php', assign_post(array('del' => 'opt1')), $c);
is_same('refusal: a tunnel naming it BOTH ways is reported once, not twice',
        substr_count($r['out'], 'VPN: IPsec (id 0'), 1);

/* --- the page shows a gapped config completely, in number order --------
 *
 * Array order is no longer number order: opt2 was appended when it reused the
 * freed number, so $config['interfaces'] reads lan, wan, opt1, opt3, opt2. */
is_same('the config array order after a reuse really is out of order',
        array_keys($r2['config']['interfaces']), array('lan', 'wan', 'opt1', 'opt3', 'opt2'));
$r4 = mw_drive('interfaces_assign.php', array(), $r2['config']);
preg_match_all('/<select name="(\w+)"/', $r4['out'], $m);
is_same('the page lists every interface, OPTs in NUMBER order',
        $m[1], array('lan', 'wan', 'opt1', 'opt2', 'opt3'));

$r5 = mw_drive('interfaces_assign.php', array(), $gapped);
preg_match_all('/<select name="(\w+)"/', $r5['out'], $m);
is_same('a config with a hole is listed completely -- OPT3 does not vanish',
        $m[1], array('lan', 'wan', 'opt1', 'opt3'));
is_true ('and its delete button is addressed by its real name',
         strpos($r5['out'], 'name="del_opt3"') !== false);

/* --- REFUSED while a rule still names it ------------------------------- */
$c = optcfg();
$c['filter']['rule'][] = array('type' => 'block', 'interface' => 'opt2',
                               'descr' => 'DMZ lockdown',
                               'source' => array('any' => true),
                               'destination' => array('any' => true));
$r = mw_drive('interfaces_assign.php', assign_post(array('del' => 'opt2')), $c);
is_true ('refusal: a filter rule naming the interface refuses the delete',
         strpos($r['out'], 'INPUT_ERRORS:') !== false);
is_true ('refusal: and it names the page and the rule',
         strpos($r['out'], 'Firewall: Rules (id 2, "DMZ lockdown")') !== false);
is_true ('refusal: nothing is deleted', isset($r['config']['interfaces']['opt2']));
is_true ('refusal: its DHCP config is left alone too', isset($r['config']['dhcpd']['opt2']));
is_false('refusal: and no reboot is demanded for a refusal', $r['flag']);

/* A rule naming a DIFFERENT interface must not block the delete. optcfg() has
   rules on OPT1 and OPT3 and none on OPT2, so this is the no-over-refusal
   case. */
$r = mw_drive('interfaces_assign.php', assign_post(array('del' => 'opt2')), optcfg());
is_false('rules naming OPT1 and OPT3 do not block deleting OPT2',
         strpos($r['out'], 'INPUT_ERRORS:') !== false);
is_false('and it really was deleted', isset($r['config']['interfaces']['opt2']));

/* the name can also be a rule's source or destination NETWORK */
$c = optcfg();
$c['filter']['rule'][] = array('type' => 'pass', 'interface' => 'lan', 'descr' => 'to DMZ',
                               'source' => array('network' => 'lan'),
                               'destination' => array('network' => 'opt2'));
$r = mw_drive('interfaces_assign.php', assign_post(array('del' => 'opt2')), $c);
is_true ('refusal: a rule whose DESTINATION is the interface net refuses it too',
         strpos($r['out'], 'to DMZ') !== false);

/* and a shaper rule */
$c = optcfg();
$c['shaper']['rule'] = array(array('targetpipe' => '0', 'interface' => 'opt2',
                                   'descr' => 'DMZ cap', 'direction' => 'out'));
$r = mw_drive('interfaces_assign.php', assign_post(array('del' => 'opt2')), $c);
is_true ('refusal: a shaper rule naming the interface refuses it',
         strpos($r['out'], 'Firewall: Traffic shaper (id 0, "DMZ cap")') !== false);

/* every other section that stores an interface name as a value */
$cases = array(
	'NAT, inbound'    => array('nat', 'rule'),
	'NAT, 1:1'        => array('nat', 'onetoone'),
	'Static routes'   => array('staticroutes', 'route'),
	'Wake on LAN'     => array('wol', 'wolentry'),
	'Proxy ARP'       => array('proxyarp', 'proxyarpnet'),
	'IPsec'           => array('ipsec', 'tunnel'),
);
foreach ($cases as $label => $path) {
	$c = optcfg();
	if (count($path) == 2)
		$c[$path[0]][$path[1]] = array(array('interface' => 'opt2', 'descr' => 'x'));
	$r = mw_drive('interfaces_assign.php', assign_post(array('del' => 'opt2')), $c);
	is_true ("refusal: $label naming the interface refuses the delete",
	         strpos($r['out'], $label) !== false &&
	         isset($r['config']['interfaces']['opt2']));
}

/* outbound NAT is nested one level deeper */
$c = optcfg();
$c['nat']['advancedoutbound'] = array('enable' => true,
	'rule' => array(array('interface' => 'opt2', 'descr' => 'DMZ NAT')));
$r = mw_drive('interfaces_assign.php', assign_post(array('del' => 'opt2')), $c);
is_true ('refusal: an advanced outbound NAT rule refuses it',
         strpos($r['out'], 'NAT, outbound (id 0, "DMZ NAT")') !== false);

/* the captive portal, which is a single value rather than a list */
$c = optcfg();
$c['captiveportal'] = array('enable' => true, 'interface' => 'opt2');
$r = mw_drive('interfaces_assign.php', assign_post(array('del' => 'opt2')), $c);
is_true ('refusal: the captive portal interface refuses it',
         strpos($r['out'], 'Services: Captive portal') !== false);

/* a bridge is recorded on the OTHER interface, as the name of this one */
$c = optcfg();
$c['interfaces']['opt3']['bridge'] = 'opt2';
$r = mw_drive('interfaces_assign.php', assign_post(array('del' => 'opt2')), $c);
is_true ('refusal: an interface bridged TO it refuses the delete, and says which',
         strpos($r['out'], 'OPT3, which is bridged to it') !== false);

/* --- only an OPT that exists can be deleted ---------------------------- */
$r = mw_drive('interfaces_assign.php',
	assign_post(array('raw' => array('del_lan_x' => '17'))), optcfg());
is_true ('del_lan_x is refused', strpos($r['out'], 'no optional interface') !== false);
is_true ('LAN is still there', isset($r['config']['interfaces']['lan']));
is_true ('and so is the LAN DHCP server', isset($r['config']['dhcpd']['lan']));

$r = mw_drive('interfaces_assign.php',
	assign_post(array('raw' => array('del_opt9_x' => '17'))), optcfg());
is_true ('a delete for a number that does not exist is refused',
         strpos($r['out'], 'no optional interface') !== false);
is_same('and nothing changed', array_keys($r['config']['interfaces']),
        array('lan', 'wan', 'opt1', 'opt2', 'opt3'));

/* a malformed <opt4/> still has to be deletable, or it is stuck on the page */
$c = optcfg();
$c['interfaces']['opt4'] = '';
$r = mw_drive('interfaces_assign.php',
	assign_post(array('raw' => array('del_opt4_x' => '17'))), $c);
is_false('a malformed OPT section can be deleted', isset($r['config']['interfaces']['opt4']));
is_same('and the real interfaces are untouched', array_keys($r['config']['interfaces']),
        array('lan', 'wan', 'opt1', 'opt2', 'opt3'));

/* --- no PHP diagnostics on any of it ----------------------------------- */
$r = mw_drive('interfaces_assign.php', assign_post(array('del' => 'opt2')), optcfg());
is_same('no warning, notice or deprecation from the delete path',
        mw_diags($r['out']), array());
$r = mw_drive('interfaces_assign.php', array(), array('interfaces' => array()));
is_same('nor from rendering a config with no interfaces at all',
        mw_diags($r['out']), array());
$r = mw_drive('interfaces_assign.php', array(), $gapped);
is_same('nor from rendering a config with a hole in it',
        mw_diags($r['out']), array());
$r = mw_drive('interfaces_assign.php', assign_post(array('add' => true)), $gapped);
is_same('nor from reusing a freed number', mw_diags($r['out']), array());


/* =======================================================================
 * VLANs.
 *
 * A VLAN cannot get a stable identifier the way optN did: its name is its
 * POSITION in $config['vlans']['vlan'], and a hole in a list section does not
 * survive being saved -- xmlparse.inc rebuilds one with
 * array_push($curpath, count($ptr)), so config.xml reads the entries back as
 * 0..n-1. So a delete from the MIDDLE still renumbers and still needs a reboot.
 *
 * Deleting the LAST entry renumbers nothing, which makes it the mirror of the
 * add path's pure append -- and vlan_inuse() has already established that the
 * interface is assigned to nothing, so it cannot be carrying this session.
 * That one is applied live.
 * ======================================================================= */

function vlancfg() {
	return array(
		'interfaces' => array(
			'lan'  => array('if' => 'em1', 'ipaddr' => '10.0.0.1', 'subnet' => '24'),
			'wan'  => array('if' => 'em0', 'ipaddr' => 'dhcp'),
			'opt1' => array('if' => 'vlan2', 'descr' => 'LAN-B'),
			'opt3' => array('if' => 'em4', 'descr' => 'GUEST'),
		),
		'vlans' => array('vlan' => array(
			array('if' => 'em2', 'tag' => '10', 'descr' => 'servers'),
			array('if' => 'em2', 'tag' => '20', 'descr' => 'voice'),
			array('if' => 'em2', 'tag' => '30', 'descr' => 'iot'),
			array('if' => 'em2', 'tag' => '40', 'descr' => 'spare'),
		)),
	);
}

/* --- delete the LAST VLAN: live, no reboot ----------------------------- */
$r = mw_drive('interfaces_vlan.php', array('del_3_x' => '17'), vlancfg());
is_same('vlan delete (last): the entry is gone', count($r['config']['vlans']['vlan']), 3);
is_false('vlan delete (last): NO reboot is demanded', $r['flag']);
is_same('vlan delete (last): nothing is renumbered -- OPT1 keeps vlan2',
        $r['config']['interfaces']['opt1']['if'], 'vlan2');
is_same('vlan delete (last): the surviving tags are unchanged',
        array_column($r['config']['vlans']['vlan'], 'tag'), array('10', '20', '30'));

/* On the build host no vlan interface exists, so interface_is_present() is
   false and there is nothing to destroy -- which is itself a case worth
   asserting: the config and the running system already agree, so still no
   reboot. The ifconfig command line itself is asserted below, by calling
   interfaces_vlan_destroy_if() directly. */
is_true ('vlan delete (last): nothing is destroyed that is not there',
         $r['cmds'] === array());

/* --- delete from the MIDDLE: renumbered, reboot ------------------------ */
$r = mw_drive('interfaces_vlan.php', array('del_1_x' => '17'), vlancfg());
is_same('vlan delete (middle): the entry is gone', count($r['config']['vlans']['vlan']), 3);
is_true ('vlan delete (middle): a reboot IS demanded', $r['flag']);
is_same('vlan delete (middle): the assignment above it is renumbered, vlan2 -> vlan1',
        $r['config']['interfaces']['opt1']['if'], 'vlan1');
is_same('vlan delete (middle): and nothing is destroyed live', $r['cmds'], array());

/* --- still refused while assigned, even past a hole in the OPTs --------
 *
 * vlan_inuse() walks the OPTs with opt_interfaces(), so the OPT above the gap
 * is checked. A counting loop stopped at opt1 and let this delete through --
 * the VLAN went away while OPT3 was still assigned to it. */
$c = vlancfg();
$c['interfaces']['opt3']['if'] = 'vlan3';
$r = mw_drive('interfaces_vlan.php', array('del_3_x' => '17'), $c);
is_true ('vlan delete: an assigned VLAN is refused, naming the interface',
         strpos($r['out'], 'still assigned to OPT3') !== false);
is_same('vlan delete: the refused entry is still there',
        count($r['config']['vlans']['vlan']), 4);
is_false('vlan delete: a refusal demands no reboot and destroys nothing',
         $r['flag'] || $r['cmds'] !== array());

/* --- a reboot already pending: saved, but not applied ------------------
 *
 * The live vlanN names no longer match the config positions, so vlan3 may be an
 * interface carrying somebody else's tag. Same gate as the add path. */
$r = mw_drive('interfaces_vlan.php', array('del_3_x' => '17'), vlancfg(),
              array('rebootpending' => true));
is_same('vlan delete with a reboot pending: still saved',
        count($r['config']['vlans']['vlan']), 3);
is_true ('vlan delete with a reboot pending: the flag stays set', $r['flag']);
is_same('vlan delete with a reboot pending: nothing is destroyed', $r['cmds'], array());

/* --- a number that is not there ---------------------------------------- */
$r = mw_drive('interfaces_vlan.php', array('del_9_x' => '17'), vlancfg());
is_true ('vlan delete: a number that does not exist is refused',
         strpos($r['out'], 'no VLAN to delete') !== false);
is_same('vlan delete: and nothing is deleted', count($r['config']['vlans']['vlan']), 4);
is_false('vlan delete: nor is a reboot demanded for it -- which used to put the ' .
         'whole webGUI into save-only mode over a no-op', $r['flag']);

/* --- the redirect tokens the delete now comes back with ---------------
 *
 * A delete that is applied live has an outcome to report, exactly as an add
 * does, so it redirects with a token. Looked up in a fixed map rather than
 * echoed, so nothing out of the query string reaches the page. */
$r = mw_drive('interfaces_vlan.php', array(), vlancfg(), array('get' => array('status' => 'deleted')));
is_true ('the "deleted" token says the interface was destroyed and no reboot is needed',
         strpos($r['out'], 'its interface destroyed') !== false &&
         strpos($r['out'], 'no reboot is required') !== false);
$r = mw_drive('interfaces_vlan.php', array(), vlancfg(), array('get' => array('status' => 'delfailed')));
is_true ('the "delfailed" token says it is still tagging until a reboot',
         strpos($r['out'], 'could not be destroyed') !== false);
$r = mw_drive('interfaces_vlan.php', array(), vlancfg(), array('get' => array('status' => 'made-up')));
is_false('an unknown token prints nothing at all',
         strpos($r['out'], 'INFO:') !== false);
is_same('and no token produces no diagnostics either', mw_diags($r['out']), array());

/* --- the destroy command line ----------------------------------------- */
$r = mw_drive('interfaces_vlan.php', array(), vlancfg(),
              array('fn' => 'interfaces_vlan_destroy_if', 'arg' => '3'));
is_same('the destroy runs exactly one ifconfig, named by position',
        $r['cmds'], array('/sbin/ifconfig vlan3 destroy'));
is_same('and its exit status is passed back to the caller', $r['fnout'], '0');

/* the name comes from an array index and goes into a command line unquoted */
$r = mw_drive('interfaces_vlan.php', array(), vlancfg(),
              array('fn' => 'interfaces_vlan_destroy_if', 'arg' => '3; /sbin/reboot'));
is_same('the position is cast to an integer before it reaches the shell',
        $r['cmds'], array('/sbin/ifconfig vlan3 destroy'));

/* a failed destroy must be reported, not swallowed */
$r = mw_drive('interfaces_vlan.php', array(), vlancfg(),
              array('fn' => 'interfaces_vlan_destroy_if', 'arg' => '3', 'rc' => 1));
is_same('a failed destroy returns the ifconfig status', $r['fnout'], '1');

exit(mw_report('optiface'));
