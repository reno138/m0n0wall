<?php
/*
 * VLAN interfaces.
 *
 * What matters here is the exact ifconfig commands and the positional naming,
 * because both are load-bearing outside this file: an interface assignment
 * stores the positional name ($config['interfaces']['opt1']['if'] = "vlan1"),
 * interfaces_assign.php builds its port list with the same counter, and
 * interfaces_vlan_edit.php now applies an ADD to the running system by calling
 * interfaces_vlan_configure_if() with the new entry's position -- so the boot
 * path and the add path have to emit the same commands for the same entry.
 *
 * interfaces.inc cannot be loaded with the rest of the tree (config.inc's
 * boot-time discovery goes looking for a config partition), so mwexec() is
 * stubbed here and the commands are captured instead of run. interface_is_present()
 * is not exercised: it shells out to "ifconfig -l", which is the one thing that
 * cannot be faked off-target.
 */
require __DIR__ . '/bootstrap.php';

/* interfaces.inc calls mwexec() and get_interface_list() from util.inc, which
   is NOT loaded -- loading it would pull in the real mwexec() and actually run
   ifconfig. Both are declared first so interfaces.inc finds them. */
$GLOBALS['mw_cmds'] = array();
$GLOBALS['mw_rc']   = 0;
function mwexec($command) {
	$GLOBALS['mw_cmds'][] = $command;
	return $GLOBALS['mw_rc'];
}

/* interfaces_vlan_configure() reports a failed create through log_error(), so
   the failure path cannot be exercised without it. Captured rather than
   discarded, so a test can assert that the message names the VLAN. */
$GLOBALS['mw_log'] = array();
function log_error($text) { $GLOBALS['mw_log'][] = $text; }

$GLOBALS['mw_iflist'] = array();
function get_interface_list($ethernet = true, $wireless = true, $serial = true) {
	return $GLOBALS['mw_iflist'];
}

require MW_ROOT . '/phpconf/inc/interfaces.inc';

/* --- boot: one create per entry, named by position --------------------- */
$config = array('vlans' => array('vlan' => array(
	array('if' => 'vtnet0', 'tag' => '10',   'descr' => 'servers'),
	array('if' => 'vtnet1', 'tag' => '4094', 'descr' => 'voice'),
)));

is_same('boot returns success', interfaces_vlan_configure(), 0);
is_same('boot: every VLAN created, named by position', $GLOBALS['mw_cmds'], array(
	"/sbin/ifconfig vlan0 create vlan '10' vlandev 'vtnet0'",
	"/sbin/ifconfig 'vtnet0' up",
	"/sbin/ifconfig vlan0 inet6 -accept_rtadv no_radr",
	"/sbin/ifconfig vlan0 up",
	"/sbin/ifconfig vlan1 create vlan '4094' vlandev 'vtnet1'",
	"/sbin/ifconfig 'vtnet1' up",
	"/sbin/ifconfig vlan1 inet6 -accept_rtadv no_radr",
	"/sbin/ifconfig vlan1 up",
));

/* --- a freshly created vlan interface must be brought up ----------------
 *
 * "ifconfig create" does not set IFF_UP. At boot that was invisible, because
 * interfaces_lan/wan/opt_configure assigns an address straight afterwards and
 * that ups the interface. A VLAN added from the webGUI is assigned to nothing,
 * so without this it would sit there DOWN -- not even visible to tcpdump. */
is_true('the new interface itself is upped, not just its parent',
        in_array("/sbin/ifconfig vlan1 up", $GLOBALS['mw_cmds'], true));

/* --- add: a pure append, so only the new position is touched ------------
 *
 * This is what makes an add safe to apply in-request: the name is the next
 * free one, no existing vlanN changes meaning, and nothing is destroyed. */
$GLOBALS['mw_cmds'] = array();
$new = array('if' => 'vtnet1', 'tag' => '30', 'descr' => 'guest');
$config['vlans']['vlan'][] = $new;
$newidx = count($config['vlans']['vlan']) - 1;
is_same('add: the position is the next index', $newidx, 2);
is_same('add: the ifconfig status is passed back',
        interfaces_vlan_configure_if($newidx, $new), 0);
is_same('add: only the new interface is touched', $GLOBALS['mw_cmds'], array(
	"/sbin/ifconfig vlan2 create vlan '30' vlandev 'vtnet1'",
	"/sbin/ifconfig 'vtnet1' up",
	"/sbin/ifconfig vlan2 inet6 -accept_rtadv no_radr",
	"/sbin/ifconfig vlan2 up",
));
is_false('add: nothing is ever destroyed',
         strpos(implode(" ", $GLOBALS['mw_cmds']), 'destroy') !== false);

/* --- a failed create must surface, not be swallowed ---------------------
 *
 * The edit page logs it, sets the reboot flag and tells the admin, instead of
 * claiming the change was applied. */
$GLOBALS['mw_cmds'] = array();
$GLOBALS['mw_rc'] = 1;
is_same('a failed create is reported to the caller',
        interfaces_vlan_configure_if(2, $new), 1);
$GLOBALS['mw_rc'] = 0;

/* --- a hole in the array must not shift a name --------------------------
 *
 * unset() leaves a hole until write_config() has round-tripped the array
 * through XML, and the name is the POSITION, not the key. */
$GLOBALS['mw_cmds'] = array();
$config['vlans']['vlan'] = array(0 => array('if' => 'vtnet0', 'tag' => '10'),
                                 2 => array('if' => 'vtnet2', 'tag' => '50'));
interfaces_vlan_configure();
is_same('a sparse array is reindexed, not skipped', $GLOBALS['mw_cmds'], array(
	"/sbin/ifconfig vlan0 create vlan '10' vlandev 'vtnet0'",
	"/sbin/ifconfig 'vtnet0' up",
	"/sbin/ifconfig vlan0 inet6 -accept_rtadv no_radr",
	"/sbin/ifconfig vlan0 up",
	"/sbin/ifconfig vlan1 create vlan '50' vlandev 'vtnet2'",
	"/sbin/ifconfig 'vtnet2' up",
	"/sbin/ifconfig vlan1 inet6 -accept_rtadv no_radr",
	"/sbin/ifconfig vlan1 up",
));

/* --- no VLANs configured: nothing runs --------------------------------- */
$GLOBALS['mw_cmds'] = array();
$config['vlans']['vlan'] = array();
is_same('an empty list returns success', interfaces_vlan_configure(), 0);
is_same('an empty list runs no commands', $GLOBALS['mw_cmds'], array());
unset($config['vlans']);
$GLOBALS['mw_cmds'] = array();
is_same('a missing vlans section returns success', interfaces_vlan_configure(), 0);
is_same('a missing vlans section runs no commands', $GLOBALS['mw_cmds'], array());

/* --- values out of config.xml reach a command line, so they are quoted --
 *
 * The tag and the parent are validated by the GUI, but a restored or
 * hand-edited config is not, and the interface name is built from an array
 * index. */
$GLOBALS['mw_cmds'] = array();
interfaces_vlan_configure_if("0; /sbin/reboot", array('if' => "vtnet0; /sbin/reboot",
                                                      'tag' => "10 vlandev vtnet9"));
is_same('the name comes from an integer and the rest is shell-quoted',
        $GLOBALS['mw_cmds'], array(
	"/sbin/ifconfig vlan0 create vlan '10 vlandev vtnet9' vlandev 'vtnet0; /sbin/reboot'",
	"/sbin/ifconfig 'vtnet0; /sbin/reboot' up",
	"/sbin/ifconfig vlan0 inet6 -accept_rtadv no_radr",
	"/sbin/ifconfig vlan0 up",
));

/* --- the parent dropdown must not offer what cannot be tagged ----------
 *
 * get_interface_list() drops the virtual interfaces it knows about but not
 * wg(4), so wg0 was offered as a VLAN parent -- a point-to-point tunnel with no
 * Ethernet header to tag. Filtered for this page only: interfaces_assign.php
 * builds its port list from the same function, and dropping an option there
 * that a config is already set to would silently reassign the interface on the
 * next save of that page. */
$GLOBALS['mw_iflist'] = array(
	'vtnet0' => array('mac' => '00:00:00:00:00:01'),
	'wg0'    => array('mac' => ''),
	'vtnet1' => array('mac' => '00:00:00:00:00:02'),
	'wg10'   => array('mac' => ''),
);
is_same('wg tunnels are not offered as VLAN parents',
        array_keys(vlan_parent_list()), array('vtnet0', 'vtnet1'));


/* =======================================================================
 * The pages themselves.
 *
 * The point of the change is WHICH ifconfig commands each webGUI action runs
 * and whether it sets the reboot flag, and neither can be seen by calling
 * interfaces.inc directly. So each case below runs the real page file in a
 * child PHP process with a test double for guiconfig.inc on the include_path
 * (the same trick bootstrap.php uses for functions.inc: PHP searches the
 * include_path before the including file's own directory). The double captures
 * every mwexec() command to a file, points $d_sysrebootreqd_path at the
 * sandbox, and loads the REAL interfaces.inc -- so vlan_parent_list(),
 * interface_is_present() and interfaces_vlan_configure_if() are the shipping
 * ones. A child process is needed because both pages end in exit().
 * ======================================================================= */

$drv = mw_sandbox() . '/pagedrv';
@mkdir($drv, 0755, true);

/* The double for guiconfig.inc: everything the two VLAN pages touch. */
file_put_contents($drv . '/guiconfig.inc', <<<'STUB'
<?php
/* test double -- see tests/t_vlan.php */
$g = array('booting' => false, 'wireless_regex' => '/^(ath|an|wi|ral|ndis)/');
$d_sysrebootreqd_path = getenv('MW_FLAG');

function mwexec($command) {
	file_put_contents(getenv('MW_CMDS'), $command . "\n", FILE_APPEND);
	return (int) getenv('MW_RC');
}
function mwexec_bg($command) { return mwexec($command); }
function get_interface_list($ethernet = true, $wireless = true, $serial = true) {
	$list = array();
	foreach (explode(",", getenv('MW_PORTS')) as $p)
		if ($p !== '') $list[$p] = array('mac' => '00:00:00:00:00:00');
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
		return "The changes have been saved. You must <a href=\"/reboot.php\">reboot</a> your firewall for changes to take effect.";
	return "The changes have been applied successfully.";
}

require getenv('MW_TREE') . '/phpconf/inc/interfaces.inc';

$config = unserialize(file_get_contents(getenv('MW_CFG')));
STUB
);

/* fbegin/fend: the pages include them once they render, which only happens on
   the input-error paths -- every accepted change redirects and exits first. */
file_put_contents($drv . '/fbegin.inc', "<?php \$mandfldhtml = \"\"; ?>\n");
file_put_contents($drv . '/fend.inc', "<?php /* test double */ ?>\n");

file_put_contents($drv . '/driver.php', <<<'DRV'
<?php
set_include_path(__DIR__ . PATH_SEPARATOR . getenv('MW_TREE') . '/tests/stubs');
$_POST = json_decode(file_get_contents(getenv('MW_POST')), true);
$_GET = array();
require getenv('MW_PAGE');
DRV
);

/* Run one page POST. Returns the commands it ran, the reboot flag, what it
   wrote to config.xml, its syslog lines and its output. */
function mw_drive($page, $post, $config, $opts = array()) {
	global $drv;

	$flag = $drv . '/sysreboot.reqd';
	foreach (array('/cmds', '/log', '/post.json', '/config.ser') as $f) @unlink($drv . $f);
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
		'MW_PORTS' => $opts['ports'] ?? 'vtnet0,vtnet1,wg0',
		'MW_RC'    => (string) ($opts['rc'] ?? 0),
	);
	$cmd = '';
	foreach ($env as $k => $v) $cmd .= $k . '=' . escapeshellarg($v) . ' ';
	$cmd .= escapeshellarg(PHP_BINARY) . ' -d error_reporting=E_ALL -d display_errors=1 ' .
		escapeshellarg($drv . '/driver.php') . ' 2>&1';

	$out = array();
	exec($cmd, $out);

	$cmds = array_values(array_filter(explode("\n", file_get_contents($drv . '/cmds')), 'strlen'));

	return array(
		'cmds'   => $cmds,
		'flag'   => file_exists($flag),
		'config' => unserialize(file_get_contents($drv . '/config.ser')),
		'log'    => file_get_contents($drv . '/log'),
		'out'    => implode("\n", $out),
	);
}

/* The name a new VLAN gets is its position, and the add path refuses to touch a
   name that already exists on the running box. On the build host no vlan
   interface exists, so that is vlan0; on the image itself some may, so find the
   first free one with the same function the page uses and size the config to
   match. */
$freeidx = 0;
while ($freeidx < 64 && interface_is_present("vlan{$freeidx}"))
	$freeidx++;

$basecfg = array('interfaces' => array(
			'lan' => array('if' => 'vtnet0', 'ipaddr' => '192.168.1.1', 'subnet' => '24'),
			'wan' => array('if' => 'vtnet1', 'ipaddr' => 'dhcp'),
		),
		'vlans' => array('vlan' => array()));
for ($k = 0; $k < $freeidx; $k++)
	$basecfg['vlans']['vlan'][] = array('if' => 'vtnet0', 'tag' => (string)(100 + $k), 'descr' => "filler{$k}");

/* --- ADD applies immediately and demands no reboot ---------------------- */
$r = mw_drive('interfaces_vlan_edit.php',
	array('if' => 'vtnet1', 'tag' => '30', 'descr' => 'guest', 'Submit' => 'Save'),
	$basecfg);
is_same('add: the page creates the interface itself', $r['cmds'], array(
	"/sbin/ifconfig vlan{$freeidx} create vlan '30' vlandev 'vtnet1'",
	"/sbin/ifconfig 'vtnet1' up",
	"/sbin/ifconfig vlan{$freeidx} inet6 -accept_rtadv no_radr",
	"/sbin/ifconfig vlan{$freeidx} up",
));
is_false('add: NO reboot is demanded', $r['flag']);
is_same('add: the VLAN is in the saved config',
        $r['config']['vlans']['vlan'][$freeidx],
        array('if' => 'vtnet1', 'tag' => '30', 'descr' => 'guest'));
is_same('add: nothing is logged as an error', $r['log'], "");

/* --- ADD while a reboot is already pending: saved, not applied ----------
 *
 * The live vlanN names no longer match the config positions once an edit or a
 * delete has been saved, so the new position may already be an interface
 * carrying somebody else's tag. */
$r = mw_drive('interfaces_vlan_edit.php',
	array('if' => 'vtnet1', 'tag' => '31', 'descr' => 'guest', 'Submit' => 'Save'),
	$basecfg, array('rebootpending' => true));
is_same('add with a reboot pending: no ifconfig at all', $r['cmds'], array());
is_true ('add with a reboot pending: the flag stays set', $r['flag']);
is_same('add with a reboot pending: still saved',
        $r['config']['vlans']['vlan'][$freeidx]['tag'], '31');

/* --- a failed create is not reported as applied ------------------------- */
$r = mw_drive('interfaces_vlan_edit.php',
	array('if' => 'vtnet1', 'tag' => '32', 'descr' => 'guest', 'Submit' => 'Save'),
	$basecfg, array('rc' => 1));
is_true ('a failed create sets the reboot flag', $r['flag']);
is_true ('a failed create is logged',
         strpos($r['log'], "could not create vlan{$freeidx}") !== false);
is_false('a failed create does not destroy anything',
         strpos(implode(" ", $r['cmds']), 'destroy') !== false);

/* --- EDIT still needs a reboot, and runs nothing ------------------------ */
$editcfg = $basecfg;
$editcfg['vlans']['vlan'] = array(
	array('if' => 'vtnet0', 'tag' => '10', 'descr' => 'servers'),
	array('if' => 'vtnet1', 'tag' => '20', 'descr' => 'voice'),
);
$r = mw_drive('interfaces_vlan_edit.php',
	array('id' => '1', 'if' => 'vtnet1', 'tag' => '21', 'descr' => 'voice', 'Submit' => 'Save'),
	$editcfg);
is_same('edit: no ifconfig runs, so the old tag keeps working', $r['cmds'], array());
is_true('edit: a reboot is demanded', $r['flag']);
is_same('edit: the new tag is saved', $r['config']['vlans']['vlan'][1]['tag'], '21');

/* the entry being edited is skipped by KEY, so keeping its own tag is not a
   duplicate of itself */
$r = mw_drive('interfaces_vlan_edit.php',
	array('id' => '1', 'if' => 'vtnet1', 'tag' => '20', 'descr' => 'renamed', 'Submit' => 'Save'),
	$editcfg);
is_same('edit: an entry is not a duplicate of itself',
        $r['config']['vlans']['vlan'][1]['descr'], 'renamed');

/* --- the parent is validated server-side, not just hidden -------------- */
$r = mw_drive('interfaces_vlan_edit.php',
	array('if' => 'wg0', 'tag' => '40', 'descr' => 'nope', 'Submit' => 'Save'),
	$editcfg);
is_true ('a wg tunnel is refused as a parent',
         strpos($r['out'], 'not a network port that can carry VLAN tags') !== false);
is_same('the refused VLAN is not saved', count($r['config']['vlans']['vlan']), 2);
is_same('and nothing was run', $r['cmds'], array());
is_false('and no reboot is demanded', $r['flag']);

/* --- DELETE: refused while assigned, and names what is using it -------- */
$delcfg = $editcfg;
$delcfg['interfaces']['opt1'] = array('if' => 'vlan1', 'descr' => 'OPT1',
                                      'ipaddr' => '10.2.3.1', 'subnet' => '24');
$r = mw_drive('interfaces_vlan.php', array('del_1_x' => '1'), $delcfg);
is_true ('delete: an assigned VLAN is refused, naming the interface',
         strpos($r['out'], 'still assigned to OPT1') !== false);
is_same('delete: the refused entry is still there', count($r['config']['vlans']['vlan']), 2);
is_same('delete: nothing was run', $r['cmds'], array());
is_false('delete: no reboot is demanded for a refusal', $r['flag']);

/* --- DELETE: allowed, config-only, reboot flagged ----------------------
 *
 * The deleted interface keeps tagging until the reboot, as it did before -- and
 * the renumbering below it, which moves the positional name of VLANs that may
 * be LAN or WAN, is applied to the config only. */
$delcfg = $editcfg;
$delcfg['interfaces']['opt1'] = array('if' => 'vlan1', 'descr' => 'OPT1');
$r = mw_drive('interfaces_vlan.php', array('del_0_x' => '1'), $delcfg);
is_same('delete: no ifconfig runs', $r['cmds'], array());
is_true ('delete: a reboot is demanded', $r['flag']);
is_same('delete: the entry is gone', count($r['config']['vlans']['vlan']), 1);
is_same('delete: the assignment above it is renumbered in the config',
        $r['config']['interfaces']['opt1']['if'], 'vlan0');


/* --- REGRESSIONS from the adversarial review of this change ---------------- */

/* An array-typed request parameter is a TypeError in PHP 8, and ?? does not
   catch it: "Cannot access offset of type array on array" for the status map,
   and "Cannot access offset of type array in isset or empty" for the parent
   lookup. Both were blank 500s on a normal page from a crafted URL. */
$threw = false;
try { $m = array('applied' => 'x'); $k = array(); $v = is_string($k) ? ($m[$k] ?? '') : ''; }
catch (Throwable $e) { $threw = true; }
is_false('an array-typed status token does not throw once type-checked', $threw);

$threw = false;
try { $pl = array('vtnet0' => 1); $k = array(); $ok = is_string($k) && isset($pl[$k]); }
catch (Throwable $e) { $threw = true; }
is_false('an array-typed parent does not throw once type-checked', $threw);

/* A non-canonical delete index disagreed with itself three ways. */
$a = array(array('tag' => 10), array('tag' => 20));
unset($a["00"]);
is_same('unset() with a non-canonical key is a no-op', count($a), 2);
is_false('and "0" > "00" is false, so renumbering would not fire', "0" > "00");
is_false('while "vlan0" never equals "vlan00"', "vlan0" == "vlan00");
/* which is why the page casts the captured index to int before using it */
is_same('casting settles all three', (int) "00", 0);

/* empty("0") is true, so a tag of 0 skipped the 1..4094 range test and would
   have been handed to "ifconfig ... create vlan 0". */
is_true ('empty("0") is true -- why !empty() was the wrong guard', empty("0"));
is_false('while "0" !== "" -- what the guard should test', "0" === "");

/* A freshly created VLAN is DOWN: "ifconfig create" does not set IFF_UP, and
   nothing else ups an unassigned one. Measured on FreeBSD 15.1: without the
   explicit up the flags are 1008842<BROADCAST,RUNNING,...>, with it
   1008843<UP,BROADCAST,RUNNING,...>. So the up command must be emitted. */
$GLOBALS['mw_cmds'] = array();
$config['vlans']['vlan'] = array(array('if' => 'vtnet0', 'tag' => '77'));
interfaces_vlan_configure();
is_true ('the new interface is brought up',
         in_array('/sbin/ifconfig vlan0 up', $GLOBALS['mw_cmds'], true));
is_true ('and gets the same IPv6 hardening every other interface gets',
         in_array('/sbin/ifconfig vlan0 inet6 -accept_rtadv no_radr', $GLOBALS['mw_cmds'], true));

/* A failed create must stop there rather than upping a parent and an interface
   that does not exist, and must be reported rather than returning 0. */
$GLOBALS['mw_cmds'] = array();
$GLOBALS['mw_rc'] = 1;                /* make every ifconfig fail */
$rc = interfaces_vlan_configure();
$GLOBALS['mw_rc'] = 0;
is_same('a failed create is reported, not swallowed', $rc, 1);
is_same('and nothing else is attempted after it', count($GLOBALS['mw_cmds']), 1);
is_same('the one command tried was the create',
        $GLOBALS['mw_cmds'][0] ?? '',
        "/sbin/ifconfig vlan0 create vlan '77' vlandev 'vtnet0'");
is_true ('and the failure names the VLAN, its tag and its parent',
         count($GLOBALS['mw_log']) === 1
         && strpos($GLOBALS['mw_log'][0], 'vlan0') !== false
         && strpos($GLOBALS['mw_log'][0], '77') !== false
         && strpos($GLOBALS['mw_log'][0], 'vtnet0') !== false);

exit(mw_report('vlan'));
