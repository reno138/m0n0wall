<?php
/*
	optif.inc
	Optional-interface enumeration.

	part of m0n0wall (https://m0n0.ch/wall)

	These two helpers live in a file of their own, apart from the rest of
	util.inc, for one reason: they are pure functions of $config, so the test
	suite can load them directly. util.inc as a whole cannot be loaded off-target
	-- its mwexec() runs real commands -- and the alternative was a hand-copied
	double in the tests that would drift from the shipping code the first time
	either function changed.

	util.inc require_once()s this file, so every page that has util.inc has these.
*/

/* The optional interfaces that actually exist, as number => config key.
 *
 * Returns e.g. array(1 => 'opt1', 3 => 'opt3') -- ordered by number, and with
 * GAPS PRESERVED. Both halves are what callers need: the number for a display
 * label ("OPT3"), an ?index= link and the interfaces_optional_configure_if()
 * family, and the key for $config['interfaces'][...].
 *
 * Why this exists. Fifty-odd sites across thirty-two files each rolled their own
 *
 *     for ($i = 1; isset($config['interfaces']['opt' . $i]); $i++)
 *
 * which stops dead at the first missing number. That was survivable only because
 * interfaces_assign.php closes the hole on delete by shifting opt3 down to opt2
 * -- and THAT is the renumbering that silently misassigns everything referring to
 * an interface by name. $config['dhcpd']['opt1'] is not shifted with it, so the
 * DHCP range configured for the deleted interface starts serving whichever
 * interface moved into its place, and a firewall rule naming opt3 stops matching
 * anything because opt3 no longer exists.
 *
 * The fix is to stop renumbering, which makes optN a stable identifier for the
 * life of the interface and leaves every reference to it correct. This helper is
 * the prerequisite: with gaps tolerated everywhere, closing them is no longer
 * necessary. It also removes a latent bug of its own -- a hand-edited or
 * partially restored config with a hole already defeated every one of those
 * loops, including the in-use checks that guard a VLAN delete.
 *
 * Deliberately NOT cached: callers mutate $config['interfaces'] and then
 * re-enumerate.
 */
function opt_interfaces() {
	global $config;

	$out = array();
	if (!isset($config['interfaces']) || !is_array($config['interfaces']))
		return $out;

	foreach ($config['interfaces'] as $key => $ifcfg) {
		if (!is_array($ifcfg))
			continue;
		if (!preg_match('/^opt(\d+)$/', $key, $m))
			continue;
		$out[(int) $m[1]] = $key;
	}
	ksort($out, SORT_NUMERIC);

	return $out;
}

/* The next free optional interface number.
 *
 * With gaps preserved this is no longer "count + 1": it is the lowest number not
 * in use, so a delete-then-add reuses the freed slot rather than climbing for
 * ever. interfaces_assign.php already looked for the first free number this way;
 * this puts it in one place.
 */
function opt_next_free() {
	$used = opt_interfaces();
	for ($i = 1; $i < 1000; $i++)
		if (!isset($used[$i]))
			return $i;
	return 0;               /* absurd, and the caller should refuse */
}

?>