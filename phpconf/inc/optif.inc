<?php
/*
	optif.inc
	Optional interfaces: enumerating them, and deleting one.

	part of m0n0wall (https://m0n0.ch/wall)

	A file of its own rather than part of util.inc, for two reasons.

	It has more than one caller that must agree. Both the webGUI
	(interfaces_assign.php) and the console wizard (rc.initial.setports) can
	delete an optional interface, and a delete that forgets the configuration
	belonging to that interface is the bug this whole file exists to prevent --
	so there is exactly one implementation of it, not one per entry point.

	And it can be loaded on its own, which is what lets the test suite exercise
	the real code: util.inc as a whole cannot be loaded off-target, because its
	mwexec() runs real commands. The alternative was a hand-copied double in the
	tests, which would drift from the shipping code the first time either half
	changed.

	util.inc require_once()s this file, so every page and script that has
	util.inc has all of it. opt_iface_delete() calls croen_update_job() from
	scheduler.inc, which functions.inc loads -- at call time, not load time, so
	the early util.inc include chain is unaffected.
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

/* ---------------------------------------------------------------------------
 * OPTn is a stable identifier.
 *
 * Deleting an optional interface used to CLOSE THE HOLE: opt3 was shifted down
 * into opt2, opt4 into opt3, and so on. Only $config['interfaces'] was shifted,
 * so every other reference to the name stayed where it was and quietly changed
 * meaning. $config['dhcpd']['opt1'] went on handing out the range configured
 * for the interface that had just been deleted -- now on whichever interface
 * moved into its place -- while $config['dhcpd']['opt2'] was orphaned; and a
 * filter rule naming opt2 stopped matching anything at all, because
 * pf_rule_interface() found no such interface and the rule was dropped from the
 * ruleset without a word.
 *
 * Nothing shifts now. optN belongs to its interface for as long as that
 * interface exists, which is what makes every reference to optN -- from any
 * section, written by any page -- still correct afterwards. It is also what
 * makes opt_iface_references() below answerable at all: under the shift-down,
 * every name above the one being deleted was about to mean a different
 * interface, so there was no honest answer to "what still refers to this?".
 *
 * The numbering simply acquires gaps (OPT1, OPT3). Nothing in the tree requires
 * it to be contiguous -- every enumeration goes through opt_interfaces(), which
 * preserves gaps -- and an add takes the LOWEST free number, so a freed slot
 * comes back rather than the numbering climbing for ever.
 * ------------------------------------------------------------------------ */

/* Does $val name $optif?
 *
 * Guarded rather than compared directly: these values come out of config.xml,
 * where a hand-edited or half-written entry can be an array, an integer or
 * absent, and only a string can be an interface name. */
function opt_iface_isref($val, $optif) {
	return is_string($val) && $val === $optif;
}

/* Everything OUTSIDE $config['interfaces'] that still names $optif, as a list
 * of places an admin can go and fix, so that a refusal can say where.
 *
 * There are two kinds of reference to an interface name, and they need opposite
 * treatment:
 *
 *   - a config section KEYED BY the name -- $config['dhcpd']['opt3'],
 *     $config['dhcrelay']['opt3'] -- describes that one interface and means
 *     nothing without it, so a delete takes it along. Those are NOT listed
 *     here; see opt_iface_delete().
 *
 *   - a name stored as a rule VALUE -- a filter rule's ['interface'], a shaper
 *     rule's source ['network'], a bridge -- is the admin's intent, and there
 *     is no way to guess what they would want instead. Those are what this
 *     function finds, so the delete can refuse.
 */
function opt_iface_references($optif) {
	global $config;

	$refs = array();

	/* Rule lists whose entries name an interface: ['interface'] in all of them,
	   and filter, shaper and advanced outbound NAT additionally accept an
	   interface name as a source or destination ['network'] (the $specialnets
	   entries built in guiconfig.inc). A path a given config does not have is
	   skipped, so this is safe on a minimal or a partially restored config. */
	$lists = array(
		array(array('filter', 'rule'),                  "Firewall: Rules"),
		array(array('filter', 'rule6'),                 "Firewall: Rules, IPv6"),
		array(array('shaper', 'rule'),                  "Firewall: Traffic shaper"),
		array(array('nat', 'rule'),                     "Firewall: NAT, inbound"),
		array(array('nat', 'onetoone'),                 "Firewall: NAT, 1:1"),
		array(array('nat', 'advancedoutbound', 'rule'), "Firewall: NAT, outbound"),
		array(array('staticroutes', 'route'),           "System: Static routes"),
		array(array('staticroutes', 'route6'),          "System: Static routes, IPv6"),
		array(array('proxyarp', 'proxyarpnet'),         "Services: Proxy ARP"),
		array(array('wol', 'wolentry'),                 "Services: Wake on LAN"),
		array(array('ipsec', 'tunnel'),                 "VPN: IPsec"),
	);

	foreach ($lists as $l) {
		$list = $config;
		foreach ($l[0] as $key) {
			if (!is_array($list) || !isset($list[$key])) {
				$list = null;
				break;
			}
			$list = $list[$key];
		}
		if (!is_array($list))
			continue;

		foreach ($list as $k => $ent) {
			if (!is_array($ent))
				continue;
			/* ['local-subnet']['network'] is the IPsec case, and it is the
			   ORDINARY shape rather than an exotic one: a tunnel's ['interface']
			   is the OUTSIDE interface and defaults to wan, so "tunnel over WAN
			   carrying the OPT2 network" names opt2 only here. Left dangling,
			   ipsec_ss_local_ts() returns null, ipsec_strongswan.inc omits the
			   local_ts line entirely and swanctl silently substitutes its own
			   default -- and once the number is reused the tunnel offers the NEW
			   interface's subnet to the remote peer. */
			if (!opt_iface_isref($ent['interface'] ?? null, $optif) &&
			    !opt_iface_isref($ent['source']['network'] ?? null, $optif) &&
			    !opt_iface_isref($ent['destination']['network'] ?? null, $optif) &&
			    !opt_iface_isref($ent['local-subnet']['network'] ?? null, $optif))
				continue;

			/* $k is the id in that page's own edit link, so the admin can go
			   straight to the entry rather than hunt for it. */
			$where = $l[1] . " (id " . $k;
			if (!empty($ent['descr']) && is_string($ent['descr']))
				$where .= ", \"" . $ent['descr'] . "\"";
			$refs[] = $where . ")";
		}
	}

	if (opt_iface_isref($config['captiveportal']['interface'] ?? null, $optif))
		$refs[] = "Services: Captive portal";

	/* A bridge is recorded on the OTHER interface, as the name of the one it is
	   bridged to. Delete the target and that interface is bridged to nothing:
	   filter.inc and filter_pf.inc then read an address and a subnet out of an
	   interface that is not there, and its DHCP check looks up
	   $config['dhcpd'][<the missing name>]. */
	if (is_array($config['interfaces'] ?? null)) {
		foreach ($config['interfaces'] as $ifn => $ifcfg) {
			if (is_array($ifcfg) && opt_iface_isref($ifcfg['bridge'] ?? null, $optif))
				$refs[] = "Interfaces: " . strtoupper($ifn) . ", which is bridged to it";
		}
	}

	return $refs;
}

/* Delete $optif, and the configuration that belonged to it.
 *
 * ONLY $optif: no other interface's key is touched. That is the change -- see
 * the note at the top of this block.
 *
 * What goes with it is every section KEYED BY the interface name, because such
 * a section describes that interface and nothing else. Leaving one behind is
 * how the old shift-down came to serve one interface's DHCP range on another,
 * and leaving one behind now would be just as wrong for a different reason: the
 * number is reused by the next add, so an orphaned $config['dhcpd']['opt2']
 * would silently attach itself to a completely unrelated interface.
 *
 * The sections keyed by an interface name are $config['dhcpd'] and
 * $config['dhcrelay']. Both were found by grepping the tree for
 * $config[<section>][<an interface name>]; those are the only two. Both also
 * hold non-interface keys at the same level -- $config['dhcrelay']['server'],
 * ['proxydhcp'], ['agentoption'] -- which is why this unsets the one key rather
 * than filtering the section. Everything else that can name an interface stores
 * it as a VALUE and is the admin's to change, not ours to rewrite: see
 * opt_iface_references(), and the refusal in the input validation below.
 */
function opt_iface_delete($optif) {
	global $config;

	unset($config['interfaces'][$optif]);

	/* DHCP server and DHCP relay for this interface: its address range, its
	   lease times, its WINS/DNS servers and its static mappings. */
	unset($config['dhcpd'][$optif]);
	unset($config['dhcrelay'][$optif]);

	/* Secondary (alias) addresses. These belong to the interface just as
	   surely as its DHCP range does, but they are NOT keyed by the name --
	   they are a flat list whose entries carry the name in ['if'], which in
	   THIS section holds an interface name and not a device name, unlike
	   every other ['if'] in the config.
	   
	   Left behind they are worse than an orphan, because there is no route to
	   them: interfaces_secondaries.php lists them per interface, and the only
	   link to it is on interfaces_opt.php, which shows "there is no OPTn
	   interface" once the interface is gone. So the admin can neither see nor
	   remove them -- and interfaces_secondaries_configure() matches purely on
	   the name, so as soon as opt_next_free() hands the number to a new
	   interface, that interface silently comes up with the deleted one's alias
	   addresses, and filter.inc emits pass rules for their subnets. */
	if (is_array($config['secondaries']['secondary'] ?? null)) {
		$keep = array();
		foreach ($config['secondaries']['secondary'] as $sec) {
			if (is_array($sec) && opt_iface_isref($sec['if'] ?? null, $optif))
				continue;
			$keep[] = $sec;
		}
		if (count($keep))
			$config['secondaries']['secondary'] = $keep;
		else
			unset($config['secondaries']['secondary']);
	}

	/* Scheduler: any enable/disable job whose target was this interface. Left
	   behind, such a job fires at its next scheduled time against a name that
	   no longer exists -- or, once the number has been reused, against an
	   entirely different interface. */
	/* function_exists(): this is also called from convert_config(), and while
	   rc.bootup does load functions.inc before calling it, a future caller
	   earlier in the include chain would otherwise take the boot down with a
	   fatal instead of skipping a cleanup that a pre-scheduler config cannot
	   have needed anyway. */
	if (function_exists('croen_update_job'))
		croen_update_job(Array('interface-enable', 'interface-disable'), $optif);
}

/* Which optional interface should get which port, for the console "Assign
 * interfaces" wizard (phpconf/rc.initial.setports).
 *
 * $ports is the list of device names the admin typed, in the order they typed
 * them. Returns array('map' => array(optname => device), 'surplus' => list of
 * optnames that were not given a port and are therefore to be deleted).
 *
 * The ports go to the optional interfaces that ALREADY EXIST, taken in number
 * order, so each one keeps its own name -- and with it its DHCP section, its
 * firewall and shaper rules, its secondary addresses and its scheduler jobs.
 *
 * The wizard used to write opt1..optN straight from the order the ports were
 * entered. That renamed the interfaces underneath everything that referred to
 * them: with opt1=DMZ and opt2=GUEST, entering GUEST's port first made GUEST
 * opt1, so it inherited the DMZ's DHCP range and every rule written for the
 * DMZ, while its own were left pointing at an opt2 that no longer existed. It
 * is the same misassignment described at the top of this file.
 *
 * Surplus ports become new interfaces at the lowest free number, matching what
 * an add does in the webGUI. Fewer ports than interfaces means the extra
 * interfaces are deleted, and the caller does that through opt_iface_delete()
 * so their dependent configuration goes with them.
 *
 * Here rather than in the wizard so it can be tested: the wizard itself reads
 * from the console and reboots the machine.
 */
function opt_assign_map($ports) {
	$existing = array_values(opt_interfaces());	/* in NUMBER order */
	$usednums = array_keys(opt_interfaces());
	$map      = array();

	for ($i = 0; $i < count($ports); $i++) {
		if (isset($existing[$i])) {
			$map[$existing[$i]] = $ports[$i];
			continue;
		}
		/* the lowest number neither in use nor already claimed just above */
		for ($n = 1; in_array($n, $usednums); $n++)
			;
		$usednums[] = $n;
		$map['opt' . $n] = $ports[$i];
	}

	return array('map' => $map, 'surplus' => array_slice($existing, count($ports)));
}

?>