#!/usr/local/bin/php
<?php 
/*
	$Id$
	part of m0n0wall (http://m0n0.ch/wall)
	Written by Jim McBeath based on existing m0n0wall files
	
	Copyright (C) 2003-2007 Manuel Kasper <mk@neon1.net>.
	All rights reserved.
	
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:
	
	1. Redistributions of source code must retain the above copyright notice,
	   this list of conditions and the following disclaimer.
	
	2. Redistributions in binary form must reproduce the above copyright
	   notice, this list of conditions and the following disclaimer in the
	   documentation and/or other materials provided with the distribution.
	
	THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
	INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
	AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
	AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
	OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

$pgtitle = array("Interfaces", "Assign network ports");
require("guiconfig.inc");

/*
	In this file, "port" refers to the physical port name,
	while "interface" refers to LAN, WAN, or OPTn.
*/

/* get list without VLAN/WLAN virtual interfaces */
$portlist = get_interface_list(true, false, true);

/* add VLAN interfaces */
if (is_array($config['vlans']['vlan'] ?? null) && count($config['vlans']['vlan'])) {
	$i = 0;
	foreach ($config['vlans']['vlan'] as $vlan) {
		$portlist['vlan' . $i] = $vlan;
		$portlist['vlan' . $i]['isvlan'] = true;
		$i++;
	}
}

/* add WLAN interfaces */
if (is_array($config['wlans']['wlan'] ?? null) && count($config['wlans']['wlan'])) {
	$i = 0;
	foreach ($config['wlans']['wlan'] as $wlan) {
		$portlist['wlan' . $i] = $wlan;
		$portlist['wlan' . $i]['iswlan'] = true;
		$i++;
	}
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
			if (!opt_iface_isref($ent['interface'] ?? null, $optif) &&
			    !opt_iface_isref($ent['source']['network'] ?? null, $optif) &&
			    !opt_iface_isref($ent['destination']['network'] ?? null, $optif))
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

	/* Scheduler: any enable/disable job whose target was this interface. Left
	   behind, such a job fires at its next scheduled time against a name that
	   no longer exists -- or, once the number has been reused, against an
	   entirely different interface. */
	croen_update_job(Array('interface-enable', 'interface-disable'), $optif);
}

if ($_POST) {

	unset($input_errors);

	/* input validation */

	/* Build a list of the port names so we can see how the interfaces map */
	$portifmap = array();
	foreach ($portlist as $portname => $portinfo)
		$portifmap[$portname] = array();

	/* Go through the list of ports selected by the user,
	   build a list of port-to-interface mappings in portifmap */
	foreach ($_POST as $ifname => $ifport) {
		if (($ifname == 'lan') || ($ifname == 'wan') || (substr($ifname, 0, 3) == 'opt'))
			$portifmap[$ifport][] = strtoupper($ifname);
	}

	/* Deliver error message for any port with more than one assignment */
	foreach ($portifmap as $portname => $ifnames) {
		if (count($ifnames) > 1) {
			$errstr = "Port " . $portname .
				" was assigned to " . count($ifnames) .
				" interfaces:";
				
			foreach ($portifmap[$portname] as $ifn)
				$errstr .= " " . $ifn;
			
			$input_errors[] = $errstr;
		}
	}

	/* A delete is validated HERE, before anything is written, and one that would
	   leave a dangling reference is REFUSED rather than warned about.
	   
	   Refused, because the alternative is a configuration that quietly does not
	   mean what it says. An interface name left in a filter rule matches
	   nothing: pf_rule_interface() returns null and the rule is dropped from the
	   generated ruleset, so a block rule stops blocking and a pass rule stops
	   passing, with no error anywhere -- and a warning printed after the fact is
	   read, at best, once. A refusal costs one round trip, names every reference
	   it found, and every one of those is editable in the webGUI; the delete can
	   then be repeated and nothing has been lost. It is also what the sibling
	   page already does: interfaces_vlan.php refuses to delete a VLAN that is
	   still assigned to an interface, and names what is using it.
	   
	   In the validation phase rather than the update phase, so that a refusal
	   abandons the whole save -- the port assignments submitted in the same POST
	   are not applied either, exactly as for any other input error on this
	   page. */
	foreach ($_POST as $pn => $pv) {
		if (!preg_match("/^del_(.+)_x$/", $pn, $matches))
			continue;

		$del_ifname = $matches[1];

		/* LAN and WAN are rendered without a delete button, but a POST is only a
		   POST: the old handler unset whatever name it was handed, so a crafted
		   del_lan_x deleted the LAN interface -- and now that a delete also takes
		   the section keyed by that name with it, it would take the LAN DHCP
		   server along too. Only an OPT key that is really there can be deleted.
		   
		   array_key_exists() rather than is_array(): an empty <opt2/> in a
		   hand-edited config parses to "", and the admin has to be able to delete
		   that. */
		if (!preg_match('/^opt\d+$/', $del_ifname) ||
		    !array_key_exists($del_ifname, $config['interfaces'] ?? array())) {
			$input_errors[] = "There is no optional interface to delete under the name \"" .
				$del_ifname . "\".";
			continue;
		}

		$refs = opt_iface_references($del_ifname);
		if (count($refs)) {
			$input_errors[] = strtoupper($del_ifname) . " cannot be deleted because it " .
				"is still named by: " . implode("; ", $refs) . ". Change or remove " .
				"those first: an interface name left behind in a rule matches " .
				"nothing, and the rule is silently dropped from the ruleset.";
		}
	}

	/* opt_next_free() returns 0 only when every number it is willing to try is
	   taken, which no real configuration reaches -- but adding nothing at all
	   without saying so would be worse than saying so. */
	if (isset($_POST['add_x']) && opt_next_free() < 1)
		$input_errors[] = "No optional interface number is free.";


	if (empty($input_errors)) {
		/* No errors detected, so update the config */
		foreach ($_POST as $ifname => $ifport) {
		
			if (($ifname == 'lan') || ($ifname == 'wan') ||
				(substr($ifname, 0, 3) == 'opt')) {
				
				if (!is_array($ifport)) {
					$config['interfaces'][$ifname]['if'] = $ifport;
					
					/* check for wireless interfaces, set or clear ['wireless'] */
					if (preg_match($g['wireless_regex'], $ifport)) {
						if (!is_array($config['interfaces'][$ifname]['wireless'] ?? null))
							$config['interfaces'][$ifname]['wireless'] = array();
					} else {
						unset($config['interfaces'][$ifname]['wireless']);
					}
					
					/* make sure there is a name for OPTn */
					if (substr($ifname, 0, 3) == 'opt') {
						if (!isset($config['interfaces'][$ifname]['descr']))
							$config['interfaces'][$ifname]['descr'] = strtoupper($ifname);
					}
				}
			} else if (preg_match("/^del_(.+)_x$/", $ifname, $matches)) {
				/* Validated above, so this only ever names an OPT that exists.
				
				   NO renumbering. opt3 stays opt3 when opt2 is deleted, and the
				   hole is deliberate: it is what keeps opt3's DHCP section, the
				   filter and shaper rules naming opt3, a bridge pointing at
				   opt3 and a scheduler job targeting opt3 all still pointing at
				   the same interface they meant before the delete. The shift
				   that used to happen here is the bug, not the tidiness. */
				opt_iface_delete($matches[1]);
			} else if ($ifname == "add_x") {
				/* The LOWEST free number, which is what brings a freed slot
				   back: delete OPT2 out of OPT1..OPT3 and the next add is OPT2
				   again, not OPT4. It is also the only reason the numbering
				   does not grow without bound now that a delete leaves a hole.
				   
				   The same rule the loop that used to sit here applied; it just
				   lives in util.inc now, next to the enumeration helper that
				   has to agree with it. */
				$optnum = opt_next_free();

				$newifname = 'opt' . $optnum;
				$config['interfaces'][$newifname] = array();
				$config['interfaces'][$newifname]['descr'] = "OPT" . $optnum;

				/* Find an unused port for this interface.
				
				   $usedif/$usedcfg, NOT $ifname/$ifdata: this inner loop used to
				   iterate with the same variable name as the enclosing
				   foreach ($_POST as $ifname => $ifport), so on the way out it
				   left $ifname pointing at the last key of
				   $config['interfaces'] for the rest of that iteration. It was
				   harmless only because nothing below read $ifname again -- and
				   the enclosing loop DISPATCHES on $ifname, so it was one added
				   line away from mattering. */
				foreach ($portlist as $portname => $portinfo) {
					$portused = false;
					foreach ($config['interfaces'] as $usedif => $usedcfg) {
						if (($usedcfg['if'] ?? null) == $portname) {
							$portused = true;
							break;
						}
					}
					if (!$portused) {
						$config['interfaces'][$newifname]['if'] = $portname;
						if (preg_match($g['wireless_regex'], $portname))
							$config['interfaces'][$newifname]['wireless'] = array();
						break;
					}
				}
			}
		}
	
		write_config();
		touch($d_sysrebootreqd_path);
	}
}

?>
<?php include("fbegin.inc"); ?>
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
<?php if (file_exists($d_sysrebootreqd_path)) print_info_box(get_std_save_message(0)); ?>
<form action="interfaces_assign.php" method="post" name="iform" id="iform">
<table width="100%" border="0" cellpadding="0" cellspacing="0" summary="tab pane">
  <tr><td class="tabnavtbl">
  <ul id="tabnav">
    <li class="tabact">Interface assignments</li>
    <li class="tabinact"><a href="interfaces_vlan.php">VLANs</a></li>
    <li class="tabinact"><a href="interfaces_wlan.php">WLANs</a></li>
  </ul>
  </td></tr>
  <tr> 
    <td class="tabcont">
                    <table border="0" cellpadding="0" cellspacing="0" summary="content pane">
                      <tr> 
	<td class="listhdrr">Interface</td>
	<td class="listhdr">Network port</td>
	<td class="list">&nbsp;</td>
  </tr>
  <?php
	/* Row order: the named interfaces as the configuration has them, then the
	   OPTs in NUMBER order.
	   
	   Array order is no longer number order. An add takes the lowest free
	   number but is APPENDED to $config['interfaces'], so deleting OPT2 and
	   adding one back leaves the array reading lan, wan, opt1, opt3, opt2. The
	   numbering is allowed to have gaps; the list should still read upwards.
	   
	   Sorted from the config keys rather than from opt_interfaces() on purpose:
	   that helper skips an entry that is not an array, and an empty <opt2/> in a
	   hand-edited config has to stay on this page or there is no way to delete
	   it. */
	$ifrows = array();
	$optrows = array();
	foreach ($config['interfaces'] as $ifname => $iface) {
		if (preg_match('/^opt(\d+)$/', $ifname, $m))
			$optrows[(int) $m[1]] = $ifname;
		else
			$ifrows[] = $ifname;
	}
	ksort($optrows, SORT_NUMERIC);
	$ifrows = array_merge($ifrows, array_values($optrows));
  ?>
  <?php foreach ($ifrows as $ifname):
	$iface = $config['interfaces'][$ifname];
	if (!empty($iface['descr']))
		$ifdescr = $iface['descr'];
	else
		$ifdescr = strtoupper($ifname);
	?>
  <tr> 
	<td class="listlr" valign="middle"><strong><?=$ifdescr;?></strong></td>
	  <td valign="middle" class="listr">
		<select name="<?=$ifname;?>" class="formfld" id="<?=$ifname;?>">
		  <?php foreach ($portlist as $portname => $portinfo): ?>
		  <option value="<?=htmlspecialchars($portname);?>" <?php if ($portname == ($iface['if'] ?? null)) echo "selected";?>> 
		  <?php if (!empty($portinfo['isvlan'])) {
		  			$descr = "VLAN {$portinfo['tag']} on {$portinfo['if']}";
					if (!empty($portinfo['descr']))
						$descr .= " (" . $portinfo['descr'] . ")";
					echo htmlspecialchars($descr);
				  } else if (!empty($portinfo['iswlan'])) {
		  			$descr = "WLAN \"{$portinfo['ssid']}\" on {$portinfo['if']}";
					if (!empty($portinfo['descr']))
						$descr .= " (" . $portinfo['descr'] . ")";
					echo htmlspecialchars($descr);
				  } else {
					if (!empty($portinfo['drvname']))
						echo htmlspecialchars($portname . " (" . $portinfo['drvname'] . ", " . ($portinfo['mac'] ?? '') . ")");
					else
						echo htmlspecialchars($portname . " (" . ($portinfo['mac'] ?? '') . ")");
				  }
		  ?>
		  </option>
		  <?php endforeach; ?>
		</select>
		</td>
		<td valign="middle" class="list"> 
		  <?php if (($ifname != 'lan') && ($ifname != 'wan')): ?>
		  <input name="del_<?=$ifname;?>" type="image" src="x.gif" width="17" height="17" title="delete interface" alt="delete interface" onclick="return confirm('Do you really want to delete this interface?')">
		  <?php endif; ?>
		</td>
  </tr>
  <?php endforeach; ?>
  <?php if (count($config['interfaces']) < count($portlist)): ?>
  <tr>
	<td class="list" colspan="2"></td>
	<td class="list" nowrap>
	<input name="add" type="image" src="plus.gif" width="17" height="17" title="add interface" alt="add interface">
	</td>
  </tr>
  <?php else: ?>
  <tr>
	<td class="list" colspan="3" height="10"></td>
  </tr>
  <?php endif; ?>
</table>
  <input name="Submit" type="submit" class="formbtn" value="Save"><br><br>
<p><span class="vexpl"><strong><span class="red">Warning:</span><br>
</strong>After you click &quot;Save&quot;, you must reboot the firewall to make the changes take effect. You may also have to do one or more of the following steps before you can access your firewall again: </span></p>
<ul>
  <li><span class="vexpl">change the IP address of your computer</span></li>
  <li><span class="vexpl">renew its DHCP lease</span></li>
  <li><span class="vexpl">access the webGUI with the new IP address</span></li>
</ul></td>
	</tr>
</table>
</form>
<?php include("fend.inc"); ?>
