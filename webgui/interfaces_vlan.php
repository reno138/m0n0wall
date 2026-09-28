#!/usr/local/bin/php
<?php 
/*
	$Id$
	part of m0n0wall (http://m0n0.ch/wall)
	
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

if (!is_array($config['vlans']['vlan'] ?? null))
	$config['vlans']['vlan'] = array();

$a_vlans = &$config['vlans']['vlan'] ;

/* Which logical interfaces (lan/wan/optN) are assigned to vlan$num, so the
   refusal below can name them. It used to answer only true/false, and the
   message was "still being used as an interface" with no clue which one.
   
   The walk over optN is opt_interfaces(), which keeps the gaps: an OPT number
   is a stable identifier now that deleting one no longer renumbers the OPTs
   above it, so opt1 and opt3 with no opt2 is a normal config. Counting up from
   opt1 stopped at the first missing number, which made this check -- and the
   renumber_vlan() pass below -- miss every OPT above a hole, including one left
   by a hand-edited or partially restored config. */
function vlan_inuse($num) {
	global $config, $g;

	$inuse = array();

	if (($config['interfaces']['lan']['if'] ?? null) == "vlan{$num}")
		$inuse[] = "LAN";
	if (($config['interfaces']['wan']['if'] ?? null) == "vlan{$num}")
		$inuse[] = "WAN";
	
	foreach (opt_interfaces() as $i => $optif) {
		if (($config['interfaces'][$optif]['if'] ?? null) == "vlan{$num}")
			$inuse[] = "OPT" . $i;
	}
	
	return $inuse;
}

function renumber_vlan($if, $delvlan) {
	if (!preg_match("/^vlan/", $if))
		return $if;
	
	$vlan = substr($if, 4);
	if ($vlan > $delvlan)
		return "vlan" . ($vlan - 1);
	else
		return $if;
}

/* Fixed messages for the redirects from interfaces_vlan_edit.php and from the
   delete below, looked up by token so that nothing out of the query string is
   ever echoed. The two actions that are applied to the running system come back
   with one -- an ADD, and a DELETE of the last entry in the list -- and these
   say whether that actually happened. An edit, or a delete that renumbers,
   redirects without a token and the standard reboot notice below speaks for
   it. */
$vlan_statusmsg = array(
	"saved" =>
		"The changes have been saved. Nothing needed to be applied: only the " .
		"description changed, so the running configuration already matches.",
	"applied" =>
		"The changes have been applied successfully.",
	"exists" =>
		"The VLAN has been saved, but an interface already exists under the " .
		"name it needs, so nothing was created or changed on the running " .
		"system. You must <a href=\"/reboot.php\">reboot</a> to rebuild the " .
		"VLAN interfaces from the configuration.",
	"failed" =>
		"The VLAN has been saved, but its interface could not be created right " .
		"now -- see Diagnostics: System logs. You must " .
		"<a href=\"/reboot.php\">reboot</a> to retry.",
	"held" =>
		"The VLAN has been saved, but a reboot was already pending for an " .
		"earlier change, so it was not created now. You must " .
		"<a href=\"/reboot.php\">reboot</a> for the changes to take effect.",
	"deleted" =>
		"The VLAN has been deleted and its interface destroyed. Nothing else " .
		"was renumbered, so no reboot is required.",
	"renumbered" =>
		"The VLAN has been deleted and its interface destroyed. The VLANs " .
		"after it have moved up one place, and their interfaces were renamed " .
		"to match, keeping their addresses. No reboot is required.",
	"delfailed" =>
		"The VLAN has been deleted from the configuration, but its interface " .
		"could not be destroyed right now -- see Diagnostics: System logs. It " .
		"keeps tagging until you " .
		"<a href=\"/reboot.php\">reboot</a>.",
);
/* is_string() first. Indexing an array with an ARRAY key is a TypeError in
   PHP 8 -- "Cannot access offset of type array on array" -- and ?? does not
   catch it, so ...vlan.php?status[]=x was a blank 500. */
$vlan_status = $_GET['status'] ?? '';
$savemsg = is_string($vlan_status) ? ($vlan_statusmsg[$vlan_status] ?? '') : '';

if ($_POST) {
	foreach ($_POST as $pn => $pv) {
		if (preg_match("/^del_(\d+)_x$/", $pn, $matches)) {
			/* (int), because a non-canonical index disagrees with itself three
			   ways: vlan_inuse("00") compares against the string "vlan00" and
			   so never matches a real assignment, unset($a_vlans["00"]) is a
			   no-op because PHP only canonicalises canonical integer-like keys,
			   and renumber_vlan()'s "0" > "00" is false. del_00_x therefore
			   skipped the in-use check, deleted nothing, and still demanded a
			   reboot. */
			$id = (int) $matches[1];
			/* check if still in use */
			$inuse = vlan_inuse($id);
			if (count($inuse)) {
				$input_errors[] = "This VLAN cannot be deleted because it is still assigned to " .
					implode(", ", $inuse) . ". Change that assignment on the Interface assignments tab first.";
			} else if (!array_key_exists($id, $a_vlans)) {
				/* Nothing to delete. Worth saying rather than falling through:
				   the old code renumbered nothing, deleted nothing and still set
				   the reboot flag, which puts the whole webGUI into save-only
				   mode (exec_rc_script() returns early while that file exists)
				   over a request that did nothing at all. */
				$input_errors[] = "There is no VLAN to delete under that number.";
			} else {
				/* Is this a pure TRUNCATE -- the last entry in the list?
				
				   A VLAN's interface name is its POSITION in this array, and
				   unlike optN that cannot be made a stable identifier without a
				   config schema change: a hole in a list section does not even
				   survive being saved, because xmlparse.inc rebuilds one with
				   array_push($curpath, count($ptr)) and so reads the entries
				   back as 0..n-1. The full reasoning is in the block comment
				   over the VLAN section of interfaces.inc. So renumbering stays
				   for a delete from the middle, and so does its reboot.
				   
				   The LAST entry is the exception, and it is the exact mirror of
				   the add path's pure append: renumber_vlan() only shifts
				   positions ABOVE the deleted one and there are none, so no
				   surviving vlanN changes meaning, and vlan_inuse() has just
				   come back empty, so this interface is assigned to nothing and
				   cannot be the one carrying this session. Nothing is left for a
				   reboot to reconcile, so the interface is destroyed here and no
				   reboot is demanded -- the same "no destroy of anything in use"
				   rule the add path follows, satisfied by the same two facts.
				   
				   Packed keys are part of the test: a position equals its key
				   only while the array has no holes, and config.xml cannot
				   produce one (see above), so a hole here means this page is
				   looking at an array it did not get from config.xml and the
				   positional name of the last entry is not $id. Reboot, then. */
				$keys = array_keys($a_vlans);
				$packed = ($keys === range(0, count($a_vlans) - 1));
				$islast = $packed && ($id === (count($a_vlans) - 1));
				$oldcount = count($a_vlans);

				unset($a_vlans[$id]);

				/* renumber all interfaces that use VLANs. A no-op when $islast:
				   renumber_vlan() returns $if unchanged for every position below
				   the deleted one, which is all of them. */
				$config['interfaces']['lan']['if'] = renumber_vlan($config['interfaces']['lan']['if'] ?? '', $id);
				$config['interfaces']['wan']['if'] = renumber_vlan($config['interfaces']['wan']['if'] ?? '', $id);
				foreach (opt_interfaces() as $optif)
					$config['interfaces'][$optif]['if'] = renumber_vlan($config['interfaces'][$optif]['if'] ?? '', $id);

				/* Written to disk BEFORE the running system is touched, as on the
				   edit page: if the destroy below fails, or the admin's browser
				   never sees the redirect, config.xml is already correct and the
				   next boot builds the right set of interfaces. */
				write_config();

				$status = "";

				if (!$islast) {
					/* A delete from the middle renumbers every later VLAN, so
					   the live names and the config positions now disagree.
					   That used to be settled by a reboot; now the deleted
					   interface is destroyed and the ones above it are renamed
					   down one each, live -- see interfaces_vlan_shift_down().
					   A rename keeps addresses, so a renamed VLAN carrying this
					   session keeps carrying it.
					   
					   Still a reboot when the names cannot be trusted: a reboot
					   already pending (the live set may not match the config at
					   all), or keys with holes, which config.xml cannot produce,
					   so the positional names are not what this page thinks. */
					if (!$packed) {
						touch($d_sysrebootreqd_path);
					} else if (!file_exists($d_sysrebootreqd_path)) {
						config_lock();
						$retval = interfaces_vlan_shift_down($id, $oldcount);
						if ($retval == 0)
							$retval = interfaces_vlan_reapply();
						config_unlock();
						if ($retval != 0) {
							log_error("VLAN: could not renumber the VLAN " .
								"interfaces live after deleting vlan{$id}; " .
								"a reboot will");
							touch($d_sysrebootreqd_path);
							$status = "delfailed";
						} else {
							$status = "renumbered";
						}
					}
				} else if (file_exists($d_sysrebootreqd_path)) {
					/* A reboot was already pending, so the live vlanN names do
					   not match the config positions and vlan{$id} may be an
					   interface carrying somebody else's tag. Leave it strictly
					   alone and let the reboot rebuild the lot -- the same gate,
					   for the same reason, as the create on the edit page. */
				} else if (($iflist = interface_list_live()) === null) {
					/* The interface list could not be read, so "vlan{$id} is
					   not there" and "ifconfig could not tell us" cannot be
					   told apart -- and this branch is about to claim the
					   running system needs nothing done to it.
					   
					   Do not claim that. config.xml has already been written,
					   so if the answer was wrong the VLAN is gone from the
					   configuration while its interface is still up and still
					   tagging, with no reboot flag set and the page reporting
					   that everything was applied. Fall back to the flag, which
					   is what the failed-destroy branch below does, for the same
					   reason: a reboot starts from no vlan interfaces at all and
					   reconciles whatever the true state was.
					   
					   The create path on the edit page declines to act on a
					   possibly-wrong answer from the same function; this is the
					   same caution pointed the other way. */
					log_error("VLAN: could not read the interface list, so " .
						"vlan{$id} was not destroyed; a reboot will clear it");
					touch($d_sysrebootreqd_path);
					$status = "delfailed";
				} else if (!in_array("vlan{$id}", $iflist, true)) {
					/* Genuinely not there: the configuration and the running
					   system already agree, so there is nothing to apply and
					   nothing to reboot for. */
					$status = "deleted";
				} else {
					config_lock();
					$retval = interfaces_vlan_destroy_if($id);
					config_unlock();

					if ($retval != 0) {
						log_error("VLAN: could not destroy vlan{$id}: ifconfig " .
							"returned {$retval}");
						touch($d_sysrebootreqd_path);
						$status = "delfailed";
					} else {
						$status = "deleted";
					}
				}

				header("Location: interfaces_vlan.php" .
					($status ? "?status=" . $status : ""));
				exit;
			}
		}
	}
}

?>
<?php include("fbegin.inc"); ?>
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
<?php
/* Both, when both apply -- not one or the other.
   
   This was an else, so any re-request of ...vlan.php?status=applied printed
   "applied successfully" and SUPPRESSED a genuine pending-reboot notice: the
   token lives in the query string, so a refresh or a bookmark kept hiding it
   for as long as the URL was reused. The outcome of the last action and the
   state of the box are two different facts and the admin needs both. */
if ($savemsg)
	print_info_box($savemsg);
if (file_exists($d_sysrebootreqd_path))
	print_info_box(get_std_save_message(0));
?>
<form action="interfaces_vlan.php" method="post" name="iform" id="iform">
<table width="100%" border="0" cellpadding="0" cellspacing="0" summary="tab pane">
  <tr><td class="tabnavtbl">
  <ul id="tabnav">
    <li class="tabinact1"><a href="interfaces_assign.php">Interface assignments</a></li>
    <li class="tabact">VLANs</li>
    <li class="tabinact"><a href="interfaces_wlan.php">WLANs</a></li>
  </ul>
  </td></tr>
  <tr> 
    <td class="tabcont">
<table width="100%" border="0" cellpadding="0" cellspacing="0" summary="content pane">
                <tr>
                  <td width="15%" class="listhdrr">Interface</td>
                  <td width="20%" class="listhdrr">Parent interface</td>
                  <td width="10%" class="listhdrr">VLAN tag</td>
                  <td width="45%" class="listhdr">Description</td>
                  <td width="10%" class="list"></td>
				</tr>
			  <?php $i = 0; $nvlans = count($a_vlans); foreach ($a_vlans as $vlan):
					/* Deleting anything but the last row renumbers the rows
					   after it -- vlan3 becomes vlan2 and so on -- and the
					   interface assignments are rewritten to match. Say so
					   before the click, not after. Deleting the LAST row
					   renumbers nothing and is applied immediately, so say that
					   too: the two cases behave differently enough that one
					   wording cannot cover both. */
					if ($i < ($nvlans - 1))
						$delconfirm = "Deleting this VLAN renumbers the VLANs below it (vlan2 becomes vlan1, and so on) and rewrites the interface assignments to match. A reboot is required afterwards. Continue?";
					else
						$delconfirm = "This is the last VLAN in the list, so deleting it renumbers nothing and takes effect immediately: vlan" . $i . " is destroyed when you confirm. Continue?";
			  ?>
                <tr>
                  <td class="listlr">
					<?php /* the kernel interface name IS the row's position: the
					         name to pick on the Interface assignments tab, and to
					         hand to tcpdump. The first column used to be headed
					         "Interface" and show the PARENT, so a new VLAN's own
					         name appeared nowhere on the page. */ ?>
					<?='vlan' . $i;?>
                  </td>
                  <td class="listr">
					<?=htmlspecialchars($vlan['if'] ?? '');?>
                  </td>
                  <td class="listr">
					<?=htmlspecialchars($vlan['tag'] ?? '');?>
                  </td>
                  <td class="listbg">
                    <?=htmlspecialchars($vlan['descr'] ?? '');?>&nbsp;
                  </td>
                  <td valign="middle" nowrap class="list"> <a href="interfaces_vlan_edit.php?id=<?=$i;?>"><img src="e.gif" title="edit VLAN" width="17" height="17" border="0" alt="edit VLAN"></a>
                     &nbsp;<input name="del_<?=$i;?>" type="image" src="x.gif" width="17" height="17" title="delete VLAN" alt="delete VLAN" onclick="return confirm('<?=htmlspecialchars($delconfirm);?>')"></td>
				</tr>
			  <?php $i++; endforeach; ?>
                <tr> 
                  <td class="list" colspan="4">&nbsp;</td>
                  <td class="list"> <a href="interfaces_vlan_edit.php"><img src="plus.gif" title="add VLAN" width="17" height="17" border="0" alt="add VLAN"></a></td>
				</tr>
				<tr>
				<td colspan="4" class="list"><span class="vexpl"><span class="red"><strong>
				  Note:<br>
				  </strong></span>
				  Not all drivers/NICs support 802.1Q VLAN tagging properly. On cards that do not explicitly support it, VLAN tagging will still work, but the reduced MTU may cause problems. See the m0n0wall homepage for information on supported cards.<br><br>
				  <?php if (file_exists($d_sysrebootreqd_path)): ?>
				  A reboot is pending, so VLAN changes will be saved but not applied until
				  you reboot &ndash; while a reboot is outstanding the running interfaces no
				  longer match the configuration, so it is not safe to change them in place.
				  <?php else: ?>
				  Adding, changing and deleting VLANs all take effect immediately, with no
				  reboot. A changed tag or parent is applied to the running interface in
				  place, keeping its address. Deleting a VLAN from the middle of the list
				  renumbers the ones after it, and their running interfaces are renamed to
				  match &ndash; also keeping their addresses &ndash; before whatever is
				  assigned to them is re-applied.
				  <?php endif; ?></span>
				  </td>
				<td class="list">&nbsp;</td>
				</tr>
              </table>
			  </td>
	</tr>
</table>
</form>
<?php include("fend.inc"); ?>
