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
   
   The walk over optN stops at the first gap, as it always has -- the same
   pattern gates the renumber_vlan() calls below and interfaces_autoreassign().
   interfaces_assign.php shifts the OPTs down when one is deleted, so a gap
   should not occur in normal operation, but a hand-edited or partially restored
   config can have one, and then this and the renumbering both stop early. Not
   fixed here; do not read the empty return as a guarantee that nothing is using
   the VLAN. */
function vlan_inuse($num) {
	global $config, $g;

	$inuse = array();

	if (($config['interfaces']['lan']['if'] ?? null) == "vlan{$num}")
		$inuse[] = "LAN";
	if (($config['interfaces']['wan']['if'] ?? null) == "vlan{$num}")
		$inuse[] = "WAN";
	
	for ($i = 1; isset($config['interfaces']['opt' . $i]); $i++) {
		if (($config['interfaces']['opt' . $i]['if'] ?? null) == "vlan{$num}")
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

/* Fixed messages for the redirect from interfaces_vlan_edit.php, looked up by
   token so that nothing out of the query string is ever echoed. Only an ADD
   comes back with one: an add is applied to the running system immediately, and
   these say whether that actually happened. An edit or a delete redirects
   without a token and the standard reboot notice below speaks for it. */
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
			} else {
				unset($a_vlans[$id]);

				/* renumber all interfaces that use VLANs */
				$config['interfaces']['lan']['if'] = renumber_vlan($config['interfaces']['lan']['if'] ?? '', $id);
				$config['interfaces']['wan']['if'] = renumber_vlan($config['interfaces']['wan']['if'] ?? '', $id);
				for ($i = 1; isset($config['interfaces']['opt' . $i]); $i++)
					$config['interfaces']['opt' . $i]['if'] = renumber_vlan($config['interfaces']['opt' . $i]['if'] ?? '', $id);

				write_config();
				/* A delete still requires a reboot, and unlike an add it runs no
				   ifconfig at all.
				
				   Two separate things would have to happen live. The deleted
				   interface would have to be destroyed -- and although
				   vlan_inuse() has just established that it is not assigned to
				   anything, so it cannot be the one carrying this session, that
				   is only half of it. The renumbering above moves the positional
				   NAME of every VLAN above the deleted one, and those can be LAN
				   or WAN: matching it live would mean destroying and recreating
				   in-use interfaces to shift their names down by one, any of
				   which may be the interface this request arrived on. So the
				   config is renumbered, the reboot rebuilds the interfaces from
				   it, and until then the deleted VLAN keeps tagging -- as it did
				   before this page applied anything live.
				
				   This flag is also what keeps the add path on the edit page
				   honest: while it is set, an add is saved but not created,
				   because the live vlanN names no longer match the config
				   positions. */
				touch($d_sysrebootreqd_path);
				header("Location: interfaces_vlan.php");
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
					   before the click, not after. */
					if ($i < ($nvlans - 1))
						$delconfirm = "Deleting this VLAN renumbers the VLANs below it (vlan2 becomes vlan1, and so on) and rewrites the interface assignments to match. A reboot is required afterwards. Continue?";
					else
						$delconfirm = "Do you really want to delete this VLAN?";
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
				  A reboot is pending, so adding a VLAN will be saved but not created until
				  you reboot &ndash; while a reboot is outstanding the running interfaces no
				  longer match the configuration, so it is not safe to create one in place.
				  <?php else: ?>
				  Adding a VLAN takes effect immediately &ndash; the interface is created when
				  you save, and no reboot is required.
				  <?php endif; ?>
				  Changing or deleting one still requires a reboot: the running interface has to be destroyed and rebuilt for that, and deleting a VLAN renumbers the ones after it.</span>
				  </td>
				<td class="list">&nbsp;</td>
				</tr>
              </table>
			  </td>
	</tr>
</table>
</form>
<?php include("fend.inc"); ?>
