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

$pgtitle = array("Interfaces", "Assign network ports", "Edit VLAN");
require("guiconfig.inc");

if (!is_array($config['vlans']['vlan'] ?? null))
	$config['vlans']['vlan'] = array();

$a_vlans = &$config['vlans']['vlan'];

/* Not get_interface_list(): that also offers wg(4) tunnels, which cannot carry
   802.1Q tags. See vlan_parent_list() in interfaces.inc. */
$portlist = vlan_parent_list();

$id = $_GET['id'] ?? null;
if (isset($_POST['id']))
	$id = $_POST['id'];

if (isset($id) && !empty($a_vlans[$id])) {
	$pconfig['if'] = $a_vlans[$id]['if'];
	$pconfig['tag'] = $a_vlans[$id]['tag'];
	$pconfig['descr'] = $a_vlans[$id]['descr'];
}

if ($_POST) {

	unset($input_errors);
	$pconfig = $_POST;

	/* input validation */
	$reqdfields = explode(" ", "if tag");
	$reqdfieldsn = explode(",", "Parent interface,VLAN tag");
	
	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
	
	/* isset(), not !empty(): empty("0") is TRUE, so a tag of 0 skipped this
	   range test entirely and do_input_validation only rejects unset and "".
	   That used to put a bogus 0 in config.xml; now it would also be handed to
	   "ifconfig vlanN create vlan 0", which is not a valid tag. */
	$vtag = $_POST['tag'] ?? '';
	if (is_string($vtag) && $vtag !== '' &&
	    (!is_numericint($vtag) || ((int) $vtag < 1) || ((int) $vtag > 4094))) {
		$input_errors[] = "The VLAN tag must be an integer between 1 and 4094.";
	} else if (!is_string($vtag) && $vtag !== null) {
		$input_errors[] = "The VLAN tag must be an integer between 1 and 4094.";
	}

	/* The parent was never checked: whatever was posted went into config.xml,
	   and only the dropdown kept it sensible. It now also goes straight into an
	   "ifconfig ... vlandev" command line on the add path, so check it against
	   the list the dropdown was built from. */
	$vparent = $_POST['if'] ?? '';
	if (!is_string($vparent)) {
		/* isset() with an ARRAY offset is itself a TypeError in PHP 8
		   ("Cannot access offset of type array in isset or empty"), so the
		   type has to be settled before the lookup rather than inside it. */
		$input_errors[] = "The parent interface is not a network port that can carry VLAN tags.";
	} else if ($vparent !== '' && !isset($portlist[$vparent])) {
		$input_errors[] = "The parent interface is not a network port that can carry VLAN tags.";
	}

	foreach ($a_vlans as $i => $vlan) {
		/* skip the entry being edited -- by KEY. This compared the whole entry
		   by value, which also skipped any other entry that happened to be
		   identical. */
		if (isset($id) && (!empty($a_vlans[$id])) && ((string)$i === (string)$id))
			continue;
		
		if ((($vlan['if'] ?? null) == ($_POST['if'] ?? null)) && (($vlan['tag'] ?? null) == ($_POST['tag'] ?? null))) {
			$input_errors[] = "A VLAN with the tag {$vlan['tag']} is already defined on this interface.";
			break;
		}	
	}

	if (empty($input_errors)) {
		$vlan = array();
		$vlan['if'] = $_POST['if'] ?? null;
		$vlan['tag'] = $_POST['tag'] ?? null;
		$vlan['descr'] = $_POST['descr'] ?? null;

		$isnew = !(isset($id) && !empty($a_vlans[$id]));

		/* Does this edit change anything the RUNNING SYSTEM cares about?
		
		   Only 'if' and 'tag' are on the wire -- 'descr' is a label this page
		   and the list page show and nothing else reads. So a description-only
		   edit, or a Save with nothing altered at all, leaves the live
		   interfaces already correct and must NOT demand a reboot. It used to:
		   the flag was touched unconditionally, which both told the admin a lie
		   and, because exec_rc_script() returns early while that flag exists,
		   quietly put the rest of the webGUI into save-only mode until they
		   rebooted. */
		$wirechanged = $isnew
		    || (($a_vlans[$id]['if'] ?? null) !== $vlan['if'])
		    || (($a_vlans[$id]['tag'] ?? null) !== $vlan['tag']);

		if ($isnew) {
			$a_vlans[] = $vlan;
			/* The kernel name of a VLAN is its position in this list, and an
			   add only ever appends -- so this is the next free name, nothing
			   refers to it yet, and no existing vlanN changes meaning.
			   
			   Captured HERE, before write_config(): write_config() re-reads
			   config.xml and reassigns $config, which leaves $a_vlans pointing
			   at the pre-write copy. Nothing below reads it again. */
			$newidx = count($a_vlans) - 1;
		} else {
			$a_vlans[$id] = $vlan;
		}

		/* Written to disk BEFORE anything is done to the running system: if the
		   ifconfig below fails, or the admin's browser never sees the redirect,
		   config.xml is already correct and the VLAN comes up at the next boot.
		   There is no half-applied state to recover from. */
		write_config();

		if (!$isnew && $wirechanged) {
			/* Applied live: the interface is retargeted in place, not
			   destroyed and recreated, so its addresses, pf states and leases
			   survive -- see interfaces_vlan_retag_if(). Then whatever is
			   assigned on top is re-applied.
			   
			   If the tag or parent changed on the VLAN that carries this very
			   session, the session goes wherever the admin just moved it --
			   which is what they asked for, and what the reboot used to do
			   too, only a minute later.
			   
			   Held, as every page's apply is, while a reboot is already
			   pending: then the live vlanN names may not match the config
			   positions, and vlan{$id} could be somebody else's interface. */
			if (file_exists($d_sysrebootreqd_path)) {
				header("Location: interfaces_vlan.php?status=held");
				exit;
			}
			config_lock();
			$retval = interfaces_vlan_retag_if($id, $vlan);
			if ($retval == 0)
				$retval = interfaces_vlan_reapply();
			config_unlock();
			if ($retval != 0) {
				log_error("VLAN: could not apply the change to vlan{$id} " .
					"(tag {$vlan['tag']} on {$vlan['if']}) live; a reboot will");
				touch($d_sysrebootreqd_path);
				header("Location: interfaces_vlan.php?status=failed");
				exit;
			}
			header("Location: interfaces_vlan.php?status=applied");
			exit;
		}

		if (!$isnew) {
			/* A description-only edit, or a Save with nothing altered. The live
			   interfaces already match, so there is nothing to apply and nothing
			   to reboot for. Returns here rather than falling through, because
			   the create path below is reachable only for an add -- $newidx is
			   set only in that branch. */
			header("Location: interfaces_vlan.php?status=saved");
			exit;
		}

		/* Create the new interface now.
		
		   Skipped while a reboot is already pending, exactly as every other page
		   skips its apply step (services_dhcp.php, interfaces_opt.php, the
		   firewall pages, and exec_rc_script() itself all gate on this file).
		   Here it is also the correctness gate: the only ways the live vlanN
		   interfaces can stop matching the config positions are a VLAN edit or a
		   VLAN delete, and both set this flag -- so while it is absent,
		   vlan{$newidx} is guaranteed to be a free name. While it is present,
		   vlan{$newidx} may well be an existing interface carrying another
		   VLAN's tag, and reconciling that is what the reboot is for.
		   
		   Note what is NOT here: no destroy, on any branch. A vlan interface
		   that is already up may be carrying the session this request arrived
		   on, and this page has no business tearing one down -- so when the name
		   is not free, or the create fails, it defers to the reboot and says so
		   instead. */
		$status = "applied";

		if (file_exists($d_sysrebootreqd_path)) {
			$status = "held";
		} else {
			$newif = "vlan{$newidx}";

			if (interface_is_present($newif)) {
				/* Something already owns that name, so the running system does
				   not line up with the config positions after all -- a vlan
				   created by hand on the console, say. Leave it strictly alone:
				   it could be carrying anything, including this session. */
				log_error("VLAN: {$newif} already exists, so the new VLAN " .
					"(tag {$vlan['tag']} on {$vlan['if']}) was saved but not " .
					"created; a reboot will rebuild the VLAN interfaces.");
				touch($d_sysrebootreqd_path);
				$status = "exists";
			} else {
				config_lock();
				$retval = interfaces_vlan_configure_if($newidx, $vlan);
				config_unlock();

				if ($retval != 0) {
					/* No cleanup destroy: interface_is_present() said the name
					   was free, but if that was wrong -- "ifconfig -l" failing,
					   for instance -- then destroying it would tear down
					   somebody else's interface with config.xml already written.
					   A half-created interface is harmless by comparison: it is
					   assigned to nothing, and the next boot rebuilds it. */
					log_error("VLAN: could not create {$newif} (tag " .
						"{$vlan['tag']} on {$vlan['if']}): ifconfig returned " .
						"{$retval}");
					touch($d_sysrebootreqd_path);
					$status = "failed";
				}
			}
		}

		header("Location: interfaces_vlan.php?status=" . $status);
		exit;
	}
}
?>
<?php include("fbegin.inc"); ?>
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
            <form action="interfaces_vlan_edit.php" method="post" name="iform" id="iform">
              <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="content pane">
				<tr>
                  <td width="22%" valign="top" class="vncellreq">Parent interface</td>
                  <td width="78%" class="vtable"> 
                    <select name="if" class="formfld">
                      <?php
					  /* Keep the entry's CURRENTLY STORED parent in the list even
					     if it is no longer an offerable one -- this page used to
					     offer wg0, and any VLAN saved against it would otherwise
					     have no <option> marked selected. The browser then submits
					     whatever is first in the list, so simply opening such an
					     entry and pressing Save would silently re-parent it. */
					  $vlan_cur = $pconfig['if'] ?? '';
					  if (is_string($vlan_cur) && $vlan_cur !== '' && !isset($portlist[$vlan_cur]))
						  $portlist[$vlan_cur] = array('drvname' => 'no longer available', 'mac' => '');

					  foreach ($portlist as $ifn => $ifinfo): ?>
                      <option value="<?=htmlspecialchars($ifn);?>" <?php if ($ifn == ($pconfig['if'] ?? null)) echo "selected"; ?>> 
					  <?php if (!empty($ifinfo['drvname']))
							echo htmlspecialchars($ifn . " (" . $ifinfo['drvname'] . ", " .  ($ifinfo['mac'] ?? '') . ")");
						else
							echo htmlspecialchars($ifn . " (" . ($ifinfo['mac'] ?? '') . ")");
					  ?>
                      </option>
                      <?php endforeach; ?>
                    </select></td>
                </tr>
				<tr>
                  <td valign="top" class="vncellreq">VLAN tag </td>
                  <td class="vtable">
                    <?=$mandfldhtml;?><input name="tag" type="text" class="formfld" id="tag" size="6" value="<?=htmlspecialchars($pconfig['tag'] ?? '');?>">
                    <br>
                    <span class="vexpl">802.1Q VLAN tag (between 1 and 4094) </span></td>
			    </tr>
				<tr>
                  <td width="22%" valign="top" class="vncell">Description</td>
                  <td width="78%" class="vtable"> 
                    <input name="descr" type="text" class="formfld" id="descr" size="40" value="<?=htmlspecialchars($pconfig['descr'] ?? '');?>">
                    <br> <span class="vexpl">You may enter a description here
                    for your reference (not parsed).</span></td>
                </tr>
                <tr>
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%"> 
                    <input name="Submit" type="submit" class="formbtn" value="Save">
                    <?php if (isset($id) && !empty($a_vlans[$id])): ?>
                    <input name="id" type="hidden" value="<?=htmlspecialchars($id);?>">
                    <?php endif; ?>
                  </td>
                </tr>
              </table>
</form>
<?php include("fend.inc"); ?>
