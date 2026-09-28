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

$pgtitle = array("Services", "Wake on LAN");
require("guiconfig.inc");

if (!is_array($config['wol']['wolentry'] ?? null)) {
	$config['wol']['wolentry'] = array();
}
wol_sort();
$a_wol = &$config['wol']['wolentry'];

$mac = '';
$if = '';

if ($_POST || !empty($_GET['mac'])) {

	foreach ($_POST as $pn => $pv) {
		if (preg_match("/^del_(\d+)_x$/", $pn, $matches)) {
			$id = $matches[1];
			if (!empty($a_wol[$id])) {
				// Scheduler: delete matching jobs
				croen_update_job('wol', $a_wol[$id]['descr'] ?? null);
				unset($a_wol[$id]);
				write_config();
				header("Location: services_wol.php");
				exit;
			}
		}
	}
	
	$input_errors = array();
	
	if (!empty($_GET['mac'])) {
		/* csrf-magic only guards POST (it returns early for any other method),
		   so a bare GET here meant any page anywhere could make this firewall
		   send a magic packet just by referencing the URL -- an <img src> was
		   enough. The wake links now carry a token and it is checked here. */
		/* check_tokenS: csrf_get_tokens() can return several joined by ';', and the
		   singular form would reject a perfectly good one. */
		if (empty($_GET['csrf']) || !csrf_check_tokens($_GET['csrf'])) {
			$input_errors[] = "Request could not be verified. Use the wake link on this page.";
			$mac = $if = '';
		} else {
			$mac = $_GET['mac'];
			$if = $_GET['if'] ?? '';
		}
	} else {
		$mac = $_POST['mac_input'] ?? '';
		$if = $_POST['interface'] ?? '';
	}
	
	$mac = str_replace("-", ":", $mac);

	/* input validation */
	if (!$mac || !is_macaddr($mac))
		$input_errors[] = "A valid MAC address must be specified.";
	/* $if indexes $config['interfaces'] two lines below, so an arbitrary
	   string got there from the URL and simply produced an empty broadcast. */
	if (!$if || !isset($config['interfaces'][$if]) || !is_array($config['interfaces'][$if]))
		$input_errors[] = "A valid interface must be specified.";

	if (empty($input_errors)) {		
		services_wol_send($config['interfaces'][$if]['ipaddr'] ?? '', $config['interfaces'][$if]['subnet'] ?? '', $mac);
		$savemsg = "Sent magic packet to {$mac}.";
	}
}

?>
<?php include("fbegin.inc"); ?>
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
<?php if (!empty($savemsg)) print_info_box($savemsg); ?>
			<form action="services_wol.php" method="post" name="iform" id="iform">
			  <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="content pane">
			  <tr> 
                  <td width="22%" valign="top" class="vncellreq">Interface</td>
                  <td width="78%" class="vtable">
					<select name="interface" class="formfld">
                      <?php $interfaces = array('lan' => 'LAN');
					  /* opt_interfaces() rather than counting up from 1: a deleted
					     optional interface no longer renumbers the rest, so the numbering
					     can have gaps and a counting loop would stop at the first one,
					     dropping every interface past it from the list. */
					  foreach (opt_interfaces() as $optif) {
					    if (isset($config['interfaces'][$optif]['enable']) &&
							empty($config['interfaces'][$optif]['bridge']))
					  		$interfaces[$optif] = $config['interfaces'][$optif]['descr'] ?? '';
					  }
					  foreach ($interfaces as $iface => $ifacename): ?>
                      <option value="<?=$iface;?>" <?php if ($iface == $if) echo "selected"; ?>> 
                      <?=htmlspecialchars($ifacename);?>
                      </option>
                      <?php endforeach; ?>
                    </select> <br>
                    <span class="vexpl">Choose which interface the host to be woken up is connected to.</span></td>
                </tr>
                <tr>
				  <td width="22%" valign="top" class="vncellreq">MAC address</td>
				  <td width="78%" class="vtable">
                      <?=$mandfldhtml;?><input name="mac_input" type="text" class="formfld" id="mac_input" size="20" value="<?=htmlspecialchars($mac);?>">
                      <br>
                      Enter a MAC address <span class="vexpl"> in the following format: xx:xx:xx:xx:xx:xx</span></td></tr>
				<tr>
				  <td width="22%" valign="top">&nbsp;</td>
				  <td width="78%"> 
                    <input name="Submit" type="submit" class="formbtn" value="Send">
				</td>
				</tr>
			</table>
			<span class="vexpl"><span class="red"><strong>Note:<br>
            </strong></span>This service can be used to wake up (power on) computers by sending special &quot;Magic Packets&quot;. The NIC in the computer that is to be woken up must support Wake on LAN and has to be configured properly (WOL cable, BIOS settings). </span><br>
                      <br> 
                      You may store MAC addresses below for your convenience.
Click the MAC address to wake up a computer. <br>
&nbsp;
<table width="100%" border="0" cellpadding="0" cellspacing="0" summary="mac-mapping widget">
                <tr>
                  <td width="15%" class="listhdrr">Interface</td>
                  <td width="25%" class="listhdrr">MAC address</td>
                  <td width="50%" class="listhdr">Description</td>
                  <td width="10%" class="list"></td>
				</tr>
			  <?php $i = 0; foreach ($a_wol as $wolent): ?>
                <tr>
                  <td class="listlr">
                    <?php if (($wolent['interface'] ?? null) == "lan")
							   echo "LAN";
						   else
						       echo $config['interfaces'][$wolent['interface']]['descr'] ?? '';
					?>&nbsp;
                  </td>
                  <td class="listr">
                    <a href="?mac=<?=urlencode($wolent['mac'] ?? '');?>&amp;if=<?=urlencode($wolent['interface'] ?? '');?>&amp;csrf=<?=urlencode(csrf_get_tokens());?>"><?=strtolower($wolent['mac'] ?? '');?></a>&nbsp;
                  </td>
                  <td class="listbg">
                    <?=htmlspecialchars($wolent['descr'] ?? '');?>&nbsp;
                  </td>
                  <td valign="middle" nowrap class="list"> <a href="services_wol_edit.php?id=<?=$i;?>"><img src="e.gif" title="edit entry" width="17" height="17" border="0" alt="edit entry"></a>
                     &nbsp;<input name="del_<?=$i;?>" type="image" src="x.gif" width="17" height="17" title="delete entry" alt="delete entry" onclick="return confirm('Do you really want to delete this entry?')"></td>
				</tr>
			  <?php $i++; endforeach; ?>
                <tr> 
                  <td class="list" colspan="3"></td>
                  <td class="list"> <a href="services_wol_edit.php"><img src="plus.gif" title="add entry" width="17" height="17" border="0" alt="edd entry"></a></td>
				</tr>
              </table>
</form>
<?php include("fend.inc"); ?>
