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

$pgtitle = array("Firewall", "NAT", "Edit 1:1");
require("guiconfig.inc");

if (!is_array($config['nat']['onetoone'] ?? null)) {
	$config['nat']['onetoone'] = array();
}
nat_1to1_rules_sort();
$a_1to1 = &$config['nat']['onetoone'];

$id = $_GET['id'] ?? null;
if (isset($_POST['id']))
	$id = $_POST['id'];

if (isset($id) && !empty($a_1to1[$id])) {
	$pconfig['external'] = $a_1to1[$id]['external'] ?? null;
	$pconfig['internal'] = $a_1to1[$id]['internal'] ?? null;
	$pconfig['interface'] = $a_1to1[$id]['interface'] ?? null;
	if (empty($pconfig['interface']))
		$pconfig['interface'] = "wan";
	if (empty($a_1to1[$id]['subnet']))
		$pconfig['subnet'] = 32;
	else
		$pconfig['subnet'] = $a_1to1[$id]['subnet'];
	$pconfig['descr'] = $a_1to1[$id]['descr'] ?? null;
} else {
    $pconfig['subnet'] = 32;
	$pconfig['interface'] = "wan";
}

if ($_POST) {
	
	$input_errors = array();
	$pconfig = $_POST;

	/* input validation */
	$reqdfields = explode(" ", "interface external internal");
	$reqdfieldsn = explode(",", "Interface,External subnet,Internal subnet");
	
	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

	if ((!empty($_POST['external']) && !is_ipaddr($_POST['external']))) {
		$input_errors[] = "A valid external subnet must be specified.";
	}
	if ((!empty($_POST['internal']) && !is_ipaddr($_POST['internal']))) {
		$input_errors[] = "A valid internal subnet must be specified.";
	}
	
	/*  return the subnet address given a host address and a subnet bit count */
	if ($extsubnetip = gen_subnet($_POST['external'] ?? null, $_POST['subnet'] ?? null)) {
		$_POST['external'] = $extsubnetip;
	} else {
		$input_errors[] = "Can't convert external ip to valid subnet address.";
	}

	if ($intsubnetip = gen_subnet($_POST['internal'] ?? null, $_POST['subnet'] ?? null)) {
		$_POST['internal'] = $intsubnetip;
	} else {
		$input_errors[] = "Can't convert internal ip to valid subnet address.";
	}

	if (is_ipaddr($config['interfaces']['wan']['ipaddr'] ?? null)) {
		if (check_subnets_overlap($_POST['external'] ?? null, $_POST['subnet'] ?? null, 
				$config['interfaces']['wan']['ipaddr'], 32))
			$input_errors[] = "The WAN IP address may not be used in a 1:1 rule.";
	}
	

	/* check for overlaps with other 1:1 */
	foreach ($a_1to1 as $natent) {
		if (isset($id) && (!empty($a_1to1[$id])) && ($a_1to1[$id] === $natent))
			continue;
		
		if (check_subnets_overlap($_POST['external'] ?? null, $_POST['subnet'] ?? null, $natent['external'], $natent['subnet'] ?? null)) {
			$input_errors[] = "Another 1:1 rule overlaps with the specified external subnet.";
			break;
		} else if (check_subnets_overlap($_POST['internal'] ?? null, $_POST['subnet'] ?? null, $natent['internal'], $natent['subnet'] ?? null)) {
			$input_errors[] = "Another 1:1 rule overlaps with the specified internal subnet.";
			break;
		}
	}
	
	/* check for overlaps with server NAT */
	if (is_array($config['nat']['servernat'] ?? null)) {
		foreach ($config['nat']['servernat'] as $natent) {
			if (check_subnets_overlap($_POST['external'] ?? null, $_POST['subnet'] ?? null,
				$natent['ipaddr'], 32)) {
				$input_errors[] = "A server NAT entry overlaps with the specified external subnet.";
				break;
			}
		}
	}
	
	/* check for overlaps with advanced outbound NAT */
	if (is_array($config['nat']['advancedoutbound']['rule'] ?? null)) {
		foreach ($config['nat']['advancedoutbound']['rule'] as $natent) {
			if (!empty($natent['target']) && 
				check_subnets_overlap($_POST['external'] ?? null, $_POST['subnet'] ?? null, $natent['target'], 32)) {
				$input_errors[] = "An advanced outbound NAT entry overlaps with the specified external subnet.";
				break;
			}
		}
	}

	if (empty($input_errors)) {
		$natent = array();
		$natent['external'] = $_POST['external'];
		$natent['internal'] = $_POST['internal'];
		$natent['subnet'] = $_POST['subnet'] ?? null;
		$natent['descr'] = $_POST['descr'] ?? null;
		$natent['interface'] = $_POST['interface'] ?? null;
		
		if (isset($id) && !empty($a_1to1[$id]))
			$a_1to1[$id] = $natent;
		else
			$a_1to1[] = $natent;
		
		touch($d_natconfdirty_path);

		if (!empty($_POST['autoaddproxy'])) {
			/* auto-generate a matching proxy arp entry */
			$arpent = array();           
			$arpent['interface'] = $_POST['interface'] ?? null;
			$arpent['network'] = $_POST['external'] . "/" . $_POST['subnet'];
			$arpent['descr'] = "NAT " . ($_POST['descr'] ?? '');
			
			$config['proxyarp']['proxyarpnet'][] = $arpent;
			
			touch($d_proxyarpdirty_path);
		}
		
		write_config();
		
		header("Location: firewall_nat_1to1.php");
		exit;
	}
}
?>
<?php include("fbegin.inc"); ?>
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
            <form action="firewall_nat_1to1_edit.php" method="post" name="iform" id="iform">
              <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="content pane">
				<tr>
				  <td width="22%" valign="top" class="vncellreq">Interface</td>
				  <td width="78%" class="vtable">
					<select name="interface" class="formfld">
						<?php
						$interfaces = array('wan' => 'WAN');
						/* opt_interfaces() rather than counting up from 1: a deleted
						   optional interface no longer renumbers the rest, so the
						   numbering can have gaps and a counting loop would stop at the
						   first one. */
						foreach (opt_interfaces() as $optif) {
							$interfaces[$optif] = $config['interfaces'][$optif]['descr'];
						}
						foreach ($interfaces as $iface => $ifacename): ?>
						<option value="<?=$iface;?>" <?php if ($iface == ($pconfig['interface'] ?? null)) echo "selected"; ?>>
						<?=htmlspecialchars($ifacename);?>
						</option>
						<?php endforeach; ?>
					</select><br>
				  <span class="vexpl">Choose which interface this rule applies to.<br>
				  Hint: in most cases, you'll want to use WAN here.</span></td>
				</tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">External subnet</td>
                  <td width="78%" class="vtable"> 
                    <?=$mandfldhtml;?><input name="external" type="text" class="formfld" id="external" size="20" value="<?=htmlspecialchars($pconfig['external'] ?? '');?>">
                    / 
                    <select name="subnet" class="formfld" id="subnet">
                      <?php for ($i = 32; $i >= 0; $i--): ?>
                      <option value="<?=$i;?>" <?php if ($i == ($pconfig['subnet'] ?? null)) echo "selected"; ?>>
                      <?=$i;?>
                      </option>
                      <?php endfor; ?>
                    </select>
                    <br>
                    <span class="vexpl">Enter the external (WAN) subnet for the 1:1 mapping. You may map single IP addresses by specifying a /32 subnet.</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Internal subnet</td>
                  <td width="78%" class="vtable"> 
                    <?=$mandfldhtml;?><input name="internal" type="text" class="formfld" id="internal" size="20" value="<?=htmlspecialchars($pconfig['internal'] ?? '');?>"> 
                    <br>
                     <span class="vexpl">Enter the internal (LAN) subnet for the 1:1 mapping. The subnet size specified for the external subnet also applies to the internal subnet (they  have to be the same).</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">Description</td>
                  <td width="78%" class="vtable"> 
                    <input name="descr" type="text" class="formfld" id="descr" size="40" value="<?=htmlspecialchars($pconfig['descr'] ?? '');?>"> 
                    <br> <span class="vexpl">You may enter a description here 
                    for your reference (not parsed).</span></td>
                </tr><?php if (!(isset($id) && !empty($a_1to1[$id]))): ?>
		<tr> 
		  <td width="22%" valign="top">&nbsp;</td>
		  <td width="78%"> 
		    <input name="autoaddproxy" type="checkbox" id="autoaddproxy" value="yes" checked="checked">
		    <strong>Auto-add a <a href="services_proxyarp.php">proxy ARP</a> entry to this interface
		    </strong></td>
		</tr><?php endif; ?>
                <tr> 
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%"> 
                    <input name="Submit" type="submit" class="formbtn" value="Save"> 
                    <?php if (isset($id) && !empty($a_1to1[$id])): ?>
                    <input name="id" type="hidden" value="<?=htmlspecialchars($id);?>"> 
                    <?php endif; ?>
                  </td>
                </tr>
              </table>
</form>
<?php include("fend.inc"); ?>
