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

$pgtitle = array("Firewall", "NAT", "Edit");
require("guiconfig.inc");

if (!is_array($config['nat']['rule'] ?? null)) {
	$config['nat']['rule'] = array();
}
nat_rules_sort();
$a_nat = &$config['nat']['rule'];

$id = $_GET['id'] ?? null;
if (isset($_POST['id']))
	$id = $_POST['id'];

$pconfig = array();

if (isset($id) && !empty($a_nat[$id])) {
	$pconfig['extaddr'] = $a_nat[$id]['external-address'] ?? null;
	$pconfig['proto'] = $a_nat[$id]['protocol'] ?? null;
	$extports = explode("-", $a_nat[$id]['external-port'] ?? '');
	$pconfig['beginport'] = $extports[0] ?? null;
	$pconfig['endport'] = $extports[1] ?? null;
	$pconfig['localip'] = $a_nat[$id]['target'] ?? null;
	$pconfig['localbeginport'] = $a_nat[$id]['local-port'] ?? null;
	$pconfig['descr'] = $a_nat[$id]['descr'] ?? null;
	$pconfig['interface'] = $a_nat[$id]['interface'] ?? null;
	if (!$pconfig['interface'])
		$pconfig['interface'] = "wan";
} else {
	$pconfig['interface'] = "wan";
}

if ($_POST) {

	if (!empty($_POST['beginport_cust']) && empty($_POST['beginport']))
		$_POST['beginport'] = $_POST['beginport_cust'];
	if (!empty($_POST['endport_cust']) && empty($_POST['endport']))
		$_POST['endport'] = $_POST['endport_cust'];
	if (!empty($_POST['localbeginport_cust']) && empty($_POST['localbeginport']))
		$_POST['localbeginport'] = $_POST['localbeginport_cust'];
		
	if (empty($_POST['endport']))
		$_POST['endport'] = $_POST['beginport'] ?? null;
	
	unset($input_errors);
	$pconfig = $_POST;

	/* input validation */
	$reqdfields = explode(" ", "interface proto beginport localip localbeginport");
	$reqdfieldsn = explode(",", "Interface,Protocol,Start port,NAT IP,Local port");
	
	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
	
	if (($_POST['extaddr'] ?? null) == 'wan' && ($_POST['interface'] ?? null) == 'wan') {
		$input_errors[] = "The interface must not be WAN if the External Address is set to WAN.";
	}
	
	if ((!empty($_POST['beginport']) && !is_port($_POST['beginport']))) {
		$input_errors[] = "The start port must be an integer between 1 and 65535.";
	}
	if ((!empty($_POST['endport']) && !is_port($_POST['endport']))) {
		$input_errors[] = "The end port must be an integer between 1 and 65535.";
	}
	if ((!empty($_POST['localbeginport']) && !is_port($_POST['localbeginport']))) {
		$input_errors[] = "The local port must be an integer between 1 and 65535.";
	}
	if ((!empty($_POST['localip']) && !is_ipaddroralias($_POST['localip']))) {
		$input_errors[] = "A valid NAT IP address or host alias must be specified.";
	}
	
	if (($_POST['beginport'] ?? null) > ($_POST['endport'] ?? null)) {
		/* swap */
		$tmp = $_POST['endport'] ?? null;
		$_POST['endport'] = $_POST['beginport'];
		$_POST['beginport'] = $tmp;
	}
	
	if (empty($input_errors)) {
		if ((($_POST['endport'] ?? null) - ($_POST['beginport'] ?? null) + ($_POST['localbeginport'] ?? null)) > 65535)
			$input_errors[] = "The target port range must lie between 1 and 65535.";
	}
	
	/* check for overlaps */
	foreach ($a_nat as $natent) {
		if (isset($id) && (!empty($a_nat[$id])) && ($a_nat[$id] === $natent))
			continue;
		if (($natent['interface'] ?? null) != ($_POST['interface'] ?? null))
			continue;
		if (($natent['external-address'] ?? null) != ($_POST['extaddr'] ?? null))
			continue;
		if ((($natent['protocol'] ?? null) != ($_POST['proto'] ?? null)) && (($natent['protocol'] ?? null) != "tcp/udp") && (($_POST['proto'] ?? null) != "tcp/udp"))
			continue;
		
		$natports = explode("-", $natent['external-port'] ?? '');
		$begp = $natports[0] ?? null;
		$endp = $natports[1] ?? null;
		if (!$endp)
			$endp = $begp;
		
		if (!(   ((($_POST['beginport'] ?? null) < $begp) && (($_POST['endport'] ?? null) < $begp))
		      || ((($_POST['beginport'] ?? null) > $endp) && (($_POST['endport'] ?? null) > $endp)))) {
			
			$input_errors[] = "The external port range overlaps with an existing entry.";
			break;
		}
	}

	if (empty($input_errors)) {
		$natent = array();
		if (!empty($_POST['extaddr']))
			$natent['external-address'] = $_POST['extaddr'];
		$natent['protocol'] = $_POST['proto'] ?? null;
		
		if (($_POST['beginport'] ?? null) == ($_POST['endport'] ?? null))
			$natent['external-port'] = $_POST['beginport'] ?? null;
		else
			$natent['external-port'] = ($_POST['beginport'] ?? '') . "-" . ($_POST['endport'] ?? '');
		
		$natent['target'] = $_POST['localip'] ?? null;
		$natent['local-port'] = $_POST['localbeginport'] ?? null;
		$natent['interface'] = $_POST['interface'] ?? null;
		$natent['descr'] = $_POST['descr'] ?? null;
		
		if (isset($id) && !empty($a_nat[$id]))
			$a_nat[$id] = $natent;
		else
			$a_nat[] = $natent;
		
		touch($d_natconfdirty_path);
		
		if (!empty($_POST['autoadd']) && (($_POST['extaddr'] ?? null) != 'wan')) {
			/* auto-generate a matching firewall rule */
			$filterent = array();		
			$filterent['interface'] = $_POST['interface'] ?? null;
			$filterent['protocol'] = $_POST['proto'] ?? null;
			$filterent['source']['any'] = "";
			$filterent['destination']['address'] = $_POST['localip'] ?? null;
			
			$dstpfrom = $_POST['localbeginport'] ?? null;
			$dstpto = $dstpfrom + ($_POST['endport'] ?? null) - ($_POST['beginport'] ?? null);
			
			if ($dstpfrom == $dstpto)
				$filterent['destination']['port'] = $dstpfrom;
			else
				$filterent['destination']['port'] = $dstpfrom . "-" . $dstpto;
			
			$filterent['descr'] = "NAT " . ($_POST['descr'] ?? '');
			
			$config['filter']['rule'][] = $filterent;
			
			touch($d_filterconfdirty_path);
		}
		
		write_config();
		
		header("Location: firewall_nat.php");
		exit;
	}
}
?>
<?php include("fbegin.inc"); ?>
<script type="text/javascript">
<!--
function ext_change() {
	if (document.iform.beginport.selectedIndex == 0) {
		document.iform.beginport_cust.disabled = 0;
	} else {
		document.iform.beginport_cust.value = "";
		document.iform.beginport_cust.disabled = 1;
	}
	if (document.iform.endport.selectedIndex == 0) {
		document.iform.endport_cust.disabled = 0;
	} else {
		document.iform.endport_cust.value = "";
		document.iform.endport_cust.disabled = 1;
	}
	if (document.iform.localbeginport.selectedIndex == 0) {
		document.iform.localbeginport_cust.disabled = 0;
	} else {
		document.iform.localbeginport_cust.value = "";
		document.iform.localbeginport_cust.disabled = 1;
	}
}
function ext_rep_change() {
	document.iform.endport.selectedIndex = document.iform.beginport.selectedIndex;
	document.iform.localbeginport.selectedIndex = document.iform.beginport.selectedIndex;
}
//-->
</script>
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
            <form action="firewall_nat_edit.php" method="post" name="iform" id="iform">
              <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="content pane">
			  	<tr>
                  <td width="22%" valign="top" class="vncellreq">Interface</td>
                  <td width="78%" class="vtable">
					<select name="interface" class="formfld">
						<?php
						$interfaces = array('wan' => 'WAN', 'lan' => 'LAN');
						/* opt_interfaces() rather than counting up from 1: a deleted
						   optional interface no longer renumbers the rest, so the
						   numbering can have gaps and a counting loop would stop at the
						   first one. */
						foreach (opt_interfaces() as $optif) {
							$interfaces[$optif] = $config['interfaces'][$optif]['descr'] ?? null;
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
                  <td width="22%" valign="top" class="vncellreq">External address</td>
                  <td width="78%" class="vtable"> 
                    <select name="extaddr" class="formfld">
					  <option value="" <?php if (empty($pconfig['extaddr'])) echo "selected"; ?>>Interface address</option>
					  <option value="wan" <?php if (($pconfig['extaddr'] ?? null) == 'wan' ) echo "selected"; ?>>WAN address</option>		
                      <?php
					  if (is_array($config['nat']['servernat'] ?? null)):
						  foreach ($config['nat']['servernat'] as $sn):
							  $sn_ipaddr = $sn['ipaddr'] ?? '';
							  $sn_descr = $sn['descr'] ?? ''; ?>
                      <option value="<?=$sn_ipaddr;?>" <?php if ($sn_ipaddr == ($pconfig['extaddr'] ?? null)) echo "selected"; ?>><?=htmlspecialchars("{$sn_ipaddr} ({$sn_descr})");?></option>
                      <?php endforeach; endif; ?>
                    </select><br>
                    <span class="vexpl">
					If you want this rule to apply to another IP address than the IP address of the interface chosen above,
					select it here (you need to define IP addresses on the
					<a href="firewall_nat_server.php">Server NAT</a> page first).</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Protocol</td>
                  <td width="78%" class="vtable"> 
                    <select name="proto" class="formfld">
                      <?php $protocols = explode(" ", "TCP UDP TCP/UDP"); foreach ($protocols as $proto): ?>
                      <option value="<?=strtolower($proto);?>" <?php if (strtolower($proto) == ($pconfig['proto'] ?? null)) echo "selected"; ?>><?=htmlspecialchars($proto);?></option>
                      <?php endforeach; ?>
                    </select> <br> <span class="vexpl">Choose which IP protocol 
                    this rule should match.<br>
                    Hint: in most cases, you should specify <em>TCP</em> &nbsp;here.</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">External port 
                    range </td>
                  <td width="78%" class="vtable"> 
                    <table border="0" cellspacing="0" cellpadding="0">
                      <tr> 
                        <td>from:&nbsp;&nbsp;</td>
                        <td><select name="beginport" class="formfld" onChange="ext_rep_change();ext_change()">
                            <option value="">(other)</option>
                            <?php $bfound = 0; foreach ($wkports as $wkport => $wkportdesc): ?>
                            <option value="<?=$wkport;?>" <?php if ($wkport == ($pconfig['beginport'] ?? null)) {
																echo "selected";
																$bfound = 1;
															}?>>
							<?=htmlspecialchars($wkportdesc);?>
							</option>
                            <?php endforeach; ?>
                          </select> <input name="beginport_cust" type="text" size="5" value="<?php if (!$bfound) echo htmlspecialchars($pconfig['beginport'] ?? ''); ?>"></td>
                      </tr>
                      <tr> 
                        <td>to:</td>
                        <td><select name="endport" class="formfld" onChange="ext_change()">
                            <option value="">(other)</option>
                            <?php $bfound = 0; foreach ($wkports as $wkport => $wkportdesc): ?>
                            <option value="<?=$wkport;?>" <?php if ($wkport == ($pconfig['endport'] ?? null)) {
																echo "selected";
																$bfound = 1;
															}?>>
							<?=htmlspecialchars($wkportdesc);?>
							</option>
							<?php endforeach; ?>
                          </select> <input name="endport_cust" type="text" size="5" value="<?php if (!$bfound) echo htmlspecialchars($pconfig['endport'] ?? ''); ?>"></td>
                      </tr>
                    </table>
                    <br> <span class="vexpl">Specify the port or port range on 
                    the firewall's external address for this mapping.<br>
                    Hint: you can leave the <em>'to'</em> field empty if you only 
                    want to map a single port</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">NAT IP</td>
                  <td width="78%" class="vtable"> 
                    <?=$mandfldhtml;?><input name="localip" type="text" class="formfldalias" id="localip" size="20" value="<?=htmlspecialchars($pconfig['localip'] ?? '');?>"> 
                    <br> <span class="vexpl">Enter the internal IP address of 
                    the server on which you want to map the ports.<br>
                    e.g. <em>192.168.1.12</em></span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Local port</td>
                  <td width="78%" class="vtable"> 
                    <select name="localbeginport" class="formfld" onChange="ext_change()">
                      <option value="">(other)</option>
                      <?php $bfound = 0; foreach ($wkports as $wkport => $wkportdesc): ?>
                      <option value="<?=$wkport;?>" <?php if ($wkport == ($pconfig['localbeginport'] ?? null)) {
																echo "selected";
																$bfound = 1;
															}?>>
					  <?=htmlspecialchars($wkportdesc);?>
					  </option>
                      <?php endforeach; ?>
                    </select> <input name="localbeginport_cust" type="text" size="5" value="<?php if (!$bfound) echo htmlspecialchars($pconfig['localbeginport'] ?? ''); ?>"> 
                    <br>
                    <span class="vexpl">Specify the port on the machine with the 
                    IP address entered above. In case of a port range, specify 
                    the beginning port of the range (the end port will be calculated 
                    automatically).<br>
                    Hint: this is usually identical to the 'from' port above</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">Description</td>
                  <td width="78%" class="vtable"> 
                    <input name="descr" type="text" class="formfld" id="descr" size="40" value="<?=htmlspecialchars($pconfig['descr'] ?? '');?>"> 
                    <br> <span class="vexpl">You may enter a description here 
                    for your reference (not parsed).</span></td>
                </tr><?php if (!(isset($id) && !empty($a_nat[$id]))): ?>
                <tr> 
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%"> 
                    <input name="autoadd" type="checkbox" id="autoadd" value="yes">
                    <strong>Auto-add a firewall rule to permit traffic through 
                    this NAT rule</strong></td>
                </tr><?php endif; ?>
                <tr> 
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%"> 
                    <input name="Submit" type="submit" class="formbtn" value="Save"> 
                    <?php if (isset($id) && !empty($a_nat[$id])): ?>
                    <input name="id" type="hidden" value="<?=htmlspecialchars($id);?>"> 
                    <?php endif; ?>
                  </td>
                </tr>
              </table>
</form>
<script type="text/javascript">
<!--
ext_change();
//-->
</script>
<?php include("fend.inc"); ?>
