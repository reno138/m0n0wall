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

$pgtitle = array("Firewall", "Traffic shaper", "Edit rule");
require("guiconfig.inc");

if (!is_array($config['shaper']['rule'] ?? null)) {
	$config['shaper']['rule'] = array();
}
$a_shaper = &$config['shaper']['rule'];

$specialsrcdst = explode(" ", "any lan");

$id = $_GET['id'] ?? null;
if (isset($_POST['id']))
	$id = $_POST['id'] ?? null;
	
$after = $_GET['after'] ?? null;
if (isset($_POST['after']))
	$after = $_POST['after'] ?? null;
	
if (isset($_GET['dup'])) {
	$id = $_GET['dup'];
	$after = $_GET['dup'];
}
	
function is_specialnet($net) {
	global $specialsrcdst;
	
	if (in_array($net, $specialsrcdst) || strstr($net, "opt"))
		return true;
	else
		return false;
}
	
function address_to_pconfig($adr, &$padr, &$pmask, &$pnot, &$pbeginport, &$pendport) {
		
	if (isset($adr['any']))
		$padr = "any";
	else if (!empty($adr['network']))
		$padr = $adr['network'];
	else if (!empty($adr['address'])) {
		list($padr, $pmask) = array_pad(explode("/", $adr['address']), 2, null);
		if (!$pmask)
			$pmask = 32;
	}
	
	if (isset($adr['not']))
		$pnot = 1;
	else
		$pnot = 0;
	
	if (!empty($adr['port'])) {
		list($pbeginport, $pendport) = array_pad(explode("-", $adr['port']), 2, null);
		if (!$pendport)
			$pendport = $pbeginport;
	} else {
		$pbeginport = "any";
		$pendport = "any";
	}
}

function pconfig_to_address(&$adr, $padr, $pmask, $pnot, $pbeginport, $pendport) {
	
	$adr = array();
	
	if ($padr == "any")
		$adr['any'] = true;
	else if (is_specialnet($padr))
		$adr['network'] = $padr;
	else {
		$adr['address'] = $padr;
		if ($pmask != 32)
			$adr['address'] .= "/" . $pmask;
	}
	
	$adr['not'] = $pnot ? true : false;
	
	if (($pbeginport != 0) && ($pbeginport != "any")) {
		if ($pbeginport != $pendport)
			$adr['port'] = $pbeginport . "-" . $pendport;
		else
			$adr['port'] = $pbeginport;
	}
}

if (isset($id) && !empty($a_shaper[$id])) {
	$pconfig['interface'] = $a_shaper[$id]['interface'] ?? null;
	
	if (isset($a_shaper[$id]['protocol']))
		$pconfig['proto'] = $a_shaper[$id]['protocol'] ?? null;
	else
		$pconfig['proto'] = "any";
	
	address_to_pconfig($a_shaper[$id]['source'] ?? null, $pconfig['src'],
		$pconfig['srcmask'], $pconfig['srcnot'],
		$pconfig['srcbeginport'], $pconfig['srcendport']);
		
	address_to_pconfig($a_shaper[$id]['destination'] ?? null, $pconfig['dst'],
		$pconfig['dstmask'], $pconfig['dstnot'],
		$pconfig['dstbeginport'], $pconfig['dstendport']);
	
	if (isset($a_shaper[$id]['targetpipe'])) {
		$pconfig['target'] = "targetpipe:" . $a_shaper[$id]['targetpipe'];
	} else if (isset($a_shaper[$id]['targetqueue'])) {
		$pconfig['target'] = "targetqueue:" . $a_shaper[$id]['targetqueue'];
	}
	
	$pconfig['direction'] = $a_shaper[$id]['direction'] ?? null;
	$pconfig['iptos'] = $a_shaper[$id]['iptos'] ?? null;
	$pconfig['iplen'] = $a_shaper[$id]['iplen'] ?? null;
	$pconfig['tcpflags'] = $a_shaper[$id]['tcpflags'] ?? null;
	$pconfig['descr'] = $a_shaper[$id]['descr'] ?? null;
	$pconfig['disabled'] = isset($a_shaper[$id]['disabled']);
	
	if (($pconfig['srcbeginport'] ?? null) == 0) {
		$pconfig['srcbeginport'] = "any";
		$pconfig['srcendport'] = "any";
	}
	if (($pconfig['dstbeginport'] ?? null) == 0) {
		$pconfig['dstbeginport'] = "any";
		$pconfig['dstendport'] = "any";
	}
	
} else {
	/* defaults */
	$pconfig['src'] = "any";
	$pconfig['dst'] = "any";
}

if (isset($_GET['dup']))
	unset($id);

if ($_POST) {

	if ((($_POST['proto'] ?? null) != "tcp") && (($_POST['proto'] ?? null) != "udp") && (($_POST['proto'] ?? null) != "any")) {
		$_POST['srcbeginport'] = 0;
		$_POST['srcendport'] = 0;
		$_POST['dstbeginport'] = 0;
		$_POST['dstendport'] = 0;
	} else {
	
		if (!empty($_POST['srcbeginport_cust']) && empty($_POST['srcbeginport']))
			$_POST['srcbeginport'] = $_POST['srcbeginport_cust'] ?? null;
		if (!empty($_POST['srcendport_cust']) && empty($_POST['srcendport']))
			$_POST['srcendport'] = $_POST['srcendport_cust'] ?? null;
	
		if (($_POST['srcbeginport'] ?? null) == "any") {
			$_POST['srcbeginport'] = 0;
			$_POST['srcendport'] = 0;
		} else {			
			if (empty($_POST['srcendport']))
				$_POST['srcendport'] = $_POST['srcbeginport'] ?? null;
		}
		if (($_POST['srcendport'] ?? null) == "any")
			$_POST['srcendport'] = $_POST['srcbeginport'] ?? null;
		
		if (!empty($_POST['dstbeginport_cust']) && empty($_POST['dstbeginport']))
			$_POST['dstbeginport'] = $_POST['dstbeginport_cust'] ?? null;
		if (!empty($_POST['dstendport_cust']) && empty($_POST['dstendport']))
			$_POST['dstendport'] = $_POST['dstendport_cust'] ?? null;
		
		if (($_POST['dstbeginport'] ?? null) == "any") {
			$_POST['dstbeginport'] = 0;
			$_POST['dstendport'] = 0;
		} else {			
			if (empty($_POST['dstendport']))
				$_POST['dstendport'] = $_POST['dstbeginport'] ?? null;
		}
		if (($_POST['dstendport'] ?? null) == "any")
			$_POST['dstendport'] = $_POST['dstbeginport'] ?? null;		
	}
		
	if (is_specialnet($_POST['srctype'] ?? '')) {
		$_POST['src'] = $_POST['srctype'] ?? null;
		$_POST['srcmask'] = 0;
	} else if (($_POST['srctype'] ?? null) == "single") {
		$_POST['srcmask'] = 32;
	}
	if (is_specialnet($_POST['dsttype'] ?? '')) {
		$_POST['dst'] = $_POST['dsttype'] ?? null;
		$_POST['dstmask'] = 0;
	}  else if (($_POST['dsttype'] ?? null) == "single") {
		$_POST['dstmask'] = 32;
	}
	
	$intos = array();
	foreach ($iptos as $tos) {
		if (($_POST['iptos_' . $tos] ?? null) == "on")
			$intos[] = $tos;
		else if (($_POST['iptos_' . $tos] ?? null) == "off")
			$intos[] = "!" . $tos;
	}
	$_POST['iptos'] = join(",", $intos);
	
	$intcpflags = array();
	foreach ($tcpflags as $tcpflag) {
		if (($_POST['tcpflags_' . $tcpflag] ?? null) == "on")
			$intcpflags[] = $tcpflag;
		else if (($_POST['tcpflags_' . $tcpflag] ?? null) == "off")
			$intcpflags[] = "!" . $tcpflag;
	}
	$_POST['tcpflags'] = join(",", $intcpflags);
	
	$input_errors = array();
	$pconfig = $_POST;

	/* input validation */
	$reqdfields = explode(" ", "target proto src dst");
	$reqdfieldsn = explode(",", "Target,Protocol,Source,Destination");
	
	if (!(is_specialnet($_POST['srctype'] ?? '') || (($_POST['srctype'] ?? null) == "single"))) {
		$reqdfields[] = "srcmask";
		$reqdfieldsn[] = "Source bit count";
	}
	if (!(is_specialnet($_POST['dsttype'] ?? '') || (($_POST['dsttype'] ?? null) == "single"))) {
		$reqdfields[] = "dstmask";
		$reqdfieldsn[] = "Destination bit count";
	}
	
	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
	
	if (empty($_POST['srcbeginport'])) {
		$_POST['srcbeginport'] = 0;
		$_POST['srcendport'] = 0;
	}
	if (empty($_POST['dstbeginport'])) {
		$_POST['dstbeginport'] = 0;
		$_POST['dstendport'] = 0;
	}
	
	if ((!empty($_POST['srcbeginport']) && !is_port($_POST['srcbeginport']))) {
		$input_errors[] = "The start source port must be an integer between 1 and 65535.";
	}
	if ((!empty($_POST['srcendport']) && !is_port($_POST['srcendport']))) {
		$input_errors[] = "The end source port must be an integer between 1 and 65535.";
	}
	if ((!empty($_POST['dstbeginport']) && !is_port($_POST['dstbeginport']))) {
		$input_errors[] = "The start destination port must be an integer between 1 and 65535.";
	}
	if ((!empty($_POST['dstendport']) && !is_port($_POST['dstendport']))) {
		$input_errors[] = "The end destination port must be an integer between 1 and 65535.";
	}
	
	if (!is_specialnet($_POST['srctype'] ?? '')) {
		if ((!empty($_POST['src']) && !is_ipaddroranyalias($_POST['src']))) {
			$input_errors[] = "A valid source IP address or alias must be specified.";
		}
		if ((!empty($_POST['srcmask']) && !is_numericint($_POST['srcmask']))) {
			$input_errors[] = "A valid source bit count must be specified.";
		}
	}
	if (!is_specialnet($_POST['dsttype'] ?? '')) {
		if ((!empty($_POST['dst']) && !is_ipaddroranyalias($_POST['dst']))) {
			$input_errors[] = "A valid destination IP address or alias must be specified.";
		}
		if ((!empty($_POST['dstmask']) && !is_numericint($_POST['dstmask']))) {
			$input_errors[] = "A valid destination bit count must be specified.";
		}
	}
	
	if (($_POST['srcbeginport'] ?? null) > ($_POST['srcendport'] ?? null)) {
		/* swap */
		$tmp = $_POST['srcendport'] ?? null;
		$_POST['srcendport'] = $_POST['srcbeginport'] ?? null;
		$_POST['srcbeginport'] = $tmp;
	}
	if (($_POST['dstbeginport'] ?? null) > ($_POST['dstendport'] ?? null)) {
		/* swap */
		$tmp = $_POST['dstendport'] ?? null;
		$_POST['dstendport'] = $_POST['dstbeginport'] ?? null;
		$_POST['dstbeginport'] = $tmp;
	}
	
	if ((!empty($_POST['iplen']) && !preg_match("/^(\d+)(-(\d+))?$/", $_POST['iplen']))) {
		$input_errors[] = "The IP packet length must be an integer or a range (from-to).";
	}

	if (empty($input_errors)) {
		$shaperent = array();
		$shaperent['interface'] = $_POST['interface'] ?? null;
		
		if (($_POST['proto'] ?? null) != "any")
			$shaperent['protocol'] = $_POST['proto'] ?? null;
		else
			unset($shaperent['protocol']);
		
		pconfig_to_address($shaperent['source'], $_POST['src'] ?? null,
			$_POST['srcmask'] ?? null, $_POST['srcnot'] ?? null,
			$_POST['srcbeginport'] ?? null, $_POST['srcendport'] ?? null);
			
		pconfig_to_address($shaperent['destination'], $_POST['dst'] ?? null,
			$_POST['dstmask'] ?? null, $_POST['dstnot'] ?? null,
			$_POST['dstbeginport'] ?? null, $_POST['dstendport'] ?? null);
		
		$shaperent['direction'] = $_POST['direction'] ?? null;
		$shaperent['iplen'] = $_POST['iplen'] ?? null;
		$shaperent['iptos'] = $_POST['iptos'] ?? null;
		$shaperent['tcpflags'] = $_POST['tcpflags'] ?? null;
		$shaperent['descr'] = $_POST['descr'] ?? null;
		$shaperent['disabled'] = !empty($_POST['disabled']) ? true : false;
		
		list($targettype,$target) = array_pad(explode(":", $_POST['target'] ?? ''), 2, null);
		$shaperent[$targettype] = $target;
		
		if (isset($id) && !empty($a_shaper[$id])) {
			// Scheduler: update matching jobs
			croen_update_job(Array('shaper-enable_rule', 'shaper-disable_rule'), $a_shaper[$id]['descr'], ($shaperent['descr'] != '' ? $shaperent['descr'] : FALSE));
			$a_shaper[$id] = $shaperent;
		} else {
			if (is_numeric($after))
				array_splice($a_shaper, $after+1, 0, array($shaperent));
			else
				$a_shaper[] = $shaperent;
		}
		
		write_config();
		touch($d_shaperconfdirty_path);
		header("Location: firewall_shaper.php");
		exit;
	}
}
?>
<?php include("fbegin.inc"); ?>
<script type="text/javascript">
<!--
var portsenabled = 1;

function ext_change() {
	if ((document.iform.srcbeginport.selectedIndex == 0) && portsenabled) {
		document.iform.srcbeginport_cust.disabled = 0;
	} else {
		document.iform.srcbeginport_cust.value = "";
		document.iform.srcbeginport_cust.disabled = 1;
	}
	if ((document.iform.srcendport.selectedIndex == 0) && portsenabled) {
		document.iform.srcendport_cust.disabled = 0;
	} else {
		document.iform.srcendport_cust.value = "";
		document.iform.srcendport_cust.disabled = 1;
	}
	if ((document.iform.dstbeginport.selectedIndex == 0) && portsenabled) {
		document.iform.dstbeginport_cust.disabled = 0;
	} else {
		document.iform.dstbeginport_cust.value = "";
		document.iform.dstbeginport_cust.disabled = 1;
	}
	if ((document.iform.dstendport.selectedIndex == 0) && portsenabled) {
		document.iform.dstendport_cust.disabled = 0;
	} else {
		document.iform.dstendport_cust.value = "";
		document.iform.dstendport_cust.disabled = 1;
	}
	
	if (!portsenabled) {
		document.iform.srcbeginport.disabled = 1;
		document.iform.srcendport.disabled = 1;
		document.iform.dstbeginport.disabled = 1;
		document.iform.dstendport.disabled = 1;
	} else {
		document.iform.srcbeginport.disabled = 0;
		document.iform.srcendport.disabled = 0;
		document.iform.dstbeginport.disabled = 0;
		document.iform.dstendport.disabled = 0;
	}
}

function typesel_change() {
	switch (document.iform.srctype.selectedIndex) {
		case 1:	/* single */
			document.iform.src.disabled = 0;
			document.iform.srcmask.value = "";
			document.iform.srcmask.disabled = 1;
			break;
		case 2:	/* network */
			document.iform.src.disabled = 0;
			document.iform.srcmask.disabled = 0;
			break;
		default:
			document.iform.src.value = "";
			document.iform.src.disabled = 1;
			document.iform.srcmask.value = "";
			document.iform.srcmask.disabled = 1;
			break;
	}
	switch (document.iform.dsttype.selectedIndex) {
		case 1:	/* single */
			document.iform.dst.disabled = 0;
			document.iform.dstmask.value = "";
			document.iform.dstmask.disabled = 1;
			break;
		case 2:	/* network */
			document.iform.dst.disabled = 0;
			document.iform.dstmask.disabled = 0;
			break;
		default:
			document.iform.dst.value = "";
			document.iform.dst.disabled = 1;
			document.iform.dstmask.value = "";
			document.iform.dstmask.disabled = 1;
			break;
	}
}

function proto_change() {
	if (document.iform.proto.selectedIndex < 2 || document.iform.proto.selectedIndex == 8) {
		portsenabled = 1;
	} else {
		portsenabled = 0;
	}
	
	ext_change();
}

function src_rep_change() {
	document.iform.srcendport.selectedIndex = document.iform.srcbeginport.selectedIndex;
}
function dst_rep_change() {
	document.iform.dstendport.selectedIndex = document.iform.dstbeginport.selectedIndex;
}
//-->
</script>
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
<?php if (is_array($config['shaper']['pipe'] ?? null) && (count($config['shaper']['pipe']) > 0)): ?>
            <form action="firewall_shaper_edit.php" method="post" name="iform" id="iform">
              <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="content pane">
                <tr> 
                  <td valign="top" class="vncellreq">Target</td>
                  <td class="vtable"><select name="target" class="formfld">
                      <?php 
	       if (is_array($config['shaper']['pipe'] ?? null) && count($config['shaper']['pipe']) > 0):
					  foreach ($config['shaper']['pipe'] as $pipei => $pipe): ?>
                      <option value="<?="targetpipe:$pipei";?>" <?php if ("targetpipe:$pipei" == ($pconfig['target'] ?? null)) echo "selected"; ?>> 
                      <?php
					  	echo htmlspecialchars("Pipe " . ($pipei + 1));
						if (!empty($pipe['descr']))
							echo htmlspecialchars(" (" . $pipe['descr'] . ")");
					  ?>
                      </option>
                      <?php endforeach; endif;
               if (is_array($config['shaper']['queue'] ?? null) && count($config['shaper']['queue']) > 0):
					  foreach ($config['shaper']['queue'] as $queuei => $queue): ?>
                      <option value="<?="targetqueue:$queuei";?>" <?php if ("targetqueue:$queuei" == ($pconfig['target'] ?? null)) echo "selected"; ?>> 
                      <?php
					  	echo htmlspecialchars("Queue " . ($queuei + 1));
						if (!empty($queue['descr']))
							echo htmlspecialchars(" (" . $queue['descr'] . ")");
					  ?>
                      </option>
                      <?php endforeach; endif; ?>
                    </select> <br>
                    <span class="vexpl">Choose a pipe or queue where packets that 
                    match this rule should be sent.</span></td>
                </tr>
                <tr>
                  <td valign="top" class="vncellreq">Disabled</td>
                  <td class="vtable">
                    <input name="disabled" type="checkbox" id="disabled" value="yes" <?php if (!empty($pconfig['disabled'])) echo "checked"; ?>>
                    <strong>Disable this rule</strong><br>
                    <span class="vexpl">Set this option to disable this rule without removing it from the list.</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Interface</td>
                  <td width="78%" class="vtable"><select name="interface" class="formfld">
                      <?php $interfaces = array('lan' => 'LAN', 'wan' => 'WAN');
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
                    </select> <br>
                    <span class="vexpl">Choose which interface packets must pass 
                    through to match this rule.</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Protocol</td>
                  <td width="78%" class="vtable"><select name="proto" class="formfld" onchange="proto_change()">
                      <?php $protocols = explode(" ", "TCP UDP ICMP ESP AH GRE IPv6 IGMP any"); foreach ($protocols as $proto): ?>
                      <option value="<?=strtolower($proto);?>" <?php if (strtolower($proto) == ($pconfig['proto'] ?? null)) echo "selected"; ?>> 
                      <?=htmlspecialchars($proto);?>
                      </option>
                      <?php endforeach; ?>
                    </select> <br> <span class="vexpl">Choose which IP protocol 
                    this rule should match.<br>
                    Hint: in most cases, you should specify <em>TCP</em> &nbsp;here.</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Source</td>
                  <td width="78%" class="vtable"> <input name="srcnot" type="checkbox" id="srcnot" value="yes" <?php if (!empty($pconfig['srcnot'])) echo "checked"; ?>> 
                    <strong>not</strong><br>
                    Use this option to invert the sense of the match.<br> <br> 
                    <table border="0" cellspacing="0" cellpadding="0" summary="type-address widget">
                      <tr> 
                        <td>Type:&nbsp;&nbsp;</td>
						<td></td>
                        <td><select name="srctype" class="formfld" onChange="typesel_change()">
                            <?php $sel = is_specialnet($pconfig['src'] ?? ''); ?>
                            <option value="any" <?php if (($pconfig['src'] ?? null) == "any") { echo "selected"; } ?>> 
                            any</option>
                            <option value="single" <?php if ((($pconfig['srcmask'] ?? null) == 32) && !$sel) { echo "selected"; $sel = 1; } ?>> 
                            Single host or alias</option>
                            <option value="network" <?php if (!$sel) echo "selected"; ?>> 
                            Network</option>
                            <option value="lan" <?php if (($pconfig['src'] ?? null) == "lan") { echo "selected"; } ?>> 
                            LAN subnet</option>
                            <?php foreach (opt_interfaces() as $i => $optif): ?>
                            <option value="opt<?=$i;?>" <?php if (($pconfig['src'] ?? null) == "opt" . $i) { echo "selected"; } ?>> 
                            <?=htmlspecialchars($config['interfaces'][$optif]['descr'] ?? '');?>
                            subnet</option>
                            <?php endforeach; ?>
                          </select></td>
                      </tr>
                      <tr> 
                        <td>Address:&nbsp;&nbsp;</td>
						<td><?=$mandfldhtmlspc;?></td>
                        <td><input name="src" type="text" class="formfldalias" id="src" size="20" value="<?php if (!is_specialnet($pconfig['src'] ?? '')) echo htmlspecialchars($pconfig['src'] ?? '');?>">
                          / 
                          <select name="srcmask" class="formfld" id="srcmask">
                            <?php for ($i = 31; $i > 0; $i--): ?>
                            <option value="<?=$i;?>" <?php if ($i == ($pconfig['srcmask'] ?? null)) echo "selected"; ?>> 
                            <?=$i;?>
                            </option>
                            <?php endfor; ?>
                          </select></td>
                      </tr>
                    </table></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Source port range 
                  </td>
                  <td width="78%" class="vtable"> <table border="0" cellspacing="0" cellpadding="0" summary="from-to widget">
                      <tr> 
                        <td>from:&nbsp;&nbsp;</td>
                        <td><select name="srcbeginport" class="formfld" onchange="src_rep_change();ext_change()">
                            <option value="">(other)</option>
                            <option value="any" <?php $bfound = 0; if (($pconfig['srcbeginport'] ?? null) == "any") { echo "selected"; $bfound = 1; } ?>>any</option>
                            <?php foreach ($wkports as $wkport => $wkportdesc): ?>
                            <option value="<?=$wkport;?>" <?php if ($wkport == ($pconfig['srcbeginport'] ?? null)) {
																echo "selected";
																$bfound = 1;
															}?>> 
                            <?=htmlspecialchars($wkportdesc);?>
                            </option>
                            <?php endforeach; ?>
                          </select> <input name="srcbeginport_cust" type="text" size="5" value="<?php if (!$bfound && !empty($pconfig['srcbeginport'])) echo htmlspecialchars($pconfig['srcbeginport'] ?? ''); ?>"></td>
                      </tr>
                      <tr> 
                        <td>to:</td>
                        <td><select name="srcendport" class="formfld" onchange="ext_change()">
                            <option value="">(other)</option>
                            <option value="any" <?php $bfound = 0; if (($pconfig['srcendport'] ?? null) == "any") { echo "selected"; $bfound = 1; } ?>>any</option>
                            <?php foreach ($wkports as $wkport => $wkportdesc): ?>
                            <option value="<?=$wkport;?>" <?php if ($wkport == ($pconfig['srcendport'] ?? null)) {
																echo "selected";
																$bfound = 1;
															}?>> 
                            <?=htmlspecialchars($wkportdesc);?>
                            </option>
                            <?php endforeach; ?>
                          </select> <input name="srcendport_cust" type="text" size="5" value="<?php if (!$bfound && !empty($pconfig['srcendport'])) echo htmlspecialchars($pconfig['srcendport'] ?? ''); ?>"></td>
                      </tr>
                    </table>
                    <br> <span class="vexpl">Specify the port or port range for 
                    the source of the packet for this rule.<br>
                    Hint: you can leave the <em>'to'</em> field empty if you only 
                    want to filter a single port</span></td>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Destination</td>
                  <td width="78%" class="vtable"> <input name="dstnot" type="checkbox" id="dstnot" value="yes" <?php if (!empty($pconfig['dstnot'])) echo "checked"; ?>> 
                    <strong>not</strong><br>
                    Use this option to invert the sense of the match.<br> <br> 
                    <table border="0" cellspacing="0" cellpadding="0" summary="type-address widget">
                      <tr> 
                        <td>Type:&nbsp;&nbsp;</td>
						<td></td>
                        <td><select name="dsttype" class="formfld" onChange="typesel_change()">
                            <?php $sel = is_specialnet($pconfig['dst'] ?? ''); ?>
                            <option value="any" <?php if (($pconfig['dst'] ?? null) == "any") { echo "selected"; } ?>> 
                            any</option>
                            <option value="single" <?php if ((($pconfig['dstmask'] ?? null) == 32) && !$sel) { echo "selected"; $sel = 1; } ?>> 
                            Single host or alias</option>
                            <option value="network" <?php if (!$sel) echo "selected"; ?>> 
                            Network</option>
                            <option value="lan" <?php if (($pconfig['dst'] ?? null) == "lan") { echo "selected"; } ?>> 
                            LAN subnet</option>
                            <?php foreach (opt_interfaces() as $i => $optif): ?>
                            <option value="opt<?=$i;?>" <?php if (($pconfig['dst'] ?? null) == "opt" . $i) { echo "selected"; } ?>> 
                            <?=htmlspecialchars($config['interfaces'][$optif]['descr'] ?? '');?>
                            subnet</option>
                            <?php endforeach; ?>
                          </select> </td>
                      </tr>
                      <tr> 
                        <td>Address:&nbsp;&nbsp;</td>
						<td><?=$mandfldhtmlspc;?></td>
                        <td><input name="dst" type="text" class="formfldalias" id="dst" size="20" value="<?php if (!is_specialnet($pconfig['dst'] ?? '')) echo htmlspecialchars($pconfig['dst'] ?? '');?>">
                          / 
                          <select name="dstmask" class="formfld" id="dstmask">
                            <?php for ($i = 31; $i > 0; $i--): ?>
                            <option value="<?=$i;?>" <?php if ($i == ($pconfig['dstmask'] ?? null)) echo "selected"; ?>> 
                            <?=$i;?>
                            </option>
                            <?php endfor; ?>
                          </select></td>
                      </tr>
                    </table></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Destination port 
                    range </td>
                  <td width="78%" class="vtable"> <table border="0" cellspacing="0" cellpadding="0" summary="from-to widget">
                      <tr> 
                        <td>from:&nbsp;&nbsp;</td>
                        <td><select name="dstbeginport" class="formfld" onchange="dst_rep_change();ext_change()">
                            <option value="">(other)</option>
                            <option value="any" <?php $bfound = 0; if (($pconfig['dstbeginport'] ?? null) == "any") { echo "selected"; $bfound = 1; } ?>>any</option>
                            <?php foreach ($wkports as $wkport => $wkportdesc): ?>
                            <option value="<?=$wkport;?>" <?php if ($wkport == ($pconfig['dstbeginport'] ?? null)) {
																echo "selected";
																$bfound = 1;
															}?>> 
                            <?=htmlspecialchars($wkportdesc);?>
                            </option>
                            <?php endforeach; ?>
                          </select> <input name="dstbeginport_cust" type="text" size="5" value="<?php if (!$bfound && !empty($pconfig['dstbeginport'])) echo htmlspecialchars($pconfig['dstbeginport'] ?? ''); ?>"></td>
                      </tr>
                      <tr> 
                        <td>to:</td>
                        <td><select name="dstendport" class="formfld" onchange="ext_change()">
                            <option value="">(other)</option>
                            <option value="any" <?php $bfound = 0; if (($pconfig['dstendport'] ?? null) == "any") { echo "selected"; $bfound = 1; } ?>>any</option>
                            <?php foreach ($wkports as $wkport => $wkportdesc): ?>
                            <option value="<?=$wkport;?>" <?php if ($wkport == ($pconfig['dstendport'] ?? null)) {
																echo "selected";
																$bfound = 1;
															}?>> 
                            <?=htmlspecialchars($wkportdesc);?>
                            </option>
                            <?php endforeach; ?>
                          </select> <input name="dstendport_cust" type="text" size="5" value="<?php if (!$bfound && !empty($pconfig['dstendport'])) echo htmlspecialchars($pconfig['dstendport'] ?? ''); ?>"></td>
                      </tr>
                    </table>
                    <br> <span class="vexpl">Specify the port or port range for 
                    the destination of the packet for this rule.<br>
                    Hint: you can leave the <em>'to'</em> field empty if you only 
                    want to filter a single port</span></td>
                <tr> 
                  <td valign="top" class="vncell">Direction</td>
                  <td class="vtable"> <select name="direction" class="formfld">
                      <option value="" <?php if (empty($pconfig['direction'])) echo "selected"; ?>>any</option>
                      <option value="in" <?php if (($pconfig['direction'] ?? null) == "in") echo "selected"; ?>>in</option>
                      <option value="out" <?php if (($pconfig['direction'] ?? null) == "out") echo "selected"; ?>>out</option>
                    </select> <br>
                    Use this to match only packets travelling in a given direction 
                    on the interface specified above (as seen from the firewall's 
                    perspective). </td>
                </tr>
				<tr> 
                  <td width="22%" valign="top" class="vncell">IP Type of Service (TOS)</td>
                  <td width="78%" class="vtable"> <table border="0" cellspacing="0" cellpadding="0">
                      <?php 
				  $iniptos = explode(",", $pconfig['iptos'] ?? '');
				  foreach ($iptos as $tos): $dontcare = true; ?>
                      <tr> 
                        <td width="80" nowrap><strong> 
			  <?php echo $tos;?>
                          </strong></td>
                        <td nowrap> <input type="radio" name="iptos_<?=$tos;?>" value="on" <?php if (array_search($tos, $iniptos) !== false) { echo "checked"; $dontcare = false; }?>>
                          yes&nbsp;&nbsp;&nbsp;</td>
                        <td nowrap> <input type="radio" name="iptos_<?=$tos;?>" value="off" <?php if (array_search("!" . $tos, $iniptos) !== false) { echo "checked"; $dontcare = false; }?>>
                          no&nbsp;&nbsp;&nbsp;</td>
                        <td nowrap> <input type="radio" name="iptos_<?=$tos;?>" value="" <?php if ($dontcare) echo "checked";?>>
                          don't care</td>
                      </tr>
                      <?php endforeach; ?>
                    </table>
                    <span class="vexpl">Use this to match packets according to their IP TOS values.
                    </span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">IP packet length</td>
                  <td width="78%" class="vtable"><input name="iplen" type="text" id="iplen" size="10" value="<?=htmlspecialchars($pconfig['iplen'] ?? '');?>"> 
                    <br>
                    Setting this makes the rule match packets of a given length 
                    (either a single value or a range in the syntax <em>from-to</em>, 
                    e.g. 0-80). </td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">TCP flags</td>
                  <td width="78%" class="vtable"> <table border="0" cellspacing="0" cellpadding="0" summary="tcp flags widget">
                      <?php 
				  $inflags = explode(",", $pconfig['tcpflags'] ?? '');
				  foreach ($tcpflags as $tcpflag): $dontcare = true; ?>
                      <tr> 
                        <td width="40" nowrap><strong> 
                          <?=strtoupper($tcpflag);?>
                          </strong></td>
                        <td nowrap> <input type="radio" name="tcpflags_<?=$tcpflag;?>" value="on" <?php if (array_search($tcpflag, $inflags) !== false) { echo "checked"; $dontcare = false; }?>>
                          set&nbsp;&nbsp;&nbsp;</td>
                        <td nowrap> <input type="radio" name="tcpflags_<?=$tcpflag;?>" value="off" <?php if (array_search("!" . $tcpflag, $inflags) !== false) { echo "checked"; $dontcare = false; }?>>
                          cleared&nbsp;&nbsp;&nbsp;</td>
                        <td nowrap> <input type="radio" name="tcpflags_<?=$tcpflag;?>" value="" <?php if ($dontcare) echo "checked";?>>
                          don't care</td>
                      </tr>
                      <?php endforeach; ?>
                    </table>
                    <span class="vexpl">Use this to choose TCP flags that must 
                    be set or cleared for this rule to match.</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">Description</td>
                  <td width="78%" class="vtable"> <input name="descr" type="text" class="formfld" id="descr" size="40" value="<?=htmlspecialchars($pconfig['descr'] ?? '');?>"> 
                    <br> <span class="vexpl">You may enter a description here 
                    for your reference (not parsed).</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%"> <input name="Submit" type="submit" class="formbtn" value="Save"> 
                    <?php if (isset($id) && !empty($a_shaper[$id])): ?>
                    <input name="id" type="hidden" value="<?=htmlspecialchars($id);?>">
                    <?php endif; ?>
					<input name="after" type="hidden" value="<?=htmlspecialchars($after);?>">
                  </td>
                </tr>
              </table>
</form>
<script type="text/javascript">
<!--
ext_change();
typesel_change();
proto_change();
//-->
</script>
<?php else: ?>
<p><strong>You need to create a pipe or queue before you can add a new rule.</strong></p>
<?php endif; ?>
<?php include("fend.inc"); ?>
