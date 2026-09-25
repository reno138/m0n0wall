#!/usr/local/bin/php
<?php 
/*
	$Id$
	part of m0n0wall (http://m0n0.ch/wall)
	
	Copyright (C) 2003-2004 Justin Ellison <justin@techadvise.com>.
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

$pgtitle = array("Services", "DHCP relay");
require("guiconfig.inc");

/* The DHCP server the WAN itself leased from, or null if there is not one.
 *
 * Rewritten, because every part of the old version was broken against this
 * base system:
 *
 *   - it read /var/db/dhclient.leases, a filename FreeBSD's base dhclient
 *     never creates. file() returned false and count(false) is a TypeError in
 *     PHP 8, so simply ticking "proxy requests to the DHCP server on the WAN
 *     subnet" and saving returned a blank 500 page. The base client (which is
 *     OpenBSD-derived, not ISC) appends the interface name, and the port does
 *     not pass -l, so the path is the compiled default plus ".<ifname>".
 *   - the end-of-lease test compared against "}" while file() keeps the
 *     trailing newline, so the per-lease reset never fired.
 *   - the interface test compared a preg_match RESULT ARRAY against the whole
 *     WAN interface config ARRAY, which could not be equal.
 *
 * Reading the WAN's own lease file removes the need to match the interface at
 * all: every lease in it belongs to that interface, so the last
 * dhcp-server-identifier in the file is the current server.
 */
function get_wan_dhcp_server() {
	global $config, $g;

	$wanif = $config['interfaces']['wan']['if'] ?? '';
	if ($wanif === '')
		return null;

	$dhclientfn = $g['vardb_path'] . "/dhclient.leases." . $wanif;
	if (!is_readable($dhclientfn))
		return null;

	$leases = @file($dhclientfn, FILE_IGNORE_NEW_LINES);
	if (!is_array($leases))
		return null;

	/* last one wins: dhclient appends, so the newest lease is at the end */
	$server = null;
	foreach ($leases as $line) {
		if (preg_match('/dhcp-server-identifier\s+(\d+\.\d+\.\d+\.\d+)\s*;/', $line, $m))
			$server = $m[1];
	}
	return $server;
}

$if = $_GET['if'] ?? null;
if (!empty($_POST['if']))
	$if = $_POST['if'];
	
$iflist = array("lan" => "LAN");

/* Enumerate the OPTs with opt_interfaces() rather than counting up from 1:
   deleting an optional interface no longer renumbers the others, so the
   numbering can have gaps and a counting loop would stop at the first one --
   losing the relay tab for every interface past it. */
foreach (opt_interfaces() as $optif) {
	$oc = $config['interfaces'][$optif];
	
	if (isset($oc['enable']) && !empty($oc['if']) && empty($oc['bridge'])) {
		/* ?? null, not ?? '': this value is tested with isset() below, and an
			   interface with no <descr> must stay unset so $if falls back to lan. */
			$iflist[$optif] = $oc['descr'] ?? null;
	}
}

if (!$if || !isset($iflist[$if]))
	$if = "lan";

$pconfig['enable'] = isset($config['dhcrelay'][$if]['enable']);
$pconfig['server'] = $config['dhcrelay']['server'] ?? null;
$pconfig['proxydhcp'] = isset($config['dhcrelay']['proxydhcp']);
$pconfig['agentoption'] = isset($config['dhcrelay']['agentoption']);

$ifcfg = $config['interfaces'][$if];


if ($_POST) {

	unset($input_errors);
	$pconfig = $_POST;

	/* input validation */
	if (!empty($_POST['enable'])) {
		if (isset($_POST['proxydhcp'])) {
			$_POST['server'] = get_wan_dhcp_server();
			/* Say why rather than leaving the generic "required field" error:
			   the field is deliberately filled in for the user here, and it can
			   only be empty because the WAN has no DHCP lease to learn from. */
			if (empty($_POST['server']))
				$input_errors[] = "The DHCP server on the WAN subnet could not be " .
				    "determined -- the WAN interface has no DHCP lease. Set the WAN to " .
				    "DHCP and wait for it to obtain an address, or enter the server " .
				    "address manually instead of proxying.";
		}
		$reqdfields = explode(" ", "server");
		$reqdfieldsn = explode(",", "Destination Server");
		
		do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
		
		if ((!empty($_POST['server']) && !is_ipaddr($_POST['server']))) 
			$input_errors[] = "A valid Destination Server IP address  must be specified.";
		
		if (!$input_errors) {
			/* make sure that the DHCP server isn't enabled on this interface */
			if (isset($config['dhcpd'][$if]['enable'])) 
				$input_errors[] = "You must disable the DHCP server on the {$iflist[$if]} interface before enabling the DHCP Relay.";
			
			/* make sure that the DHCP server isn't running on any of the implied interfaces */
			foreach ($config['interfaces'] as $ifname => $ifcfg) {
				$subnet = ($ifcfg['ipaddr'] ?? '') . "/" . ($ifcfg['subnet'] ?? '');
				if (ip_in_subnet($_POST['server'],$subnet)) 
					$destif = $ifname;	
			}	
			if (!isset($destif)) 
				$destif = "wan";
			if (isset($config['dhcpd'][$destif]['enable']) && !$input_errors)
				$input_errors[] = "You must disable the DHCP server on the {$destif} interface before enabling the DHCP Relay.";
				
			/* if proxydhcp is selected, make sure DHCP is enabled on WAN */
			if (isset($config['dhcrelay']['proxydhcp']) && ($config['interfaces']['wan']['ipaddr'] ?? null) != "dhcp") 
				$input_errors[] = "You must have DHCP active on the WAN interface before enabling the DHCP proxy option.";
		}
	}

	if (!$input_errors) {
		$config['dhcrelay']['agentoption'] = !empty($_POST['agentoption']) ? true : false;
		$config['dhcrelay']['proxydhcp'] = !empty($_POST['proxydhcp']) ? true : false;
		$config['dhcrelay']['server'] = $_POST['server'] ?? null;
		$config['dhcrelay'][$if]['enable'] = !empty($_POST['enable']) ? true : false;
		
		write_config();
		
		$retval = 0;
		if (!file_exists($d_sysrebootreqd_path)) {
			config_lock();
			$retval = services_dhcrelay_configure();
			config_unlock();
		}
		$savemsg = get_std_save_message($retval);
		
	}
}

?>
<?php include("fbegin.inc"); ?>
<script type="text/javascript">
<!--
function enable_change(enable_over) {
	if (document.iform.enable.checked || enable_over) {
		document.iform.server.disabled = 0;
		document.iform.agentoption.disabled = 0;
		document.iform.proxydhcp.disabled = 0;
	} else {
		document.iform.server.disabled = 1;
		document.iform.agentoption.disabled = 1;
		document.iform.proxydhcp.disabled = 1;
	}
	if (document.iform.proxydhcp.checked) {
		document.iform.server.disabled = 1;
	}
}
//-->
</script>
<form action="services_dhcp_relay.php" method="post" name="iform" id="iform">
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
<?php if (!empty($savemsg)) print_info_box($savemsg); ?>
<table width="100%" border="0" cellpadding="0" cellspacing="0" summary="tab pane">
  <tr><td class="tabnavtbl">
  <ul id="tabnav">
<?php $i = 0; foreach ($iflist as $ifent => $ifname):
	if ($ifent == $if): ?>
    <li class="tabact"><?=htmlspecialchars($ifname);?></li>
<?php else: ?>
    <li class="<?php if ($i == 0) echo "tabinact1"; else echo "tabinact";?>"><a href="services_dhcp_relay.php?if=<?=$ifent;?>"><?=htmlspecialchars($ifname);?></a></li>
<?php endif; ?>
<?php $i++; endforeach; ?>
  </ul>
  </td></tr>
  <tr> 
    <td class="tabcont">			
              <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="content pane">
                      <tr> 
                        <td width="22%" valign="top" class="vtable">&nbsp;</td>
                        <td width="78%" class="vtable">
<input name="enable" type="checkbox" value="yes" <?php if (!empty($pconfig['enable'])) echo "checked"; ?> onClick="enable_change(false)">
                          <strong>Enable DHCP relay on 
                          <?=htmlspecialchars($iflist[$if]);?>
                          interface</strong></td>
                      </tr>
			<tr>
	              <td width="22%" valign="top" class="vtable">&nbsp;</td>
                      <td width="78%" class="vtable">
<input name="agentoption" type="checkbox" value="yes" <?php if (!empty($pconfig['agentoption'])) echo "checked"; ?>>
                      <strong>Append circuit ID and agent ID to requests</strong><br>
                      If this is checked, the DHCP relay will append the circuit ID (m0n0wall interface number) and the agent ID to the DHCP request.</td>
        		  </tr>
                      <tr> 
                        <td width="22%" valign="top" class="vncell">Destination server</td>
                        <td width="78%" class="vtable"> 
			<input name="proxydhcp" type="checkbox" value="yes" <?php if (!empty($pconfig['proxydhcp'])) echo "checked"; ?> onClick="enable_change(false)">  Proxy requests to DHCP server on WAN subnet
                          <br><br><input name="server" type="text" class="formfld" id="server" size="20" value="<?=htmlspecialchars($pconfig['server'] ?? '');?>">
                          <br>
			  This is the IP address of the server to which the DHCP packet is relayed.  Select "Proxy requests to DHCP server on WAN subnet" to relay DHCP packets to the server that was used on the WAN interface.
                        </td>
                      </tr>
                      <tr> 
                        <td width="22%" valign="top">&nbsp;</td>
                        <td width="78%"> 
                          <input name="if" type="hidden" value="<?=htmlspecialchars($if);?>"> 
                          <input name="Submit" type="submit" class="formbtn" value="Save" onclick="enable_change(true)"> 
                        </td>
                      </tr>
                    </table>
    </td>
  </tr>
</table>
</form>
<script type="text/javascript">
<!--
enable_change(false);
//-->
</script>
<?php include("fend.inc"); ?>
