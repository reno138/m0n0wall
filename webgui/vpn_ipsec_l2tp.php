#!/usr/local/bin/php
<?php
/*
	$Id: vpn_ipsec_l2tp.php 238 2008-01-21 18:33:33Z mkasper $
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

$pgtitle = array("VPN", "L2TP/IPsec", "Configuration");
require("guiconfig.inc");

if (!is_array($config['ipsec_l2tp']['radius'] ?? null)) {
	$config['ipsec_l2tp']['radius'] = array();
}
$ipsec_l2tpcfg = &$config['l2tp'];

$pconfig['remoteip'] = $ipsec_l2tpcfg['remoteip'] ?? null;
$pconfig['localip'] = $ipsec_l2tpcfg['localip'] ?? null;
$pconfig['redir'] = $ipsec_l2tpcfg['redir'] ?? null;
$pconfig['mode'] = $ipsec_l2tpcfg['mode'] ?? null;
$pconfig['req128'] = isset($ipsec_l2tpcfg['req128']);
$pconfig['radiusenable'] = isset($ipsec_l2tpcfg['radius']['enable']);
$pconfig['radacct_enable'] = isset($ipsec_l2tpcfg['radius']['accounting']);
$pconfig['radiusserver'] = $ipsec_l2tpcfg['radius']['server'] ?? null;
$pconfig['radiussecret'] = $ipsec_l2tpcfg['radius']['secret'] ?? null;
$pconfig['psk'] = $ipsec_l2tpcfg['ipsec']['psk'] ?? null ;

$pconfig['nunits'] = $ipsec_l2tpcfg['nunits'] ?? null;
if (empty($pconfig['nunits']))
	$pconfig['nunits'] = 16;

if ($_POST) {

	unset($input_errors);
	$pconfig = $_POST;

	/* input validation */
	if (($_POST['mode'] ?? null) == "server") {
		$reqdfields = explode(" ", "localip remoteip");
		$reqdfieldsn = explode(",", "Server address,Remote start address");
		
		if (!empty($_POST['radiusenable'])) {
			$reqdfields = array_merge($reqdfields, explode(" ", "radiusserver radiussecret"));
			$reqdfieldsn = array_merge($reqdfieldsn, 
				explode(",", "RADIUS server address,RADIUS shared secret"));
		}
		
		do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
		
		if ((!empty($_POST['localip']) && !is_ipaddr($_POST['localip']))) {
			$input_errors[] = "A valid server address must be specified.";
		}
		/* gated on 'subnet', which this page has no input for, so the remote
		   start address was never validated */
		if ((!empty($_POST['remoteip']) && !is_ipaddr($_POST['remoteip']))) {
			$input_errors[] = "A valid remote start address must be specified.";
		}
		if ((!empty($_POST['radiusserver']) && !is_ipaddr($_POST['radiusserver']))) {
			$input_errors[] = "A valid RADIUS server address must be specified.";
		}
		
		if (empty($input_errors)) {	
			$_POST['remoteip'] = $pconfig['remoteip'] = gen_subnet($_POST['remoteip'] ?? '', $ipsec_l2tp_subnet_sizes[$_POST['nunits'] ?? ''] ?? null);
			$subnet_start = ip2long($_POST['remoteip']);
			$subnet_end = ip2long($_POST['remoteip']) + ($_POST['nunits'] ?? null) - 1;
						
			if ((ip2long($_POST['localip'] ?? '') >= $subnet_start) && 
			    (ip2long($_POST['localip'] ?? '') <= $subnet_end)) {
				$input_errors[] = "The specified server address lies in the remote subnet.";	
			}
			if (($_POST['localip'] ?? null) == ($config['interfaces']['lan']['ipaddr'] ?? null)) {
				$input_errors[] = "The specified server address is equal to the LAN interface address.";	
			}
		}
	} else if (($_POST['mode'] ?? null) == "redir") {
		$reqdfields = explode(" ", "redir");
		$reqdfieldsn = explode(",", "IPsec/L2TP redirection target address");
		
		do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
		
		if ((!empty($_POST['redir']) && !is_ipaddr($_POST['redir']))) {
			$input_errors[] = "A valid target address must be specified.";
		}
	}

	if (empty($input_errors)) {
		$ipsec_l2tpcfg['nunits'] = $_POST['nunits'] ?? null;
		$ipsec_l2tpcfg['remoteip'] = $_POST['remoteip'] ?? null;
		$ipsec_l2tpcfg['redir'] = $_POST['redir'] ?? null;
		$ipsec_l2tpcfg['localip'] = $_POST['localip'] ?? null;
		$ipsec_l2tpcfg['mode'] = $_POST['mode'] ?? null;
		$ipsec_l2tpcfg['radius']['enable'] = !empty($_POST['radiusenable']) ? true : false;
		$ipsec_l2tpcfg['radius']['accounting'] = !empty($_POST['radacct_enable']) ? true : false;
		$ipsec_l2tpcfg['radius']['server'] = $_POST['radiusserver'] ?? null;
		$ipsec_l2tpcfg['radius']['secret'] = $_POST['radiussecret'] ?? null;
		$ipsec_l2tpcfg['ipsec']['psk'] = $_POST['psk'] ?? null;
			
		write_config();
		
		$retval = 0;
		if (!file_exists($d_sysrebootreqd_path)) {
			config_lock();
			$retval = vpn_ipsec_l2tp_configure();
			/* The IPsec half, and the rules that let clients reach it.
			
			   Saving this page used to start mpd5 and stop there: nothing
			   regenerated swanctl.conf, so the pre-shared key above configured
			   nothing and the L2TP listener was left unprotected. The ruleset
			   also has to be rebuilt, because whether pf passes IKE/NAT-T/ESP
			   depends on whether this server is enabled. */
			if ($retval == 0)
				$retval = vpn_ipsec_configure();
			filter_configure();
			config_unlock();
		}
		$savemsg = get_std_save_message($retval);
	}
}
?>
<?php include("fbegin.inc"); ?>
<script type="text/javascript">
<!--
function get_radio_value(obj)
{
	for (i = 0; i < obj.length; i++) {
		if (obj[i].checked)
			return obj[i].value;
	}
	return null;
}

function enable_change(enable_over) {
	if ((get_radio_value(document.iform.mode) == "server") || enable_over) {
		document.iform.nunits.disabled = 0;
		document.iform.remoteip.disabled = 0;
		document.iform.psk.disabled = 0;
		document.iform.localip.disabled = 0;
		document.iform.radiusenable.disabled = 0;
		
		if (document.iform.radiusenable.checked || enable_over) {
			document.iform.radacct_enable.disabled = 0;
			document.iform.radiusserver.disabled = 0;
			document.iform.radiussecret.disabled = 0;
		} else {
			document.iform.radacct_enable.disabled = 1;
			document.iform.radiusserver.disabled = 1;
			document.iform.radiussecret.disabled = 1;
		}
	} else {
		document.iform.nunits.disabled = 1;
		document.iform.remoteip.disabled = 1;
		document.iform.localip.disabled = 1;
		document.iform.psk.disabled = 1;
		document.iform.radiusenable.disabled = 1;
		document.iform.radacct_enable.disabled = 1;
		document.iform.radiusserver.disabled = 1;
		document.iform.radiussecret.disabled = 1;
	}
	/* A third block used to live here toggling a 'redir' input. Neither that
	   input nor a "redir" mode has ever existed on this form, so assigning to
	   it threw a TypeError on a null element -- which aborted enable_change()
	   before it returned and left every field on the page disabled, whatever
	   the mode was set to. Removed along with the config keys behind it. */
}
//-->
</script>
<form action="vpn_ipsec_l2tp.php" method="post" name="iform" id="iform">
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
<?php if (!empty($savemsg)) print_info_box($savemsg); ?>
<table width="100%" border="0" cellpadding="0" cellspacing="0" summary="tab pane">
  <tr><td class="tabnavtbl">
  <ul id="tabnav">
<?php 
   	$tabs = array('Configuration' => 'vpn_ipsec_l2tp.php',
           		  'Users' => 'vpn_l2tp_users.php');
	dynamic_tab_menu($tabs);
?>
  </ul>
  </td></tr>
  <tr> 
    <td class="tabcont">
              <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="content pane">
                <tr> 
                  <td width="22%" valign="top" class="vtable">&nbsp;</td>
                  <td width="78%" class="vtable"> 
                    <input name="mode" type="radio" onclick="enable_change(false)" value="off"
				  	<?php if ((($pconfig['mode'] ?? null) != "server") && (($pconfig['mode'] ?? null) != "redir")) echo "checked";?>>
                    Off</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vtable">&nbsp;</td>
                  <td width="78%" class="vtable">
<input type="radio" name="mode" value="server" onclick="enable_change(false)" <?php if (($pconfig['mode'] ?? null) == "server") echo "checked"; ?>>
                    Enable IPsec/L2TP server</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">IPSEC PSK</td>
                  <td width="78%" class="vtable"> 
                    <?=$mandfldhtml;?><input name="psk" type="password" class="formfld" id="psk" size="20" value="<?=htmlspecialchars($pconfig['psk'] ?? '');?>"> 
                    <br>
                    Enter the IPSEC Pre-Shared Key the IPsec/L2TP server should use on its side 
                    for all clients.</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Server address</td>
                  <td width="78%" class="vtable"> 
                    <?=$mandfldhtml;?><input name="localip" type="text" class="formfld" id="localip" size="20" value="<?=htmlspecialchars($pconfig['localip'] ?? '');?>"> 
                    <br>
                    Enter the IP address the IPsec/L2TP server should use on its side 
                    for all clients.</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Remote address 
                    range</td>
                  <td width="78%" class="vtable"> 
                    <?=$mandfldhtml;?><input name="remoteip" type="text" class="formfld" id="remoteip" size="20" value="<?=htmlspecialchars($pconfig['remoteip'] ?? '');?>">
                    <select name="nunits">
                    <?php
                    	foreach ($ipsec_l2tp_subnet_sizes as $units => $sncidr) {
                    		echo "<option value=\"$units\"";
                    		if ($units == ($pconfig['nunits'] ?? null))
                    			echo " selected";
                    		echo ">/$sncidr ($units addresses)</option>\n";
                    	}
                    ?>
                    </select>
                    <br>
                    Specify the start address and size for the client IP address subnet.<br>
                    The IPsec/L2TP server will assign client addresses from the subnet given above
                    to clients. The size of the subnet determines the maximum number of concurrent connections
                    that the IPsec/L2TP server can handle.</td>
                </tr>
                <tr>
                  <td width="22%" valign="top" class="vncell">RADIUS</td>
                  <td width="78%" class="vtable">
                    <input name="radiusenable" type="checkbox" id="radiusenable" value="yes" onclick="enable_change(false)" <?php if (!empty($pconfig['radiusenable'])) echo "checked"; ?>>
                    <strong>Use a RADIUS server for authenticating VPN users</strong><br>
                    <span class="vexpl">Authenticate against RADIUS instead of the local user list on
                    the <a href="vpn_l2tp_users.php">Users</a> tab. This is the PPP user
                    authentication that happens INSIDE the tunnel &ndash; separate from, and in
                    addition to, the pre-shared key above, which authenticates the IPsec
                    layer.</span></td>
                </tr>
                <tr>
                  <td width="22%" valign="top" class="vncell">RADIUS server</td>
                  <td width="78%" class="vtable">
                    <input name="radiusserver" type="text" class="formfld" id="radiusserver" size="20" value="<?=htmlspecialchars($pconfig['radiusserver'] ?? '');?>"><br>
                    <span class="vexpl">The IP address of the RADIUS server.</span></td>
                </tr>
                <tr>
                  <td width="22%" valign="top" class="vncell">RADIUS shared secret</td>
                  <td width="78%" class="vtable">
                    <input name="radiussecret" type="password" class="formfld" id="radiussecret" size="20" value="<?=htmlspecialchars($pconfig['radiussecret'] ?? '');?>"><br>
                    <span class="vexpl">The secret this firewall and the RADIUS server share.</span></td>
                </tr>
                <tr>
                  <td width="22%" valign="top" class="vncell">RADIUS accounting</td>
                  <td width="78%" class="vtable">
                    <input name="radacct_enable" type="checkbox" id="radacct_enable" value="yes" <?php if (!empty($pconfig['radacct_enable'])) echo "checked"; ?>>
                    <strong>Send accounting records to the RADIUS server</strong><br>
                    <span class="vexpl">Reports session start, stop and volume for each VPN
                    user.</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%"> 
                    <input name="Submit" type="submit" class="formbtn" value="Save" onclick="enable_change(true)"> 
                  </td>
                </tr>
                <tr> 
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%"><span class="vexpl"><span class="red"><strong>Note:<br>
                    </strong></span>Don't forget to add a firewall rule to permit 
                    traffic from IPsec/L2TP clients!</span></td>
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
