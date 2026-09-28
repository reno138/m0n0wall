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

$pgtitle = array("Services", "Dynamic DNS");
require("guiconfig.inc");

if (!is_array($config['dnsupdate'] ?? null)) {
	$config['dnsupdate'] = array();
}

$pconfig['username'] = $config['dyndns']['username'] ?? null;
$pconfig['password'] = $config['dyndns']['password'] ?? null;
$pconfig['host'] = $config['dyndns']['host'] ?? null;
$pconfig['server'] = $config['dyndns']['server'] ?? null;
$pconfig['port'] = $config['dyndns']['port'] ?? null;
$pconfig['mx'] = $config['dyndns']['mx'] ?? null;
$pconfig['type'] = $config['dyndns']['type'] ?? null;
$pconfig['enable'] = isset($config['dyndns']['enable']);
$pconfig['wildcard'] = isset($config['dyndns']['wildcard']);

$pconfig['dnsupdate_enable'] = isset($config['dnsupdate']['enable']);
$pconfig['dnsupdate_host'] = $config['dnsupdate']['host'] ?? null;
$pconfig['dnsupdate_ttl'] = $config['dnsupdate']['ttl'] ?? null;
if (empty($pconfig['dnsupdate_ttl']))
	$pconfig['dnsupdate_ttl'] = 60;
$pconfig['dnsupdate_keydata'] = $config['dnsupdate']['keydata'] ?? null;
$pconfig['dnsupdate_keyname'] = $config['dnsupdate']['keyname'] ?? null;
$pconfig['dnsupdate_usetcp'] = isset($config['dnsupdate']['usetcp']);

if ($_POST) {

	$input_errors = array();
	$pconfig = $_POST;

	/* input validation */
	$reqdfields = array();
	$reqdfieldsn = array();
	if (!empty($_POST['enable'])) {
		$reqdfields = array_merge($reqdfields, explode(" ", "host username password type"));
		$reqdfieldsn = array_merge($reqdfieldsn, explode(",", "Hostname,Username,Password,Service type"));
	}
	if (!empty($_POST['dnsupdate_enable'])) {
		$reqdfields = array_merge($reqdfields, explode(" ", "dnsupdate_host dnsupdate_ttl dnsupdate_keyname dnsupdate_keydata"));
		$reqdfieldsn = array_merge($reqdfieldsn, explode(",", "Hostname,TTL,Key name,Key"));
	}
	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
	
	if ((!empty($_POST['host']) && !is_domain($_POST['host']))) {
		$input_errors[] = "The host name contains invalid characters.";
	}
	if ((!empty($_POST['server']) && !is_domain($_POST['server']) && !is_ipaddr($_POST['server']))) {
		$input_errors[] = "The server name contains invalid characters.";
	}
	if ((!empty($_POST['port']) && !is_port($_POST['port']))) {
		$input_errors[] = "The server port must be an integer between 1 and 65535.";
	}
	if ((!empty($_POST['mx']) && !is_domain($_POST['mx']))) {
		$input_errors[] = "The MX contains invalid characters.";
	}
	if ((!empty($_POST['username']) && !is_dyndns_username($_POST['username']))) {
		$input_errors[] = "The username contains invalid characters.";
	}
	
	if ((!empty($_POST['dnsupdate_host']) && !is_domain($_POST['dnsupdate_host']))) {
		$input_errors[] = "The DNS update host name contains invalid characters.";
	}
	if ((!empty($_POST['dnsupdate_ttl']) && !is_numericint($_POST['dnsupdate_ttl']))) {
		$input_errors[] = "The DNS update TTL must be an integer.";
	}
	if ((!empty($_POST['dnsupdate_keyname']) && !is_domain($_POST['dnsupdate_keyname']))) {
		$input_errors[] = "The DNS update key name contains invalid characters.";
	}

	if (empty($input_errors)) {
		$config['dyndns']['type'] = $_POST['type'] ?? null;	
		$config['dyndns']['username'] = $_POST['username'] ?? null;
		$config['dyndns']['password'] = $_POST['password'] ?? null;
		$config['dyndns']['host'] = $_POST['host'] ?? null;
		$config['dyndns']['server'] = $_POST['server'] ?? null;
		$config['dyndns']['port'] = $_POST['port'] ?? null;
		$config['dyndns']['mx'] = $_POST['mx'] ?? null;
		$config['dyndns']['wildcard'] = !empty($_POST['wildcard']) ? true : false;
		$config['dyndns']['enable'] = !empty($_POST['enable']) ? true : false;
		
		$config['dnsupdate']['enable'] = !empty($_POST['dnsupdate_enable']) ? true : false;
		$config['dnsupdate']['host'] = $_POST['dnsupdate_host'] ?? null;
		$config['dnsupdate']['ttl'] = $_POST['dnsupdate_ttl'] ?? null;
		$config['dnsupdate']['keyname'] = $_POST['dnsupdate_keyname'] ?? null;
		$config['dnsupdate']['keydata'] = $_POST['dnsupdate_keydata'] ?? null;
		$config['dnsupdate']['usetcp'] = !empty($_POST['dnsupdate_usetcp']) ? true : false;
			
		write_config();
		
		$retval = 0;
		if (!file_exists($d_sysrebootreqd_path)) {
			/* nuke the cache file */
			config_lock();
			services_dyndns_reset();
			$retval = services_dyndns_configure();
			$retval |= services_dnsupdate_process();
			config_unlock();
		}
		$savemsg = get_std_save_message($retval);
	}
}
?>
<?php include("fbegin.inc"); ?>
<script type="text/javascript">
<!--
function enable_change(enable_change) {
	var endis;
	
	endis = !(document.iform.enable.checked || enable_change);
	document.iform.host.disabled = endis;
	document.iform.server.disabled = endis;
	document.iform.port.disabled = endis;
	document.iform.mx.disabled = endis;
	document.iform.type.disabled = endis;
	document.iform.wildcard.disabled = endis;
	document.iform.username.disabled = endis;
	document.iform.password.disabled = endis;
	
	endis = !(document.iform.dnsupdate_enable.checked || enable_change);
	document.iform.dnsupdate_host.disabled = endis;
	document.iform.dnsupdate_ttl.disabled = endis;
	document.iform.dnsupdate_keyname.disabled = endis;
	document.iform.dnsupdate_keydata.disabled = endis;
	document.iform.dnsupdate_usetcp.disabled = endis;
}
//-->
</script>
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
<?php if (!empty($savemsg)) print_info_box($savemsg); ?>
            <form action="services_dyndns.php" method="post" name="iform" id="iform">
              <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="content pane">
                <tr> 
                  <td colspan="2" valign="top" class="optsect_t">
				  <table border="0" cellspacing="0" cellpadding="0" width="100%" summary="checkbox pane">
				  <tr><td class="optsect_s"><strong>Dynamic DNS client</strong></td>
				  <td align="right" class="optsect_s"><input name="enable" type="checkbox" value="yes" <?php if (!empty($pconfig['enable'])) echo "checked"; ?> onClick="enable_change(false)"> <strong>Enable</strong></td></tr>
				  </table></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Service type</td>
                  <td width="78%" class="vtable">
					<select name="type" class="formfld" id="type">
                      <?php
					  /* Driven from dyndns_providers() so the list cannot drift
					     from what is actually implemented. The old list -- DHS,
					     ODS, DyNS, HN.ORG, EZ-IP, TZO -- was 2003-era and is
					     almost entirely dead or now paid. */
					  $provs = dyndns_providers();
					  $types = array(); $vals = array();
					  foreach ($provs as $k => $v) { $vals[] = $k; $types[] = $v['name']; }
					  $j = 0; for ($j = 0; $j < count($vals); $j++): ?>
                      <option value="<?=$vals[$j];?>" <?php if ($vals[$j] == ($pconfig['type'] ?? null)) echo "selected";?>> 
                      <?=htmlspecialchars($types[$j]);?>
                      </option>
                      <?php endfor; ?>
                    </select></td>
				</tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Hostname</td>
                  <td width="78%" class="vtable"> 
                    <?=$mandfldhtml;?><input name="host" type="text" class="formfld" id="host" size="30" value="<?=htmlspecialchars($pconfig['host'] ?? '');?>"> 
                  </td>
				</tr>
                 <tr> 
                  <td width="22%" valign="top" class="vncell">Server</td>
                  <td width="78%" class="vtable"> 
                    <input name="server" type="text" class="formfld" id="server" size="30" value="<?=htmlspecialchars($pconfig['server'] ?? '');?>">
                    <br>Special server to connect to. This can usually be left blank.</td>
				</tr>
                <tr> 
                <tr> 
                  <td width="22%" valign="top" class="vncell">Port</td>
                  <td width="78%" class="vtable"> 
                    <input name="port" type="text" class="formfld" id="port" size="5" value="<?=htmlspecialchars($pconfig['port'] ?? '');?>">
                    <br>Special server port to connect to. This can usually be left blank.</td>
				</tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">MX</td>
                  <td width="78%" class="vtable"> 
                    <input name="mx" type="text" class="formfld" id="mx" size="30" value="<?=htmlspecialchars($pconfig['mx'] ?? '');?>"> 
                    <br>
                    Set this option only if you need a special MX record. Not 
                    all services support this.</td>
				</tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Wildcards</td>
                  <td width="78%" class="vtable"> 
                    <input name="wildcard" type="checkbox" id="wildcard" value="yes" <?php if (!empty($pconfig['wildcard'])) echo "checked"; ?>>
                    Enable Wildcard</td>
				</tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Username</td>
                  <td width="78%" class="vtable"> 
                    <?=$mandfldhtml;?><input name="username" type="text" class="formfld" id="username" size="20" value="<?=htmlspecialchars($pconfig['username'] ?? '');?>">
                    <br><span class="vexpl">For <strong>Cloudflare</strong>, put the
                    <strong>Zone ID</strong> here and an API token scoped to DNS:Edit in
                    the password field. For <strong>deSEC</strong>, <strong>Duck DNS</strong>,
                    <strong>dynv6</strong> and <strong>FreeDNS</strong> the username is not
                    used &mdash; only the token. Everything else takes the account
                    username.</span>
                  </td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Password</td>
                  <td width="78%" class="vtable"> 
                    <?=$mandfldhtml;?><input name="password" type="password" class="formfld" id="password" size="20" value="<?=htmlspecialchars($pconfig['password'] ?? '');?>"> 
                  </td>
                </tr>
                <tr> 
                  <td colspan="2" class="list" height="12"></td>
                </tr>
                <tr> 
                  <td colspan="2" valign="top" class="optsect_t">
				  <table border="0" cellspacing="0" cellpadding="0" width="100%" summary="checkbox pane">
				  <tr>
				    <td class="optsect_s"><strong>RFC 2136 Dynamic DNS updates</strong></td>
				    <td align="right" class="optsect_s"><input name="dnsupdate_enable" type="checkbox" value="yes" <?php if (!empty($pconfig['dnsupdate_enable'])) echo "checked"; ?> onClick="enable_change(false)"> <strong>Enable</strong></td></tr>
				  </table></td>
                </tr>
                <tr>
                  <td colspan="2" class="vtable"><span class="vexpl"><span class="red"><strong>Not
                  available in this build.</strong></span> RFC 2136 updates need
                  <tt>nsupdate</tt>, which is part of bind-tools &ndash; 8.5&nbsp;MB plus
                  seven dependencies, more than this image carries for one feature. The
                  settings below are still saved, and an attempt to use them is recorded in
                  the system log, but no update is sent. The HTTP-based providers above are
                  unaffected and work normally.</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Hostname</td>
                  <td width="78%" class="vtable"> 
                    <?=$mandfldhtml;?><input name="dnsupdate_host" type="text" class="formfld" id="dnsupdate_host" size="30" value="<?=htmlspecialchars($pconfig['dnsupdate_host'] ?? '');?>"> 
                  </td>
				</tr>
                <tr>
                  <td valign="top" class="vncellreq">TTL</td>
                  <td class="vtable">
                    <?=$mandfldhtml;?><input name="dnsupdate_ttl" type="text" class="formfld" id="dnsupdate_ttl" size="6" value="<?=htmlspecialchars($pconfig['dnsupdate_ttl'] ?? '');?>"> 
                  seconds</td>
                </tr>
                <tr>
                  <td valign="top" class="vncellreq">Key name</td>
                  <td class="vtable">
                    <?=$mandfldhtml;?><input name="dnsupdate_keyname" type="text" class="formfld" id="dnsupdate_keyname" size="30" value="<?=htmlspecialchars($pconfig['dnsupdate_keyname'] ?? '');?>">
                    <br> 
                    This must match the setting on the DNS server.</td>
                </tr>
                <tr>
                  <td valign="top" class="vncellreq">Key</td>
                  <td class="vtable">
                    <?=$mandfldhtml;?><input name="dnsupdate_keydata" type="text" class="formfld" id="dnsupdate_keydata" size="70" value="<?=htmlspecialchars($pconfig['dnsupdate_keydata'] ?? '');?>">
                    <br> 
                    Paste an HMAC-MD5 key here.</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Protocol</td>
                  <td width="78%" class="vtable"> 
                    <input name="dnsupdate_usetcp" type="checkbox" id="dnsupdate_usetcp" value="yes" <?php if (!empty($pconfig['dnsupdate_usetcp'])) echo "checked"; ?>>
                    <strong>Use TCP instead of UDP</strong></td>
				</tr>
                <tr> 
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%"> 
                    <input name="Submit" type="submit" class="formbtn" value="Save" onClick="enable_change(true)"> 
                  </td>
                </tr>
                <tr> 
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%"><span class="vexpl"><span class="red"><strong>Note:<br>
                    </strong></span>You must configure a DNS server in <a href="system.php">System: 
                    General setup</a> or allow the DNS server list to be overridden 
                    by DHCP/PPP on WAN for dynamic DNS updates to work.</span></td>
                </tr>
              </table>
</form>
<script type="text/javascript">
<!--
enable_change(false);
//-->
</script>
<?php include("fend.inc"); ?>
