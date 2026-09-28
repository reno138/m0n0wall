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

$pgtitle = array("Services", "SNMP");
require("guiconfig.inc");

if (!is_array($config['snmpd'] ?? null)) {
	$config['snmpd'] = array();
	$config['snmpd']['rocommunity'] = "public";
}

$pconfig['syslocation'] = $config['snmpd']['syslocation'] ?? null;
$pconfig['syscontact'] = $config['snmpd']['syscontact'] ?? null;
$pconfig['rocommunity'] = $config['snmpd']['rocommunity'] ?? null;
$pconfig['enable'] = isset($config['snmpd']['enable']);
$pconfig['bindlan'] = isset($config['snmpd']['bindlan']);

if ($_POST) {

	$input_errors = array();
	$pconfig = $_POST;

	/* input validation */
	if (!empty($_POST['enable'])) {
		$reqdfields = explode(" ", "rocommunity");
		$reqdfieldsn = explode(",", "Community");
		
		do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

		/* Reject what the agent cannot serve, rather than silently rewriting it.
		
		   snmpd.conf's rocommunity directive is parsed unquoted -- net-snmp
		   would take a quote or a space as the start of the next field -- so
		   the generator strips the community to these characters. It used to do
		   that silently while this page accepted any text, which meant the
		   agent answered to a different community than the page displayed, and
		   a community of only punctuation produced a bare 'rocommunity' that
		   stopped snmpd starting. Validating here makes what you type what you
		   get. */
		if (!empty($_POST['rocommunity'])
		    && !preg_match('/^[A-Za-z0-9_.-]+$/', $_POST['rocommunity']))
			$input_errors[] = "The community string may only contain letters, " .
			    "digits, underscores, dots and hyphens.";

		/* sysLocation and sysContact are copied to the end of their line, so a
		   newline would inject a directive. */
		foreach (array('syslocation' => 'Location', 'syscontact' => 'Contact') as $f => $lbl) {
			if (!empty($_POST[$f]) && preg_match('/[\r\n]/', $_POST[$f]))
				$input_errors[] = "The {$lbl} may not contain line breaks.";
		}
	}

	if (empty($input_errors)) {
		$config['snmpd']['syslocation'] = $_POST['syslocation'] ?? null;	
		$config['snmpd']['syscontact'] = $_POST['syscontact'] ?? null;
		$config['snmpd']['rocommunity'] = $_POST['rocommunity'] ?? null;
		$config['snmpd']['enable'] = !empty($_POST['enable']) ? true : false;
		$config['snmpd']['bindlan'] = !empty($_POST['bindlan']) ? true : false;
			
		write_config();
		
		$retval = 0;
		if (!file_exists($d_sysrebootreqd_path)) {
			config_lock();
			$retval = services_snmpd_configure();
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
	document.iform.syslocation.disabled = endis;
	document.iform.syscontact.disabled = endis;
	document.iform.rocommunity.disabled = endis;
	document.iform.bindlan.disabled = endis;
}
//-->
</script>
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
<?php if (!empty($savemsg)) print_info_box($savemsg); ?>
            <form action="services_snmp.php" method="post" name="iform" id="iform">
              <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="content pane">
                <tr> 
                  <td width="22%" valign="top" class="vtable">&nbsp;</td>
                  <td width="78%" class="vtable">
<input name="enable" type="checkbox" value="yes" <?php if (!empty($pconfig['enable'])) echo "checked"; ?> onClick="enable_change(false)">
                    <strong>Enable SNMP agent</strong></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">System location</td>
                  <td width="78%" class="vtable"> 
                    <input name="syslocation" type="text" class="formfld" id="syslocation" size="40" value="<?=htmlspecialchars($pconfig['syslocation'] ?? '');?>"> 
                  </td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">System contact</td>
                  <td width="78%" class="vtable"> 
                    <input name="syscontact" type="text" class="formfld" id="syscontact" size="40" value="<?=htmlspecialchars($pconfig['syscontact'] ?? '');?>"> 
                  </td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Community</td>
                  <td width="78%" class="vtable"> 
                    <?=$mandfldhtml;?><input name="rocommunity" type="text" class="formfld" id="rocommunity" size="40" value="<?=htmlspecialchars($pconfig['rocommunity'] ?? '');?>"> 
                    <br>
                    In most cases, &quot;public&quot; is used here. Letters, digits,
                    underscores, dots and hyphens only &ndash; the agent's
                    configuration file parses this field unquoted.</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vtable"></td>
                  <td width="78%" class="vtable"> 
                    <input name="bindlan" type="checkbox" value="yes" <?php if (!empty($pconfig['bindlan'])) echo "checked"; ?>> <strong>Bind to LAN interface only</strong>
                    <br>
                    This option can be useful when trying to access the SNMP agent
                    by the LAN interface's IP address through a VPN tunnel terminated on the WAN interface.</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%"> 
                    <input name="Submit" type="submit" class="formbtn" value="Save" onClick="enable_change(true)"> 
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
