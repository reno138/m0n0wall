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

$pgtitle = array("System", "Advanced setup");
require("guiconfig.inc");
$pconfig['nospoofcheck'] = isset($config['bridge']['nospoofcheck']);
$pconfig['sensors'] = isset($config['system']['webgui']['sensors']['enable']);
$pconfig['cert'] = base64_decode($config['system']['webgui']['certificate'] ?? '');
$pconfig['key'] = base64_decode($config['system']['webgui']['private-key'] ?? '');
$pconfig['disableconsolemenu'] = isset($config['system']['disableconsolemenu']);
$pconfig['allowipsecfrags'] = isset($config['filter']['allowipsecfrags']);
$pconfig['expanddiags'] = isset($config['system']['webgui']['expanddiags']);
if ($g['platform'] == "generic-pc" || $g['platform'] == "generic-pc-serial")
	$pconfig['harddiskstandby'] = $config['system']['harddiskstandby'] ?? null;
$pconfig['bypassstaticroutes'] = isset($config['filter']['bypassstaticroutes']);
$pconfig['noantilockout'] = isset($config['system']['webgui']['noantilockout']);
$pconfig['ipsecdnsinterval'] = $config['ipsec']['dns-interval'] ?? null;
$pconfig['tcpidletimeout'] = $config['filter']['tcpidletimeout'] ?? null;
$pconfig['preferoldsa_enable'] = isset($config['ipsec']['preferoldsa']);
$pconfig['polling_enable'] = isset($config['system']['polling']);
$pconfig['ipfstatentries'] = $config['diag']['ipfstatentries'] ?? null;
$pconfig['portrangelow'] = $config['nat']['portrange-low'] ?? null;
$pconfig['portrangehigh'] = $config['nat']['portrange-high'] ?? null;

if ($_POST) {

	unset($input_errors);
	$savemsgadd = "";
	
	if (!empty($_POST['gencert'])) {
		/* custom certificate generation requested */
		$ck = generate_self_signed_cert("m0n0wall", $config['system']['hostname'] . "." . $config['system']['domain']);
		
		if ($ck === false) {
			$input_errors[] = "A self-signed certificate could not be generated because the system's clock is not set.";
		} else {
			$_POST['cert'] = $ck['cert'];
		 	$_POST['key'] = $ck['key'];
			$savemsgadd = "<br><br>A self-signed certificate and private key have been automatically generated.";
		}
	}
	
	$pconfig = $_POST;

	/* input validation */
	if (!empty($_POST['ipsecdnsinterval']) && !is_numericint($_POST['ipsecdnsinterval'])) {
		$input_errors[] = "The IPsec DNS check interval must be an integer.";
	}
	if (!empty($_POST['tcpidletimeout']) && !is_numericint($_POST['tcpidletimeout'])) {
		$input_errors[] = "The TCP idle timeout must be an integer.";
	}
	if (!empty($_POST['ipfstatentries']) && !is_numericint($_POST['ipfstatentries'])) {
		$input_errors[] = "The 'firewall states displayed' value must be an integer.";
	}
	if ((!empty($_POST['cert']) && empty($_POST['key'])) || (!empty($_POST['key']) && empty($_POST['cert']))) {
		$input_errors[] = "Certificate and key must always be specified together.";
	} else if (!empty($_POST['cert']) && !empty($_POST['key'])) {
		if (!is_pem_certificate($_POST['cert']))
			$input_errors[] = "This certificate does not appear to be valid.";
		/* is_pem_private_key(), not a test for "BEGIN RSA PRIVATE KEY": that is
		   PKCS#1 only, and every current openssl writes PKCS#8 by default, so a
		   key generated today was rejected here even though lighttpd reads it. */
		if (is_pem_encrypted_private_key($_POST['key']))
			$input_errors[] = "This key is passphrase-protected. The web server is " .
			    "started without a console, so it cannot prompt for one -- decrypt " .
			    "the key before uploading it.";
		else if (!is_pem_private_key($_POST['key']))
			$input_errors[] = "This key does not appear to be valid. It should be a " .
			    "PEM private key, beginning with \"-----BEGIN PRIVATE KEY-----\".";
	}
	if ((!empty($_POST['portrangelow']) || !empty($_POST['portrangehigh'])) &&
		(!is_port($_POST['portrangelow'] ?? '') || !is_port($_POST['portrangehigh'] ?? '')))
		$input_errors[] = "The outbound NAT port range start and end must be integers between 1 and 65535.";

	if (empty($input_errors)) {
		$config['bridge']['nospoofcheck'] = !empty($_POST['nospoofcheck']) ? true : false;
		$config['system']['webgui']['sensors']['enable'] = !empty($_POST['sensors']) ? true : false;
		$config['system']['webgui']['sensors']['type'] = $_POST['sensorstype'] ?? null;
		/* the mbmon key is retired -- see the sensor block in index.php */
		unset($config['system']['webgui']['mbmon']);
		$oldcert = $config['system']['webgui']['certificate'] ?? null;
		$oldkey = $config['system']['webgui']['private-key'] ?? null;
		$config['system']['webgui']['certificate'] = base64_encode($_POST['cert'] ?? '');
		$config['system']['webgui']['private-key'] = base64_encode($_POST['key'] ?? '');
		$config['system']['disableconsolemenu'] = !empty($_POST['disableconsolemenu']) ? true : false;
		$config['filter']['allowipsecfrags'] = !empty($_POST['allowipsecfrags']) ? true : false;
		$config['system']['webgui']['expanddiags'] = !empty($_POST['expanddiags']) ? true : false;
		if ($g['platform'] == "generic-pc" || $g['platform'] == "generic-pc-serial") {
			$oldharddiskstandby = $config['system']['harddiskstandby'] ?? null;
			$config['system']['harddiskstandby'] = $_POST['harddiskstandby'] ?? null;
		}
		$config['system']['webgui']['noantilockout'] = !empty($_POST['noantilockout']) ? true : false;
		$config['filter']['bypassstaticroutes'] = !empty($_POST['bypassstaticroutes']) ? true : false;
		$oldtcpidletimeout = $config['filter']['tcpidletimeout'] ?? null;
		$config['filter']['tcpidletimeout'] = $_POST['tcpidletimeout'] ?? null;
		$oldipsecdnsinterval = $config['ipsec']['dns-interval'] ?? null;
		$config['ipsec']['dns-interval'] = $_POST['ipsecdnsinterval'] ?? null;
		$oldpreferoldsa = isset($config['ipsec']['preferoldsa']);
		$config['ipsec']['preferoldsa'] = !empty($_POST['preferoldsa_enable']) ? true : false;
		$oldpolling = isset($config['system']['polling']);
		$config['system']['polling'] = !empty($_POST['polling_enable']) ? true : false;
		if (empty($_POST['ipfstatentries']))
			unset($config['diag']['ipfstatentries']);
		else
			$config['diag']['ipfstatentries'] = $_POST['ipfstatentries'] ?? null;	
		/* 'ralink' is retired: see the note where the checkbox used to be. */
		unset($config['system']['ralink']);
		$config['nat']['portrange-low'] = $_POST['portrangelow'] ?? null;
		$config['nat']['portrange-high'] = $_POST['portrangehigh'] ?? null;
		
		write_config();

		if (($config['system']['webgui']['certificate'] != $oldcert)
				|| ($config['system']['webgui']['private-key'] != $oldkey)
				|| ($config['filter']['tcpidletimeout'] != $oldtcpidletimeout)
				|| (isset($config['system']['polling']) != $oldpolling)
				) {
			touch($d_sysrebootreqd_path);
		}
		if (($g['platform'] == "generic-pc" || $g['platform'] == "generic-pc-serial") && ($config['system']['harddiskstandby'] != $oldharddiskstandby)) {
			if (empty($config['system']['harddiskstandby'])) {
				// Reboot needed to deactivate standby due to a stupid ATA-protocol
				touch($d_sysrebootreqd_path);
				unset($config['system']['harddiskstandby']);
			} else {
				// No need to set the standby-time if a reboot is needed anyway
				system_set_harddisk_standby();
			}
		}
		
		$retval = 0;
		if (!file_exists($d_sysrebootreqd_path)) {
			config_lock();
			$retval = filter_configure();
			$retval |= interfaces_optional_configure();
			if (isset($config['ipsec']['preferoldsa']) != $oldpreferoldsa || $config['ipsec']['dns-interval'] != $oldipsecdnsinterval) {
				$retval |= vpn_ipsec_configure();
			}
			$retval |= system_set_termcap();
			config_unlock();
		}
		$savemsg = get_std_save_message($retval) . $savemsgadd;
	}
}

?>
<?php include("fbegin.inc"); ?>
            <?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
            <?php if (!empty($savemsg)) print_info_box($savemsg); ?>
            <p><span class="vexpl"><span class="red"><strong>Note: </strong></span>the 
              options on this page are intended for use by advanced users only, 
              and there's <strong>NO</strong> support for them.</span></p>
            <form action="system_advanced.php" method="post" name="iform" id="iform">
              <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="content pane">
                <tr> 
                  <td colspan="2" class="list" height="12"></td>
                </tr>
				<tr> 
                  <td colspan="2" valign="top" class="listtopic">Spoof Checking</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">&nbsp;</td>
                  <td width="78%" class="vtable"> 
				    <input name="nospoofcheck" type="checkbox" id="nospoofcheck" value="yes" <?php if (!empty($pconfig['nospoofcheck'])) echo "checked"; ?>>
                    <strong>Disable Spoof Checking on bridge</strong><span class="vexpl"><br>
                    Spoof Checking blocks packets not sourced from the subnet of the
					interface the packet was recieved on.<br>
					This option only affects bridged interfaces.
                    </span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%"> 
                    <input name="Submit" type="submit" class="formbtn" value="Save"> 
                  </td>
                </tr>
                <tr> 
                  <td colspan="2" class="list" height="12"></td>
                </tr>
                <tr> 
                  <td colspan="2" valign="top" class="listtopic">webGUI SSL certificate/key</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">Certificate</td>
                  <td width="78%" class="vtable"> 
                    <textarea name="cert" cols="65" rows="7" id="cert" class="formpre"><?=htmlspecialchars($pconfig['cert'] ?? '');?></textarea>
                    <br> 
                    Paste a signed certificate in X.509 PEM format here.</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">Key</td>
                  <td width="78%" class="vtable"> 
                    <textarea name="key" cols="65" rows="7" id="key" class="formpre"><?=htmlspecialchars($pconfig['key'] ?? '');?></textarea>
                    <br> 
                    Paste an RSA private key in PEM format here.</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%"> 
					<input name="gencert" type="submit" class="formbtn" value="Generate self-signed certificate"> 
                    <input name="Submit" type="submit" class="formbtn" value="Save"> 
                  </td>
                </tr>
                <tr> 
                  <td colspan="2" class="list" height="12"></td>
                </tr>
                <tr> 
                  <td colspan="2" valign="top" class="listtopic">Firewall</td>
                </tr>
				<tr>
                  <td valign="top" class="vncell">TCP idle timeout </td>
                  <td class="vtable">                    <span class="vexpl">
                    <input name="tcpidletimeout" type="text" class="formfld" id="tcpidletimeout" size="8" value="<?=htmlspecialchars($pconfig['tcpidletimeout'] ?? '');?>">
                    seconds<br>
    Idle TCP connections will be removed from the state table after no packets have been received for the specified number of seconds. Don't set this too high or your state table could become full of connections that have been improperly shut down. The default is 2.5 hours.</span></td>
			    </tr>
				<tr> 
                  <td width="22%" valign="top" class="vncell">Static route filtering</td>
                  <td width="78%" class="vtable"> 
                    <input name="bypassstaticroutes" type="checkbox" id="bypassstaticroutes" value="yes" <?php if (!empty($pconfig['bypassstaticroutes'])) echo "checked"; ?>>
                    <strong>Bypass firewall rules for traffic on the same interface</strong><br>
					This option only applies if you have defined one or more static routes. If it is enabled, traffic that enters and leaves through the same interface will not be checked by the firewall. This may be desirable in some situations where multiple subnets are connected to the same interface. </td>
                </tr>
				<tr>
                  <td valign="top" class="vncell">IPsec fragmented packets</td>
                  <td class="vtable">
                    <input name="allowipsecfrags" type="checkbox" id="allowipsecfrags" value="yes" <?php if (!empty($pconfig['allowipsecfrags'])) echo "checked"; ?>>
                    <strong>Allow fragmented IPsec packets</strong><span class="vexpl"><br>
    This will cause m0n0wall to allow fragmented IP packets that are encapsulated in IPsec ESP packets.</span></td>
			    </tr>
				<tr>
                  <td valign="top" class="vncell">Outbound NAT port range</td>
                  <td class="vtable"><span class="vexpl">
                    <input name="portrangelow" type="text" class="formfld" id="portrangelow" size="5" value="<?=htmlspecialchars($pconfig['portrangelow'] ?? '');?>"> - 
					<input name="portrangehigh" type="text" class="formfld" id="portrangehigh" size="5" value="<?=htmlspecialchars($pconfig['portrangehigh'] ?? '');?>">
                    <br>
    This setting controls the range from which ports are randomly picked for outbound NAT. Do not change this unless you know exactly what you're doing.</span></td>
			    </tr>
                <tr> 
                  <td colspan="2" class="list" height="12"></td>
                </tr>
                <tr> 
                  <td colspan="2" valign="top" class="listtopic">Miscellaneous</td>
                </tr>
				<tr> 
				<td width="22%" valign="top" class="vncell">Motherboard Monitor</td>
                <td width="78%" class="vtable"> 
				<table >
					<tr>
					<td > 
                    <select class="formfld" name="sensorstype" align="bottom">
					<option <?php if(!(($config['system']['webgui']['sensors']['type'] ?? null) == 'F')) echo('selected');?> value="C">&deg;C</option>
					<option <?php if(($config['system']['webgui']['sensors']['type'] ?? null) == 'F') echo('selected');?> value="F">&deg;F</option>
					</select></td>
					<td>
						<input id="sensors" <?php if (!empty($pconfig['sensors'])) echo "checked"; ?> name="sensors" type="checkbox" value="yes"><strong> Show system temperatures</strong></td>
						</tr>
					</table>
					<span class="vexpl">
                    Shows CPU and chassis temperatures on the
                    <a href="index.php">System status</a> page, read from
                    coretemp(4) on Intel, amdtemp(4) on AMD and the ACPI thermal
                    zones. Nothing is shown if the hardware exposes no sensors
                    &ndash; virtual machines usually do not.</span></td>
                </tr>
				<tr> 
                  <td width="22%" valign="top" class="vncell">Console menu </td>
                  <td width="78%" class="vtable"> 
                    <input name="disableconsolemenu" type="checkbox" id="disableconsolemenu" value="yes" <?php if (!empty($pconfig['disableconsolemenu'])) echo "checked"; ?>>
                    <strong>Disable console menu</strong><span class="vexpl"><br>
                    Changes to this option will take effect after a reboot.</span></td>
                </tr>
				<!-- The "Disable firmware version check" checkbox was removed
				     along with the check itself. That check POSTed this
				     firewall's platform and version to m0n0.ch over plaintext
				     HTTP and echoed the reply into the admin page unescaped;
				     see the note at the top of system_firmware.php. With
				     nothing left to disable, the option would have been a
				     control that configured nothing. -->
				<tr>
                  <td valign="top" class="vncell">IPsec DNS check interval</td>
                  <td class="vtable">                    <span class="vexpl">
                    <input name="ipsecdnsinterval" type="text" class="formfld" id="ipsecdnsinterval" size="8" value="<?=htmlspecialchars($pconfig['ipsecdnsinterval'] ?? '');?>">
                    seconds<br>
    If at least one IPsec tunnel has a host name (instead of an IP address) as the remote gateway, a DNS lookup
    is performed at the interval specified here, and if the IP address that the host name resolved to has changed,
    the IPsec tunnel is reconfigured. The default is 60 seconds.</span></td>
			    </tr>
<?php if ($g['platform'] == "generic-pc" || $g['platform'] == "generic-pc-serial"): ?>
				<tr> 
                  <td width="22%" valign="top" class="vncell">Hard disk standby time </td>
                  <td width="78%" class="vtable"> 
                    <select name="harddiskstandby" class="formfld">
					<?php $sbvals = array(1,2,3,4,5,10,15,20,30,60); ?>
                      <option value="" <?php if(empty($pconfig['harddiskstandby'])) echo('selected');?>>Always on</option>
					<?php foreach ($sbvals as $sbval): ?>
                      <option value="<?=$sbval;?>" <?php if(($pconfig['harddiskstandby'] ?? null) == $sbval) echo 'selected';?>><?=$sbval;?> minutes</option>
					<?php endforeach; ?>
                    </select>
                    <br>
                    Puts the hard disk into standby mode when the selected amount of time after the last
                    access has elapsed. <em>Do not set this for CF cards.</em></td>
				</tr>
<?php endif; ?>
				<tr> 
                  <td width="22%" valign="top" class="vncell">Navigation</td>
                  <td width="78%" class="vtable"> 
                    <input name="expanddiags" type="checkbox" id="expanddiags" value="yes" <?php if (!empty($pconfig['expanddiags'])) echo "checked"; ?>>
                    <strong>Keep diagnostics in navigation expanded </strong></td>
                </tr>
				<tr> 
                  <td width="22%" valign="top" class="vncell">webGUI anti-lockout</td>
                  <td width="78%" class="vtable"> 
                    <input name="noantilockout" type="checkbox" id="noantilockout" value="yes" <?php if (!empty($pconfig['noantilockout'])) echo "checked"; ?>>
                    <strong>Disable webGUI anti-lockout rule</strong><br>
					By default, access to the webGUI on the LAN interface is always permitted, regardless of the user-defined filter rule set. Enable this feature to control webGUI access (make sure to have a filter rule in place that allows you in, or you will lock yourself out!).<br>
					Hint: 
					the &quot;set LAN IP address&quot; option in the console menu  resets this setting as well.</td>
                </tr>
				<tr> 
                  <td width="22%" valign="top" class="vncell">IPsec SA preferral</td>
                  <td width="78%" class="vtable"> 
                    <input name="preferoldsa_enable" type="checkbox" id="preferoldsa_enable" value="yes" <?php if (!empty($pconfig['preferoldsa_enable'])) echo "checked"; ?>>
                    <strong>Prefer old IPsec SAs</strong><br>
					By default, if several SAs match, the newest one is preferred.
					Select this option to always prefer old SAs over new ones.
					</td>
                </tr>
				<tr> 
                  <td width="22%" valign="top" class="vncell">Device polling</td>
                  <td width="78%" class="vtable"> 
                    <input name="polling_enable" type="checkbox" id="polling_enable" value="yes" <?php if (!empty($pconfig['polling_enable'])) echo "checked"; ?>>
                    <strong>Use device polling</strong><br>
					Device polling is a technique that lets the system periodically poll network devices for new
					data instead of relying on interrupts. This can reduce CPU load and therefore increase
					throughput, at the expense of a slightly higher forwarding delay (the devices are polled 1000 times
					per second). Not all NICs support polling; see the m0n0wall homepage for a list of supported cards.
					</td>
                </tr>
				<tr>
                  <td valign="top" class="vncell">Firewall states displayed</td>
                  <td class="vtable">
                    <input name="ipfstatentries" type="text" class="formfld" id="ipfstatentries" size="8" value="<?=htmlspecialchars($pconfig['ipfstatentries'] ?? '');?>">
                    entries<br>
    				<span class="vexpl">Maxmimum number of firewall state entries to be displayed on the <a href="diag_ipfstat.php">Diagnostics: Firewall state</a> page.
    				Default is 300. Setting this to a very high value will cause a slowdown when viewing the
    				firewall states page, depending on your system's processing power.</span></td>
			    </tr>
				<!-- The "Enable Ralink USB wireless devices" checkbox is gone.
				     It loaded the runfw firmware module, and sys/modules/runfw
				     no longer exists in FreeBSD 15 -- the firmware moved into
				     the run(4) driver itself, which is already compiled in. So
				     the kldload could only fail, and the option was a control
				     that configured nothing. Ralink USB adapters work without
				     it. -->
                <tr> 
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%"> 
                    <input name="Submit" type="submit" class="formbtn" value="Save"> 
                  </td>
                </tr>
              </table>
</form>
<?php include("fend.inc"); ?>
