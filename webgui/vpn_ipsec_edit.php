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

$pgtitle = array("VPN", "IPsec", "Edit tunnel");
require("guiconfig.inc");

if (!is_array($config['ipsec']['tunnel'] ?? null)) {
	$config['ipsec']['tunnel'] = array();
}
$a_ipsec = &$config['ipsec']['tunnel'];

$specialsrcdst = explode(" ", "lan");

$id = $_GET['id'] ?? null;
if (isset($_POST['id']))
	$id = $_POST['id'];
	
function is_specialnet($net) {
	global $specialsrcdst;
	
	if (in_array($net, $specialsrcdst))
		return true;
	else
		return false;
}

function address_to_pconfig($adr, &$padr, &$pmask) {
		
	if (!empty($adr['network']))
		$padr = $adr['network'];
	else if (!empty($adr['address'])) {
		/* a single host has no /bits part -> explode() returns one element */
		$addrparts = explode("/", $adr['address']);
		$padr = $addrparts[0];
		$pmask = $addrparts[1] ?? null;
		if (is_null($pmask))
			$pmask = 32;
	}
}

function pconfig_to_address(&$adr, $padr, $pmask) {
	
	$adr = array();
	
	if (is_specialnet($padr))
		$adr['network'] = $padr;
	else {
		$adr['address'] = $padr;
		if ($pmask != 32)
			$adr['address'] .= "/" . $pmask;
	}
}

if (isset($id) && !empty($a_ipsec[$id])) {
	$pconfig['disabled'] = isset($a_ipsec[$id]['disabled']);
	$pconfig['natt'] = isset($a_ipsec[$id]['natt']);
	$pconfig['dpddelay'] = $a_ipsec[$id]['dpddelay'] ?? null;
	//$pconfig['auto'] = isset($a_ipsec[$id]['auto']);

	if (!isset($a_ipsec[$id]['local-subnet']))
		$pconfig['localnet'] = "lan";
	else
		address_to_pconfig($a_ipsec[$id]['local-subnet'], $pconfig['localnet'], $pconfig['localnetmask']);
		
	if (!empty($a_ipsec[$id]['interface']))
		$pconfig['interface'] = $a_ipsec[$id]['interface'];
	else
		$pconfig['interface'] = "wan";
		
	/* an unspecified remote subnet has no /bits part -> explode() returns one element */
	$remoteparts = explode("/", $a_ipsec[$id]['remote-subnet'] ?? '');
	$pconfig['remotenet'] = $remoteparts[0] ?? null;
	$pconfig['remotebits'] = $remoteparts[1] ?? null;
	$pconfig['remotegw'] = $a_ipsec[$id]['remote-gateway'] ?? null;
	$pconfig['p1mode'] = $a_ipsec[$id]['p1']['mode'] ?? null;
	
	if (isset($a_ipsec[$id]['p1']['myident']['myaddress']))
		$pconfig['p1myidentt'] = 'myaddress';
	else if (isset($a_ipsec[$id]['p1']['myident']['address'])) {
		$pconfig['p1myidentt'] = 'address';
		$pconfig['p1myident'] = $a_ipsec[$id]['p1']['myident']['address'];
	} else if (isset($a_ipsec[$id]['p1']['myident']['fqdn'])) {
		$pconfig['p1myidentt'] = 'fqdn';
		$pconfig['p1myident'] = $a_ipsec[$id]['p1']['myident']['fqdn'];
	} else if (isset($a_ipsec[$id]['p1']['myident']['ufqdn'])) {
		$pconfig['p1myidentt'] = 'user_fqdn';
		$pconfig['p1myident'] = $a_ipsec[$id]['p1']['myident']['ufqdn'];
 	} else if (isset($a_ipsec[$id]['p1']['myident']['asn1dn'])) {
		$pconfig['p1myidentt'] = 'asn1dn';
		$pconfig['p1myident'] = $a_ipsec[$id]['p1']['myident']['asn1dn'];
	}
	
	$pconfig['p1ealgo'] = $a_ipsec[$id]['p1']['encryption-algorithm'] ?? null;
	$pconfig['p1halgo'] = $a_ipsec[$id]['p1']['hash-algorithm'] ?? null;
	$pconfig['p1dhgroup'] = $a_ipsec[$id]['p1']['dhgroup'] ?? null;
	$pconfig['p1lifetime'] = $a_ipsec[$id]['p1']['lifetime'] ?? null;
	$pconfig['p1authentication_method'] = $a_ipsec[$id]['p1']['authentication_method'] ?? null;
	$pconfig['p1pskey'] = $a_ipsec[$id]['p1']['pre-shared-key'] ?? null;
	$pconfig['p1cert'] = base64_decode($a_ipsec[$id]['p1']['cert'] ?? '');
	$pconfig['p1peercert'] = base64_decode($a_ipsec[$id]['p1']['peercert'] ?? '');
	$pconfig['p1privatekey'] = base64_decode($a_ipsec[$id]['p1']['private-key'] ?? '');
	$pconfig['p2proto'] = $a_ipsec[$id]['p2']['protocol'] ?? null;
	$pconfig['p2ealgos'] = $a_ipsec[$id]['p2']['encryption-algorithm-option'] ?? null;
	$pconfig['p2halgos'] = $a_ipsec[$id]['p2']['hash-algorithm-option'] ?? null;
	$pconfig['p2pfsgroup'] = $a_ipsec[$id]['p2']['pfsgroup'] ?? null;
	$pconfig['p2lifetime'] = $a_ipsec[$id]['p2']['lifetime'] ?? null;
	$pconfig['descr'] = $a_ipsec[$id]['descr'] ?? null;
	
} else {
	/* defaults */
	$pconfig['interface'] = "wan";
	$pconfig['localnet'] = "lan";
	/* Modern defaults (2026-09-29): IKEv2, AES-256, SHA-256, DH group 14 in
	   both phases, PFS on. These used to be IKEv1 main / 3DES / SHA-1 / DH 2
	   (1024-bit, broken) and phase 2 offered 3DES, Blowfish, CAST128 and MD5
	   with no PFS. Only a NEW tunnel gets these: an existing one keeps what it
	   has stored. 'rijndael 256' is how the lists spell AES-256. */
	$pconfig['p1mode'] = "ikev2";
	$pconfig['p1myidentt'] = "myaddress";
	$pconfig['p1authentication_method'] = "pre_shared_key";
	$pconfig['p1ealgo'] = "rijndael 256";
	$pconfig['p1halgo'] = "sha256";
	$pconfig['p1dhgroup'] = "14";
	$pconfig['p2proto'] = "esp";
	$pconfig['p2ealgos'] = array("rijndael 256");
	$pconfig['p2halgos'] = array("hmac_sha256");
	$pconfig['p2pfsgroup'] = "14";
	$pconfig['remotebits'] = 32;
}

if ($_POST) {
	if (is_specialnet($_POST['localnettype'] ?? null)) {
		$_POST['localnet'] = $_POST['localnettype'];
		$_POST['localnetmask'] = 0;
	} else if (($_POST['localnettype'] ?? null) == "single") {
		$_POST['localnetmask'] = 32;
	}
	
	$input_errors = array();
	$pconfig = $_POST;

	/* input validation */
	if (($_POST['p1authentication_method'] ?? null) == "pre_shared_key") {
		$reqdfields = explode(" ", "localnet remotenet remotebits remotegw p1pskey p2ealgos p2halgos");
		$reqdfieldsn = explode(",", "Local network,Remote network,Remote network bits,Remote gateway,Pre-Shared Key,P2 Encryption Algorithms,P2 Hash Algorithms");
	}
	else {
		$reqdfields = explode(" ", "localnet remotenet remotebits remotegw p2ealgos p2halgos");
		$reqdfieldsn = explode(",", "Local network,Remote network,Remote network bits,Remote gateway,P2 Encryption Algorithms,P2 Hash Algorithms");	
		/* Shared validator -- see pem_validate_keypair() in util.inc. */
		$input_errors = array_merge($input_errors,
			pem_validate_keypair($_POST['p1cert'] ?? '', $_POST['p1privatekey'] ?? '',
			                     'charon'));
		/* The peer's certificate has no key of ours to match, so only its shape
		   is checked -- and only when one was supplied. */
		if (($_POST['p1peercert'] ?? '') !== '' && !is_pem_certificate($_POST['p1peercert']))
			$input_errors[] = "This peer certificate does not appear to be valid. It " .
			    "should be PEM, beginning with \"-----BEGIN CERTIFICATE-----\".";
	}
	
	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
	
	if ((!empty($_POST['dpddelay']) && !is_numeric($_POST['dpddelay']))) {
		$input_errors[] = "The DPD interval must be an integer.";
	}
	
	if (!is_specialnet($_POST['localnettype'] ?? null)) {
		if ((!empty($_POST['localnet']) && !is_ipaddr4or6($_POST['localnet']))) {
			$input_errors[] = "A valid local network IP address must be specified.";
		}
		if ((!empty($_POST['localnetmask']) && !is_numeric($_POST['localnetmask']))) {
			$input_errors[] = "A valid local network bit count must be specified.";
		}
	}
	if ((!empty($_POST['p1lifetime']) && !is_numeric($_POST['p1lifetime']))) {
		$input_errors[] = "The P1 lifetime must be an integer.";
	}
	if ((!empty($_POST['p2lifetime']) && !is_numeric($_POST['p2lifetime']))) {
		$input_errors[] = "The P2 lifetime must be an integer.";
	}
	if (!empty($_POST['remotebits']) && (!is_numeric($_POST['remotebits']) || ($_POST['remotebits'] < 0) || ($_POST['remotebits'] > 128))) {
		$input_errors[] = "The remote network bits are invalid.";
	}
	if ((!empty($_POST['remotenet']) && !is_ipaddr4or6($_POST['remotenet']))) {
		$input_errors[] = "A valid remote network address must be specified.";
	}
	if ((!empty($_POST['remotegw']) && !is_ipaddr4or6($_POST['remotegw']) && !is_domain($_POST['remotegw']))) {
		$input_errors[] = "A valid remote gateway address or host name must be specified.";
	}
	if ((!empty($_POST['remotenet']) && is_ipaddr6($_POST['remotenet'])) && (!empty($_POST['remotegw']) && !is_ipaddr6($_POST['remotegw']))) {
		$input_errors[] = "You can not set an ipv6 remote subnet to an ipv4 remote gateway";
	}	
	if ((!empty($_POST['remotenet']) && is_ipaddr($_POST['remotenet'])) && (!empty($_POST['remotegw']) && is_ipaddr6($_POST['remotegw']))) {
		$input_errors[] = "You can not set an ipv4 remote subnet to an ipv6 remote gateway";
	}	
	if (((($_POST['p1myidentt'] ?? null) == "address") && !is_ipaddr4or6($_POST['p1myident'] ?? ''))) {
		$input_errors[] = "A valid IP address for 'My identifier' must be specified.";
	}
	if (((($_POST['p1myidentt'] ?? null) == "fqdn") && !is_domain($_POST['p1myident'] ?? null))) {
		$input_errors[] = "A valid domain name for 'My identifier' must be specified.";
	}
	if (($_POST['p1myidentt'] ?? null) == "user_fqdn") {
		$ufqdn = explode("@",$_POST['p1myident'] ?? '');
		if (!is_domain($ufqdn[1] ?? null)) 
			$input_errors[] = "A valid User FQDN in the form of user@my.domain.com for 'My identifier' must be specified.";
	}
	
	if (($_POST['p1myidentt'] ?? null) == "myaddress")
		$_POST['p1myident'] = "";

	if (empty($input_errors)) {
		$ipsecent['disabled'] = !empty($_POST['disabled']) ? true : false;
		//$ipsecent['auto'] = $_POST['auto'] ? true : false;
		$ipsecent['dpddelay'] = $pconfig['dpddelay'] ?? null;
		$ipsecent['interface'] = $pconfig['interface'] ?? null;
		$ipsecent['natt'] = !empty($_POST['natt']) ? true : false;
		pconfig_to_address($ipsecent['local-subnet'], $_POST['localnet'] ?? null, $_POST['localnetmask'] ?? null);
		$ipsecent['remote-subnet'] = $_POST['remotenet'] . "/" . $_POST['remotebits'];
		$ipsecent['remote-gateway'] = $_POST['remotegw'];
		$ipsecent['p1']['mode'] = $_POST['p1mode'] ?? null;
		
		$ipsecent['p1']['myident'] = array();
		switch ($_POST['p1myidentt'] ?? null) {
			case 'myaddress':
				$ipsecent['p1']['myident']['myaddress'] = true;
				break;
			case 'address':
				$ipsecent['p1']['myident']['address'] = $_POST['p1myident'] ?? null;
				break;
			case 'fqdn':
				$ipsecent['p1']['myident']['fqdn'] = $_POST['p1myident'] ?? null;
				break;
			case 'user_fqdn':
				$ipsecent['p1']['myident']['ufqdn'] = $_POST['p1myident'] ?? null;
				break;
			case 'asn1dn':
				$ipsecent['p1']['myident']['asn1dn'] = $_POST['p1myident'] ?? null;
				break;
		}
		
		$ipsecent['p1']['encryption-algorithm'] = $_POST['p1ealgo'] ?? null;
		$ipsecent['p1']['hash-algorithm'] = $_POST['p1halgo'] ?? null;
		$ipsecent['p1']['dhgroup'] = $_POST['p1dhgroup'] ?? null;
		$ipsecent['p1']['lifetime'] = $_POST['p1lifetime'] ?? null;
		$ipsecent['p1']['pre-shared-key'] = $_POST['p1pskey'] ?? null;
		$ipsecent['p1']['private-key'] = base64_encode($_POST['p1privatekey'] ?? '');
		$ipsecent['p1']['cert'] = base64_encode($_POST['p1cert'] ?? '');
		$ipsecent['p1']['peercert'] = base64_encode($_POST['p1peercert'] ?? '');
		$ipsecent['p1']['authentication_method'] = $_POST['p1authentication_method'] ?? null;
		$ipsecent['p2']['protocol'] = $_POST['p2proto'] ?? null;
		$ipsecent['p2']['encryption-algorithm-option'] = $_POST['p2ealgos'] ?? null;
		$ipsecent['p2']['hash-algorithm-option'] = $_POST['p2halgos'] ?? null;
		$ipsecent['p2']['pfsgroup'] = $_POST['p2pfsgroup'] ?? null;
		$ipsecent['p2']['lifetime'] = $_POST['p2lifetime'] ?? null;
		$ipsecent['descr'] = $_POST['descr'] ?? null;
		
		if (isset($id) && !empty($a_ipsec[$id]))
			$a_ipsec[$id] = $ipsecent;
		else
			$a_ipsec[] = $ipsecent;
		
		write_config();
		touch($d_ipsecconfdirty_path);
		
		header("Location: vpn_ipsec.php");
		exit;
	}
}
?>
<?php include("fbegin.inc"); ?>
<script type="text/javascript">
<!--
function typesel_change() {
	switch (document.iform.localnettype.selectedIndex) {
		case 0:	/* single */
			document.iform.localnet.disabled = 0;
			document.iform.localnetmask.value = "";
			document.iform.localnetmask.disabled = 1;
			break;
		case 1:	/* network */
			document.iform.localnet.disabled = 0;
			document.iform.localnetmask.disabled = 0;
			break;
		default:
			document.iform.localnet.value = "";
			document.iform.localnet.disabled = 1;
			document.iform.localnetmask.value = "";
			document.iform.localnetmask.disabled = 1;
			break;
	}
}
function methodsel_change() {
	switch (document.iform.p1authentication_method.selectedIndex) {
		case 1:	/* rsa */
			document.iform.p1pskey.disabled = 1;
			document.iform.p1privatekey.disabled = 0;
			document.iform.p1cert.disabled = 0;
			document.iform.p1peercert.disabled = 0;
			break;
		default: /* pre-shared */
			document.iform.p1pskey.disabled = 0;
			document.iform.p1privatekey.disabled = 1;
			document.iform.p1cert.disabled = 1;
			document.iform.p1peercert.disabled = 1;
			break;
	}
}
//-->
</script>
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
            <form action="vpn_ipsec_edit.php" method="post" name="iform" id="iform">
              <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="content pane">
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Mode</td>
                  <td width="78%" class="vtable"> Tunnel</td>
                </tr>
				<tr> 
                  <td width="22%" valign="top" class="vncellreq">Disabled</td>
                  <td width="78%" class="vtable"> 
                    <input name="disabled" type="checkbox" id="disabled" value="yes" <?php if (!empty($pconfig['disabled'])) echo "checked"; ?>>
                    <strong>Disable this tunnel</strong><br>
                    <span class="vexpl">Set this option to disable this tunnel without
					removing it from the list.</span></td>
                </tr>
				<!-- <tr> 
				  <td width="22%" valign="top" class="vncellreq">Auto-establish</td>
				  <td width="78%" class="vtable"> 
					<input name="auto" type="checkbox" id="auto" value="yes" <?php if (!empty($pconfig['auto'])) echo "checked"; ?>>
					<strong>Automatically establish this tunnel</strong><br>
					<span class="vexpl">Set this option to automatically re-establish this tunnel after reboots/reconfigures. If this is not set, the tunnel is established on demand.</span></td>
				</tr> -->
				<tr> 
                  <td width="22%" valign="top" class="vncellreq">Interface</td>
                  <td width="78%" class="vtable"><select name="interface" class="formfld">
                      <?php $interfaces = array('wan' => 'WAN', 'lan' => 'LAN');
					  /* OPT numbering can have gaps: deleting an interface no longer renumbers. */
					  foreach (opt_interfaces() as $optif) {
							$interfaces[$optif] = $config['interfaces'][$optif]['descr'] ?? '';
					  }
					  foreach ($interfaces as $iface => $ifacename): ?>
                      <option value="<?=$iface;?>" <?php if ($iface == ($pconfig['interface'] ?? null)) echo "selected"; ?>> 
                      <?=htmlspecialchars($ifacename);?>
                      </option>
                      <?php endforeach; ?>
                    </select> <br>
                    <span class="vexpl">Select the interface for the local endpoint of this tunnel.</span></td>
                </tr>
				<tr> 
                  <td width="22%" valign="top" class="vncellreq">NAT-T</td>
                  <td width="78%" class="vtable"> 
                    <input name="natt" type="checkbox" id="natt" value="yes" <?php if (!empty($pconfig['natt'])) echo "checked"; ?>>
                    <strong>Enable NAT Traversal (NAT-T)</strong><br>
                    <span class="vexpl">Set this option to enable the use of NAT-T (i.e. the encapsulation of ESP in UDP packets) if needed,
                    	which can help with clients that are behind restrictive firewalls.</span></td>
                </tr>
                <tr> 
				  <td width="22%" valign="top" class="vncellreq">DPD interval</td>
				  <td width="78%" class="vtable"> 
					<input name="dpddelay" type="text" class="formfld" id="dpddelay" size="5" value="<?php echo htmlspecialchars($pconfig['dpddelay'] ?? ''); ?>"> seconds<br>
					<span class="vexpl">Enter a value here to enable Dead Peer Detection (e.g. 60 seconds).</span></td>
				</tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Local subnet</td>
                  <td width="78%" class="vtable"> 
                    <table border="0" cellspacing="0" cellpadding="0" summary="network widget">
                      <tr> 
                        <td>Type:&nbsp;&nbsp;</td>
						<td></td>
                        <td><select name="localnettype" class="formfld" onChange="typesel_change()">
                            <?php $sel = is_specialnet($pconfig['localnet'] ?? null); ?>
                            <option value="single" <?php if ((($pconfig['localnetmask'] ?? null) == 32) && !$sel) { echo "selected"; $sel = 1; } ?>> 
                            Single host</option>
                            <option value="network" <?php if (!$sel) echo "selected"; ?>> 
                            Network</option>
                            <option value="lan" <?php if (($pconfig['localnet'] ?? null) == "lan") { echo "selected"; } ?>> 
                            LAN subnet</option>
                          </select></td>
                      </tr>
                      <tr> 
                        <td>Address:&nbsp;&nbsp;</td>
						<td><?=$mandfldhtmlspc;?></td>
                        <td><input name="localnet" type="text" class="formfld" id="localnet" size="20" value="<?php if (!is_specialnet($pconfig['localnet'] ?? null)) echo htmlspecialchars($pconfig['localnet'] ?? '');?>">
                          / 
                          <select name="localnetmask" class="formfld" id="localnetmask">
                            <?php for ($i = 127; $i >= 0; $i--): ?>
                            <option value="<?=$i;?>" <?php if ($i == ($pconfig['localnetmask'] ?? null)) echo "selected"; ?>>
                            <?=$i;?>
                            </option>
                            <?php endfor; ?>
                          </select> </td>
                      </tr>
                    </table></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Remote subnet</td>
                  <td width="78%" class="vtable"> 
                    <?=$mandfldhtml;?><input name="remotenet" type="text" class="formfld" id="remotenet" size="20" value="<?=$pconfig['remotenet'] ?? '';?>">
                    / 
                    <select name="remotebits" class="formfld" id="remotebits">
                      <?php for ($i = 128; $i >= 0; $i--): ?>
                      <option value="<?=$i;?>" <?php if ($i == ($pconfig['remotebits'] ?? null)) echo "selected"; ?>> 
                      <?=$i;?>
                      </option>
                      <?php endfor; ?>
                    </select></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Remote gateway</td>
                  <td width="78%" class="vtable"> 
                    <?=$mandfldhtml;?><input name="remotegw" type="text" class="formfld" id="remotegw" size="20" value="<?=$pconfig['remotegw'] ?? '';?>"> 
                    <br>
                    Enter the public IP address or host name of the remote gateway. For ipv6, use an ipv6 IP address.</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">Description</td>
                  <td width="78%" class="vtable"> 
                    <input name="descr" type="text" class="formfld" id="descr" size="40" value="<?=htmlspecialchars($pconfig['descr'] ?? '');?>"> 
                    <br> <span class="vexpl">You may enter a description here 
                    for your reference (not parsed).</span></td>
                </tr>
                <tr> 
                  <td colspan="2" class="list" height="12"></td>
                </tr>
                <tr> 
                  <td colspan="2" valign="top" class="listtopic">Phase 1 proposal 
                    (Authentication)</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Negotiation mode</td>
                  <td width="78%" class="vtable">
					<select name="p1mode" class="formfld">
                      <?php foreach ($p1_modes as $mode => $modename): ?>
                      <option value="<?=$mode;?>" <?php if ($mode == ($pconfig['p1mode'] ?? null)) echo "selected"; ?>> 
                      <?=htmlspecialchars($modename);?>
                      </option>
                      <?php endforeach; ?>
                    </select> <br> <span class="vexpl">IKEv2 is recommended. Use IKEv1 only
                    for a peer that supports nothing else &ndash; and avoid IKEv1
                    aggressive mode with a pre-shared key: it sends a hash of the key
                    that can be cracked offline.</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">My identifier</td>
                  <td width="78%" class="vtable">
					<select name="p1myidentt" class="formfld">
                      <?php foreach ($my_identifier_list as $mode => $modename): ?>
                      <option value="<?=$mode;?>" <?php if ($mode == ($pconfig['p1myidentt'] ?? null)) echo "selected"; ?>> 
                      <?=htmlspecialchars($modename);?>
                      </option>
                      <?php endforeach; ?>
                    </select> <input name="p1myident" type="text" class="formfld" id="p1myident" size="30" value="<?=$pconfig['p1myident'] ?? '';?>"> 
                  </td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Encryption algorithm</td>
                  <td width="78%" class="vtable">
					<select name="p1ealgo" class="formfld">
                      <?php foreach ($p1_ealgos as $algo => $algoname): ?>
                      <option value="<?=$algo;?>" <?php if ($algo == ($pconfig['p1ealgo'] ?? null)) echo "selected"; ?>> 
                      <?=htmlspecialchars($algoname);?>
                      </option>
                      <?php endforeach; ?>
                    </select> <br> <span class="vexpl">Must match the setting 
                    chosen on the remote side. </span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Hash algorithm</td>
                  <td width="78%" class="vtable">
					<select name="p1halgo" class="formfld">
                      <?php foreach ($p1_halgos as $algo => $algoname): ?>
                      <option value="<?=$algo;?>" <?php if ($algo == ($pconfig['p1halgo'] ?? null)) echo "selected"; ?>> 
                      <?=htmlspecialchars($algoname);?>
                      </option>
                      <?php endforeach; ?>
                    </select> <br> <span class="vexpl">Must match the setting 
                    chosen on the remote side. </span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">DH key group</td>
                  <td width="78%" class="vtable">
					<select name="p1dhgroup" class="formfld">
                      <?php foreach ($p1_keygroups as $keygroup => $keygroupname): ?>
                      <option value="<?=$keygroup;?>" <?php if ($keygroup == ($pconfig['p1dhgroup'] ?? null)) echo "selected"; ?>> 
                      <?=htmlspecialchars($keygroupname);?>
                      </option>
                      <?php endforeach; ?>
                    </select> <br> <span class="vexpl">Must match the setting
	                chosen on the remote side. </span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">Lifetime</td>
                  <td width="78%" class="vtable"> 
                    <input name="p1lifetime" type="text" class="formfld" id="p1lifetime" size="20" value="<?=$pconfig['p1lifetime'] ?? '';?>">
                    seconds</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Authentication method</td>
                  <td width="78%" class="vtable">
					<select name="p1authentication_method" class="formfld" onChange="methodsel_change()">
                      <?php foreach ($p1_authentication_methods as $method => $methodname): ?>
                      <option value="<?=$method;?>" <?php if ($method == ($pconfig['p1authentication_method'] ?? null)) echo "selected"; ?>> 
                      <?=htmlspecialchars($methodname);?>
                      </option>
                      <?php endforeach; ?>
                    </select> <br> <span class="vexpl">Must match the setting 
                    chosen on the remote side.</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Pre-Shared Key</td>
                  <td width="78%" class="vtable"> 
                    <?=$mandfldhtml;?><input name="p1pskey" type="text" class="formfld" id="p1pskey" size="40" value="<?=htmlspecialchars($pconfig['p1pskey'] ?? '');?>"> 
                  </td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Certificate</td>
                  <td width="78%" class="vtable"> 
                    <textarea name="p1cert" cols="65" rows="7" id="p1cert" class="formpre"><?=htmlspecialchars($pconfig['p1cert'] ?? '');?></textarea>
                    <br> 
                    Paste a certificate in X.509 PEM format here.</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Key</td>
                  <td width="78%" class="vtable"> 
                    <textarea name="p1privatekey" cols="65" rows="7" id="p1privatekey" class="formpre"><?=htmlspecialchars($pconfig['p1privatekey'] ?? '');?></textarea>
                    <br> 
                    Paste an RSA private key in PEM format here.</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">Peer certificate</td>
                  <td width="78%" class="vtable"> 
                    <textarea name="p1peercert" cols="65" rows="7" id="p1peercert" class="formpre"><?=htmlspecialchars($pconfig['p1peercert'] ?? '');?></textarea>
                    <br> 
                    Paste the peer X.509 certificate in PEM format here.<br>
                    Leave this blank if you want to use a CA certificate for identity validation.</td>
                </tr>
                <tr> 
                  <td colspan="2" class="list" height="12"></td>
                </tr>
                <tr> 
                  <td colspan="2" valign="top" class="listtopic">Phase 2 proposal 
                    (SA/Key Exchange)</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Protocol</td>
                  <td width="78%" class="vtable">
					<select name="p2proto" class="formfld">
                      <?php foreach ($p2_protos as $proto => $protoname): ?>
                      <option value="<?=$proto;?>" <?php if ($proto == ($pconfig['p2proto'] ?? null)) echo "selected"; ?>> 
                      <?=htmlspecialchars($protoname);?>
                      </option>
                      <?php endforeach; ?>
                    </select> <br> <span class="vexpl">ESP is encryption, AH is 
                    authentication only </span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Encryption algorithms</td>
                  <td width="78%" class="vtable"> 
                    <?php foreach ($p2_ealgos as $algo => $algoname): ?>
                    <input type="checkbox" name="p2ealgos[]" value="<?=$algo;?>" <?php if (in_array($algo, $pconfig['p2ealgos'] ?? array())) echo "checked"; ?>> 
                    <?=htmlspecialchars($algoname);?>
                    <br> 
                    <?php endforeach; ?>
                    <br>
                    Hint: use 3DES for best compatibility or if you have a hardware 
                    crypto accelerator card. Blowfish is usually the fastest in 
                    software encryption. </td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Hash algorithms</td>
                  <td width="78%" class="vtable"> 
                    <?php foreach ($p2_halgos as $algo => $algoname): ?>
                    <input type="checkbox" name="p2halgos[]" value="<?=$algo;?>" <?php if (in_array($algo, $pconfig['p2halgos'] ?? array())) echo "checked"; ?>> 
                    <?=htmlspecialchars($algoname);?>
                    <br> 
                    <?php endforeach; ?>
				  </td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">PFS key group</td>
                  <td width="78%" class="vtable">
					<select name="p2pfsgroup" class="formfld">
                      <?php foreach ($p2_pfskeygroups as $keygroup => $keygroupname): ?>
                      <option value="<?=$keygroup;?>" <?php if ($keygroup == ($pconfig['p2pfsgroup'] ?? null)) echo "selected"; ?>> 
                      <?=htmlspecialchars($keygroupname);?>
                      </option>
                      <?php endforeach; ?>
                    </select></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">Lifetime</td>
                  <td width="78%" class="vtable"> 
                    <input name="p2lifetime" type="text" class="formfld" id="p2lifetime" size="20" value="<?=$pconfig['p2lifetime'] ?? '';?>">
                    seconds</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%"> 
                    <input name="Submit" type="submit" class="formbtn" value="Save"> 
                    <?php if (isset($id) && !empty($a_ipsec[$id])): ?>
                    <input name="id" type="hidden" value="<?=htmlspecialchars($id);?>"> 
                    <?php endif; ?>
                  </td>
                </tr>
              </table>
</form>
<script type="text/javascript">
<!--
typesel_change();
methodsel_change();
//-->
</script>
<?php include("fend.inc"); ?>
