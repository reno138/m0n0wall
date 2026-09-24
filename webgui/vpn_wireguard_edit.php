<?php
/*
	vpn_wireguard_edit.php
	part of m0n0wall (http://m0n0.ch/wall)

	Copyright (C) 2026 m0n0wall contributors.
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the conditions of the two-clause
	BSD licence carried by the rest of m0n0wall are met.
*/

$pgtitle = array("VPN", "WireGuard", "Edit tunnel");
require("guiconfig.inc");

if (!is_array($config['wireguard']['tunnel'] ?? null)) {
	$config['wireguard']['tunnel'] = array();
}
$a_tunnel = &$config['wireguard']['tunnel'];

$id = $_GET['id'] ?? null;
if (isset($_POST['id']))
	$id = $_POST['id'];

if (isset($id) && !empty($a_tunnel[$id])) {
	$pconfig = $a_tunnel[$id];
} else {
	/* Sensible defaults: the next free wgN, a port, and a subnet from the
	   100.64/10 CGNAT range, which rarely collides with a home LAN. */
	$used = array();
	foreach ($a_tunnel as $t)
		$used[$t['if']] = true;
	for ($n = 0; isset($used["wg$n"]); $n++)
		;
	$pconfig['if']         = "wg$n";
	$pconfig['listenport'] = 51820 + $n;
	$pconfig['address']    = "10.6." . (6 + $n) . ".1";
	$pconfig['subnet']     = "24";
	$pconfig['enable']     = true;
}

if ($_POST) {

	unset($input_errors);
	$pconfig = $_POST;

	$reqdfields = explode(" ", "if address subnet listenport");
	$reqdfieldsn = explode(",", "Interface,Tunnel address,Subnet mask,Listen port");
	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

	if (!empty($_POST['if']) && !preg_match('/^wg\d+$/', $_POST['if']))
		$input_errors[] = "The interface name must be wg followed by a number, e.g. wg0.";

	$postif = $_POST['if'] ?? null;
	foreach ($a_tunnel as $ti => $t) {
		if ((!isset($id) || $ti != $id) && $t['if'] == $postif) {
			$input_errors[] = "Interface {$postif} is already used by another tunnel.";
			break;
		}
	}

	if (!empty($_POST['address']) && !is_ipaddr($_POST['address']))
		$input_errors[] = "A valid tunnel address must be specified.";

	if (!empty($_POST['subnet']) && (!is_numericint($_POST['subnet']) || $_POST['subnet'] < 8 || $_POST['subnet'] > 30))
		$input_errors[] = "The subnet mask must be between 8 and 30. A /31 or /32 leaves no room for peers.";

	if (!empty($_POST['listenport']) && !is_port($_POST['listenport']))
		$input_errors[] = "A valid listen port must be specified.";

	if (!empty($_POST['privatekey']) && !wg_is_valid_key($_POST['privatekey']))
		$input_errors[] = "That does not look like a WireGuard private key.";

	if (!empty($_POST['endpoint']) && !wg_is_valid_endpoint($_POST['endpoint']))
		$input_errors[] = "The endpoint must be host:port.";

	if (!empty($_POST['mtu']) && (!is_numericint($_POST['mtu']) || $_POST['mtu'] < 576 || $_POST['mtu'] > 9000))
		$input_errors[] = "The MTU must be between 576 and 9000.";

	/* Shrinking the subnet can strand peers that already hold an address
	   outside the new range. Say so rather than silently breaking them. */
	if (!$input_errors && isset($id) && is_array($a_tunnel[$id]['peer'] ?? null)) {
		$net = gen_subnet($_POST['address'], $_POST['subnet']);
		foreach ($a_tunnel[$id]['peer'] as $p) {
			if (!empty($p['address']) && !ip_in_subnet($p['address'], "$net/{$_POST['subnet']}")) {
				$input_errors[] = "Peer '{$p['name']}' has address {$p['address']}, which is outside {$net}/{$_POST['subnet']}. Move or remove it first.";
			}
		}
	}

	if (!$input_errors) {
		$tunnel = isset($id) && !empty($a_tunnel[$id]) ? $a_tunnel[$id] : array();

		$tunnel['if']         = $_POST['if'] ?? null;
		$tunnel['address']    = $_POST['address'] ?? null;
		$tunnel['subnet']     = $_POST['subnet'] ?? null;
		$tunnel['listenport'] = $_POST['listenport'] ?? null;
		$tunnel['endpoint']   = $_POST['endpoint'] ?? null;
		$tunnel['dns']        = $_POST['dns'] ?? null;
		$tunnel['mtu']        = $_POST['mtu'] ?? null;
		$tunnel['descr']      = $_POST['descr'] ?? null;
		if (!empty($_POST['disabled']))
			$tunnel['disabled'] = true;
		else
			unset($tunnel['disabled']);

		/* Generate the firewall's own key pair once and keep it. Rotating it
		   would invalidate every client config already handed out. */
		if (!empty($_POST['privatekey'])) {
			$tunnel['privatekey'] = $_POST['privatekey'];
			$tunnel['publickey']  = trim(shell_exec("echo " . escapeshellarg($_POST['privatekey']) . " | " . WG_BIN . " pubkey"));
		} else if (empty($tunnel['privatekey'])) {
			$priv = trim(shell_exec(WG_BIN . " genkey"));
			$tunnel['privatekey'] = $priv;
			$tunnel['publickey']  = trim(shell_exec("echo " . escapeshellarg($priv) . " | " . WG_BIN . " pubkey"));
		}

		if (isset($id) && !empty($a_tunnel[$id]))
			$a_tunnel[$id] = $tunnel;
		else
			$a_tunnel[] = $tunnel;

		write_config();
		touch($d_wireguardconfdirty_path);

		header("Location: vpn_wireguard.php");
		exit;
	}
}
?>
<?php include("fbegin.inc"); ?>
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
            <form action="vpn_wireguard_edit.php" method="post" name="iform" id="iform">
              <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="content pane">
                <tr>
                  <td width="22%" valign="top" class="vncellreq">Interface</td>
                  <td width="78%" class="vtable">
                    <input name="if" type="text" class="formfld" id="if" size="10" value="<?=htmlspecialchars($pconfig['if'] ?? '');?>">
                    <br><span class="vexpl">The wg(4) interface to create, e.g. <em>wg0</em>.</span></td>
                </tr>
                <tr>
                  <td valign="top" class="vncellreq">Tunnel address</td>
                  <td class="vtable">
                    <input name="address" type="text" class="formfld" id="address" size="20" value="<?=htmlspecialchars($pconfig['address'] ?? '');?>">
                    /
                    <select name="subnet" class="formfld" id="subnet">
                      <?php for ($i = 30; $i >= 8; $i--): ?>
                      <option value="<?=$i;?>" <?php if ($i == ($pconfig['subnet'] ?? null)) echo "selected"; ?>><?=$i;?></option>
                      <?php endfor; ?>
                    </select>
                    <br><span class="vexpl">This firewall's address on the tunnel, and the subnet peers are
                    allocated from. A /24 gives 253 peers.</span></td>
                </tr>
                <tr>
                  <td valign="top" class="vncellreq">Listen port</td>
                  <td class="vtable">
                    <input name="listenport" type="text" class="formfld" id="listenport" size="6" value="<?=htmlspecialchars($pconfig['listenport'] ?? '');?>">
                    <br><span class="vexpl">UDP port to listen on. Remember to allow it in the firewall rules on the
                    interface facing your clients.</span></td>
                </tr>
                <tr>
                  <td valign="top" class="vncell">Endpoint</td>
                  <td class="vtable">
                    <input name="endpoint" type="text" class="formfld" id="endpoint" size="30" value="<?=htmlspecialchars($pconfig['endpoint'] ?? '');?>">
                    <br><span class="vexpl">Optional, <em>host:port</em>. Written into generated client configurations as
                    the address to dial. Leave empty to use the current WAN address, which is what you want unless you
                    are behind another NAT or use a dynamic DNS name.</span></td>
                </tr>
                <tr>
                  <td valign="top" class="vncell">DNS server</td>
                  <td class="vtable">
                    <input name="dns" type="text" class="formfld" id="dns" size="20" value="<?=htmlspecialchars($pconfig['dns'] ?? '');?>">
                    <br><span class="vexpl">Optional. Handed to clients in their configuration. Usually this firewall's
                    tunnel address, so connected clients resolve internal names.</span></td>
                </tr>
                <tr>
                  <td valign="top" class="vncell">MTU</td>
                  <td class="vtable">
                    <input name="mtu" type="text" class="formfld" id="mtu" size="6" value="<?=htmlspecialchars($pconfig['mtu'] ?? '');?>">
                    <br><span class="vexpl">Optional. WireGuard's own default is 1420, which suits a 1500-byte path.
                    Lower it if clients connect over PPPoE or another tunnel.</span></td>
                </tr>
                <tr>
                  <td valign="top" class="vncell">Private key</td>
                  <td class="vtable">
                    <input name="privatekey" type="text" class="formfld" id="privatekey" size="50" value="<?=htmlspecialchars($pconfig['privatekey'] ?? '');?>">
                    <br><span class="vexpl">Leave empty and one will be generated. It is kept across saves &mdash;
                    changing it invalidates every client configuration already issued.
                    <?php if (!empty($pconfig['publickey'])): ?><br>Public key:
                    <strong><?=htmlspecialchars($pconfig['publickey'] ?? '');?></strong><?php endif; ?></span></td>
                </tr>
                <tr>
                  <td valign="top" class="vncell">Description</td>
                  <td class="vtable">
                    <input name="descr" type="text" class="formfld" id="descr" size="40" value="<?=htmlspecialchars($pconfig['descr'] ?? '');?>">
                    <br><span class="vexpl">You may enter a description here for your reference (not parsed).</span></td>
                </tr>
                <tr>
                  <td valign="top" class="vncell">Disabled</td>
                  <td class="vtable">
                    <input name="disabled" type="checkbox" id="disabled" value="yes" <?php if (isset($pconfig['disabled'])) echo "checked"; ?>>
                    <strong>Disable this tunnel</strong></td>
                </tr>
                <tr>
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%">
                    <input name="submit" type="submit" class="formbtn" value="Save">
                    <input type="button" class="formbtn" value="Cancel" onclick="history.back()">
                    <?php if (isset($id) && !empty($a_tunnel[$id])): ?>
                    <input name="id" type="hidden" value="<?=htmlspecialchars($id);?>">
                    <?php endif; ?>
                  </td>
                </tr>
              </table>
</form>
<?php include("fend.inc"); ?>
