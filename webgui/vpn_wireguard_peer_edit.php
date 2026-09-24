<?php
/*
	vpn_wireguard_peer_edit.php
	part of m0n0wall (http://m0n0.ch/wall)

	Copyright (C) 2026 m0n0wall contributors.
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the conditions of the two-clause
	BSD licence carried by the rest of m0n0wall are met.
*/

$pgtitle = array("VPN", "WireGuard", "Edit peer");
require("guiconfig.inc");

if (!is_array($config['wireguard']['tunnel'] ?? null)) {
	$config['wireguard']['tunnel'] = array();
}
$a_tunnel = &$config['wireguard']['tunnel'];

$tunidx = isset($_POST['tunnel']) ? $_POST['tunnel'] : ($_GET['tunnel'] ?? null);
if (!is_numeric($tunidx) || !isset($a_tunnel[$tunidx])) {
	header("Location: vpn_wireguard.php");
	exit;
}
if (!is_array($a_tunnel[$tunidx]['peer'] ?? null)) {
	$a_tunnel[$tunidx]['peer'] = array();
}
$a_peer = &$a_tunnel[$tunidx]['peer'];
$tunnel = &$a_tunnel[$tunidx];

$id = $_GET['id'] ?? null;
if (isset($_POST['id']))
	$id = $_POST['id'];

if (isset($id) && !empty($a_peer[$id])) {
	$pconfig = $a_peer[$id];
	$pconfig['keysource'] = !empty($a_peer[$id]['privatekey']) ? 'generated' : 'client';
} else {
	/* New peer: offer the next free address so the common case is one click. */
	$pconfig['address']   = wg_allocate_address($tunnel);
	$pconfig['keysource'] = 'client';
	$pconfig['addrmode']  = 'auto';
}

if ($_POST) {

	unset($input_errors);
	$pconfig = $_POST;

	$reqdfields = explode(" ", "name");
	$reqdfieldsn = explode(",", "Name");
	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

	if ($_POST['name'] && !wg_is_valid_peername($_POST['name']))
		$input_errors[] = "The name may contain only letters, digits, dots, dashes and underscores, and must start with a letter or digit.";

	/* Address: allocated from the pool, or pinned by hand. */
	if ($_POST['addrmode'] == 'static') {
		if (!$_POST['address'] || !is_ipaddr($_POST['address'])) {
			$input_errors[] = "A valid tunnel address must be specified.";
		} else {
			$net = gen_subnet($tunnel['address'], $tunnel['subnet']);
			if (!ip_in_subnet($_POST['address'], "$net/{$tunnel['subnet']}"))
				$input_errors[] = "The tunnel address must lie within {$net}/{$tunnel['subnet']}.";
			/* reject a duplicate, but not the peer's own current address */
			foreach ($a_peer as $pi => $p) {
				if ((!isset($id) || $pi != $id) && $p['address'] == $_POST['address']) {
					$input_errors[] = "That address is already assigned to peer '{$p['name']}'.";
					break;
				}
			}
			if ($_POST['address'] == $tunnel['address'])
				$input_errors[] = "That address belongs to the firewall's own end of the tunnel.";
		}
	} else {
		$auto = isset($id) && !empty($a_peer[$id]) ? $a_peer[$id]['address'] : wg_allocate_address($tunnel);
		if (!$auto)
			$input_errors[] = "There are no free addresses left in {$tunnel['address']}/{$tunnel['subnet']}. Widen the tunnel subnet or remove a peer.";
		$_POST['address'] = $auto;
	}

	/* Keys */
	if ($_POST['keysource'] == 'client') {
		if (!$_POST['publickey'])
			$input_errors[] = "A public key is required. Generate a key pair on the client and paste its public key here.";
		else if (!wg_is_valid_key($_POST['publickey']))
			$input_errors[] = "That does not look like a WireGuard public key (44 base64 characters ending in '=').";
	}

	if ($_POST['presharedkey'] && !wg_is_valid_key($_POST['presharedkey']))
		$input_errors[] = "That does not look like a WireGuard pre-shared key.";

	if ($_POST['endpoint'] && !wg_is_valid_endpoint($_POST['endpoint']))
		$input_errors[] = "The endpoint must be host:port or address:port.";

	if ($_POST['keepalive'] && (!is_numericint($_POST['keepalive']) || $_POST['keepalive'] < 1 || $_POST['keepalive'] > 65535))
		$input_errors[] = "Persistent keepalive must be a number of seconds between 1 and 65535.";

	foreach (preg_split('/[\s,]+/', trim($_POST['routes'])) as $r) {
		if ($r !== '' && !is_subnet($r))
			$input_errors[] = "'" . htmlspecialchars($r) . "' is not a valid network in CIDR notation.";
	}

	if (!$input_errors) {
		$peer = array();
		$peer['name']         = $_POST['name'];
		$peer['address']      = $_POST['address'];
		$peer['addrmode']     = $_POST['addrmode'];
		$peer['presharedkey'] = $_POST['presharedkey'];
		$peer['endpoint']     = $_POST['endpoint'];
		$peer['keepalive']    = $_POST['keepalive'];
		$peer['routes']       = $_POST['routes'];
		$peer['clientallowed']= $_POST['clientallowed'];
		$peer['descr']        = $_POST['descr'];
		if (!empty($_POST['disabled']))
			$peer['disabled'] = true;

		if ($_POST['keysource'] == 'generated') {
			/* Keep an existing generated pair rather than rotating it on every
			   save -- rotating would silently invalidate the client. */
			if (isset($id) && !empty($a_peer[$id]) && !empty($a_peer[$id]['privatekey'])) {
				$peer['privatekey'] = $a_peer[$id]['privatekey'];
				$peer['publickey']  = $a_peer[$id]['publickey'];
			} else {
				$priv = trim(shell_exec(WG_BIN . " genkey"));
				$pub  = trim(shell_exec("echo " . escapeshellarg($priv) . " | " . WG_BIN . " pubkey"));
				$peer['privatekey'] = $priv;
				$peer['publickey']  = $pub;
			}
		} else {
			$peer['publickey'] = $_POST['publickey'];
		}

		if (isset($id) && !empty($a_peer[$id]))
			$a_peer[$id] = $peer;
		else
			$a_peer[] = $peer;

		write_config();
		touch($d_wireguardconfdirty_path);

		header("Location: vpn_wireguard_peers.php?tunnel=" . $tunidx);
		exit;
	}
}
?>
<?php include("fbegin.inc"); ?>
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
            <form action="vpn_wireguard_peer_edit.php" method="post" name="iform" id="iform">
              <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="content pane">
              <tr>
                  <td width="22%" valign="top" class="vncellreq">Name</td>
                  <td width="78%" class="vtable">
                    <input name="name" type="text" class="formfld" id="name" size="30" value="<?=htmlspecialchars($pconfig['name'] ?? '');?>">
                    <br><span class="vexpl">A short name for this device, e.g. <em>my-laptop</em>. It is used for the downloaded file name.</span></td>
                </tr>
                <tr>
                  <td valign="top" class="vncellreq">Tunnel address</td>
                  <td class="vtable">
                    <input name="addrmode" type="radio" id="addrauto" value="auto" <?php if (($pconfig['addrmode'] ?? null) != 'static') echo "checked"; ?>>
                    Allocate the next free address
                    <span class="vexpl">(<?=htmlspecialchars(wg_allocate_address($tunnel));?> &mdash; <?=wg_pool_free_count($tunnel);?> free)</span><br>
                    <input name="addrmode" type="radio" id="addrstatic" value="static" <?php if (($pconfig['addrmode'] ?? null) == 'static') echo "checked"; ?>>
                    Use this address:
                    <input name="address" type="text" class="formfld" id="address" size="20" value="<?=htmlspecialchars($pconfig['address'] ?? '');?>">
                    <br><span class="vexpl">WireGuard has no DHCP &mdash; there is no broadcast domain on a tunnel
                    interface for it to run over. m0n0wall allocates an address instead and writes it into the
                    client configuration, which has the same effect.</span></td>
                </tr>
                <tr>
                  <td valign="top" class="vncellreq">Keys</td>
                  <td class="vtable">
                    <input name="keysource" type="radio" id="keyclient" value="client" <?php if (($pconfig['keysource'] ?? null) != 'generated') echo "checked"; ?>>
                    The client generated its own key pair &mdash; public key:<br>
                    <input name="publickey" type="text" class="formfld" id="publickey" size="50" value="<?=htmlspecialchars($pconfig['publickey'] ?? '');?>"><br>
                    <input name="keysource" type="radio" id="keygen" value="generated" <?php if (($pconfig['keysource'] ?? null) == 'generated') echo "checked"; ?>>
                    Generate a key pair here
                    <br><span class="vexpl"><span class="red"><strong>Prefer the first option.</strong></span>
                    Generating the pair on the firewall means the private key existed here and has to be carried to
                    the device. Having the client make its own key and pasting the public half in avoids that. An
                    existing generated pair is kept on save rather than rotated, so saving will not lock out a
                    configured client.</span></td>
                </tr>
                <tr>
                  <td valign="top" class="vncell">Pre-shared key</td>
                  <td class="vtable">
                    <input name="presharedkey" type="text" class="formfld" id="presharedkey" size="50" value="<?=htmlspecialchars($pconfig['presharedkey'] ?? '');?>">
                    <br><span class="vexpl">Optional. Adds a symmetric layer on top of the public-key handshake, which guards
                    against a future quantum attacker recording traffic today.</span></td>
                </tr>
                <tr>
                  <td valign="top" class="vncell">Networks behind this peer</td>
                  <td class="vtable">
                    <input name="routes" type="text" class="formfld" id="routes" size="40" value="<?=htmlspecialchars($pconfig['routes'] ?? '');?>">
                    <br><span class="vexpl">For site-to-site links: the networks reachable through this peer, in CIDR
                    notation, separated by spaces. Leave empty for a single client.</span></td>
                </tr>
                <tr>
                  <td valign="top" class="vncell">Client routes</td>
                  <td class="vtable">
                    <input name="clientallowed" type="text" class="formfld" id="clientallowed" size="40" value="<?=htmlspecialchars($pconfig['clientallowed'] ?? '');?>">
                    <br><span class="vexpl">What the client sends down the tunnel. Empty means the tunnel subnet only
                    (split tunnel). Use <em>0.0.0.0/0</em> to route all of the client's traffic through the firewall.</span></td>
                </tr>
                <tr>
                  <td valign="top" class="vncell">Endpoint</td>
                  <td class="vtable">
                    <input name="endpoint" type="text" class="formfld" id="endpoint" size="30" value="<?=htmlspecialchars($pconfig['endpoint'] ?? '');?>">
                    <br><span class="vexpl">Optional, <em>host:port</em>. Only needed when this firewall must initiate the
                    connection, as in a site-to-site link. Leave empty for roaming clients.</span></td>
                </tr>
                <tr>
                  <td valign="top" class="vncell">Persistent keepalive</td>
                  <td class="vtable">
                    <input name="keepalive" type="text" class="formfld" id="keepalive" size="6" value="<?=htmlspecialchars($pconfig['keepalive'] ?? '');?>">
                    seconds
                    <br><span class="vexpl">Set to 25 for a peer behind NAT that must stay reachable. Leave empty otherwise.</span></td>
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
                    <strong>Disable this peer</strong></td>
                </tr>
                <tr>
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%">
                    <input name="submit" type="submit" class="formbtn" value="Save">
                    <input type="button" class="formbtn" value="Cancel" onclick="history.back()">
                    <input name="tunnel" type="hidden" value="<?=htmlspecialchars($tunidx);?>">
                    <?php if (isset($id) && !empty($a_peer[$id])): ?>
                    <input name="id" type="hidden" value="<?=htmlspecialchars($id);?>">
                    <?php endif; ?>
                  </td>
                </tr>
              </table>
</form>
<?php include("fend.inc"); ?>
