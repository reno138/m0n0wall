<?php
/*
	vpn_wireguard_export.php
	part of m0n0wall (http://m0n0.ch/wall)

	Serves a peer's client configuration as a downloadable file, as a QR code
	image, or as a page showing both.

	Copyright (C) 2026 m0n0wall contributors.
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the conditions of the two-clause
	BSD licence carried by the rest of m0n0wall are met.
*/

/* The QR and file responses are raw output, so suppress the no-cache header
   block guiconfig.inc would otherwise emit before we set our own. */
$omit_nocacheheaders = true;
$pgtitle = array("VPN", "WireGuard", "Client configuration");
require("guiconfig.inc");

/* ?? '': opened without its parameters (a bookmark, a crawler), the checks
   below redirect -- they just have to be reached without warning first */
$tunidx = $_GET['tunnel'] ?? '';
$id     = $_GET['id'] ?? '';
$fmt    = !empty($_GET['fmt']) ? $_GET['fmt'] : 'qrpage';

if (!is_numeric($tunidx) || !is_array($config['wireguard']['tunnel'][$tunidx] ?? null)) {
	header("Location: vpn_wireguard.php");
	exit;
}
$tunnel = $config['wireguard']['tunnel'][$tunidx];

if (!is_numeric($id) || !is_array($tunnel['peer'][$id] ?? null)) {
	header("Location: vpn_wireguard_peers.php?tunnel=" . $tunidx);
	exit;
}
$peer = $tunnel['peer'][$id];

/* Where clients should dial in. Prefer the explicit override, else the
   current WAN address and this tunnel's listen port. */
if ($tunnel['endpoint']) {
	$server_endpoint = $tunnel['endpoint'];
} else {
	$wanip = get_current_wan_address(false);
	$port  = $tunnel['listenport'] ? $tunnel['listenport'] : 51820;
	$server_endpoint = $wanip ? "$wanip:$port" : "";
}

/* A private key is only present when m0n0wall generated the pair. When the
   client supplied its own public key the firewall never held the private half
   -- which is the preferred flow -- and the config says so instead. */
$privkey = $peer['privatekey'] ? $peer['privatekey'] : '';

$conftext = wg_peer_config_generate($tunnel, $peer, $privkey, $server_endpoint);
$filename = wg_config_filename($tunnel, $peer);

switch ($fmt) {

case 'conf':
	/* The file can contain a private key, so forbid caching explicitly. */
	header("Content-Type: application/octet-stream");
	header("Content-Disposition: attachment; filename=\"" . $filename . "\"");
	header("Content-Length: " . strlen($conftext));
	header("Cache-Control: no-store, no-cache, must-revalidate, private");
	header("Pragma: no-cache");
	header("Expires: 0");
	echo $conftext;
	exit;

case 'qr':
	$png = wg_config_qrcode($conftext, 'PNG');
	if ($png === null) {
		header("HTTP/1.0 503 Service Unavailable");
		header("Content-Type: text/plain");
		echo "qrencode is not installed on this firewall.";
		exit;
	}
	header("Content-Type: image/png");
	header("Content-Length: " . strlen($png));
	header("Cache-Control: no-store, no-cache, must-revalidate, private");
	header("Pragma: no-cache");
	header("Expires: 0");
	echo $png;
	exit;
}

/* default: the page showing both */
?>
<?php include("fbegin.inc"); ?>
<table width="100%" border="0" cellpadding="0" cellspacing="0" summary="tab pane">
  <tr>
    <td class="tabcont">
      <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="content pane">
        <tr>
          <td width="22%" valign="top" class="vncell">Peer</td>
          <td width="78%" class="vtable"><strong><?=htmlspecialchars($peer['name']);?></strong>
            &nbsp;<?=htmlspecialchars($peer['address']);?>
            on <?=htmlspecialchars($tunnel['if']);?></td>
        </tr>
        <tr>
          <td valign="top" class="vncell">QR code</td>
          <td class="vtable">
            <?php if (wg_qrencode_available()): ?>
            <img src="vpn_wireguard_export.php?tunnel=<?=htmlspecialchars($tunidx);?>&amp;id=<?=htmlspecialchars($id);?>&amp;fmt=qr" alt="WireGuard configuration QR code"><br>
            <span class="vexpl">Scan this with the WireGuard app on a phone or tablet.</span>
            <?php else: ?>
            <span class="red"><strong>qrencode is not installed</strong></span><br>
            <span class="vexpl">The configuration file below can still be downloaded and imported by hand.</span>
            <?php endif; ?>
          </td>
        </tr>
        <tr>
          <td valign="top" class="vncell">Configuration</td>
          <td class="vtable">
            <textarea rows="14" cols="72" name="conf" id="conf" wrap="off" readonly><?=htmlspecialchars($conftext);?></textarea><br>
            <a href="vpn_wireguard_export.php?tunnel=<?=htmlspecialchars($tunidx);?>&amp;id=<?=htmlspecialchars($id);?>&amp;fmt=conf" class="formbtn">Download <?=htmlspecialchars($filename);?></a>
          </td>
        </tr>
        <tr>
          <td valign="top">&nbsp;</td>
          <td>
            <?php if ($privkey == ''): ?>
            <p class="vexpl"><span class="red"><strong>Note:</strong></span>
            this peer's public key was supplied by the client, so the firewall does not
            hold its private key. Replace the placeholder in the
            <em>[Interface]</em> section with the private key from that device. This is
            the safer arrangement and is worth keeping.</p>
            <?php else: ?>
            <p class="vexpl"><span class="red"><strong>Warning:</strong></span>
            this configuration contains the peer's <strong>private key</strong>, because
            the key pair was generated here rather than on the client. Transfer it over a
            channel you trust and do not leave copies behind. Having the client generate
            its own key and pasting only the public half into m0n0wall avoids this
            entirely.</p>
            <?php endif; ?>
            <p class="vexpl"><?php if ($server_endpoint == ''): ?>
            <span class="red"><strong>The endpoint is empty</strong></span> because the WAN
            address could not be determined. Set an explicit endpoint on the tunnel, or the
            client will have nowhere to connect.
            <?php else: ?>
            Clients will connect to <strong><?=htmlspecialchars($server_endpoint);?></strong>.
            <?php endif; ?></p>
            <p><a href="vpn_wireguard_peers.php?tunnel=<?=htmlspecialchars($tunidx);?>" class="formbtn">Back to peers</a></p>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
<?php include("fend.inc"); ?>
