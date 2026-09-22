<?php
/*
	vpn_wireguard_peers.php
	part of m0n0wall (http://m0n0.ch/wall)

	Copyright (C) 2026 m0n0wall contributors.
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the conditions of the two-clause
	BSD licence carried by the rest of m0n0wall are met.
*/

$pgtitle = array("VPN", "WireGuard", "Peers");
require("guiconfig.inc");

if (!is_array($config['wireguard']['tunnel'])) {
	$config['wireguard']['tunnel'] = array();
}
$a_tunnel = &$config['wireguard']['tunnel'];

$tunidx = isset($_GET['tunnel']) ? $_GET['tunnel'] : $_POST['tunnel'];
if (!is_numeric($tunidx) || !isset($a_tunnel[$tunidx])) {
	header("Location: vpn_wireguard.php");
	exit;
}

if (!is_array($a_tunnel[$tunidx]['peer'])) {
	$a_tunnel[$tunidx]['peer'] = array();
}
$a_peer = &$a_tunnel[$tunidx]['peer'];
$tunnel = $a_tunnel[$tunidx];

if ($_POST) {
	foreach ($_POST as $pn => $pv) {
		if (preg_match("/del_(\d+)_x/", $pn, $matches)) {
			$id = $matches[1];
			if ($a_peer[$id]) {
				unset($a_peer[$id]);
				write_config();
				touch($d_wireguardconfdirty_path);
				header("Location: vpn_wireguard_peers.php?tunnel=" . $tunidx);
				exit;
			}
		}
	}
}

/* live handshake/counter data, if the tunnel is up */
$wgstatus = wg_get_peer_status($tunnel['if']);
?>
<?php include("fbegin.inc"); ?>
<form action="vpn_wireguard_peers.php" method="post">
<input type="hidden" name="tunnel" value="<?=htmlspecialchars($tunidx);?>">
<?php if ($savemsg) print_info_box($savemsg); ?>
<?php if (file_exists($d_wireguardconfdirty_path)): ?><p>
<?php print_info_box_np("The WireGuard configuration has been changed.<br>You must apply the changes in order for them to take effect.");?></p>
<?php endif; ?>
<table width="100%" border="0" cellpadding="0" cellspacing="0" summary="tab pane">
  <tr><td class="tabnavtbl">
  <ul id="tabnav">
<?php
	$tabs = array('Tunnels' => 'vpn_wireguard.php');
	$i = 0;
	foreach ($a_tunnel as $t) {
		$label = $t['descr'] ? $t['descr'] : $t['if'];
		$tabs["Peers: " . htmlspecialchars($label)] = "vpn_wireguard_peers.php?tunnel=" . $i;
		$i++;
	}
	dynamic_tab_menu($tabs);
?>
  </ul>
  </td></tr>
  <tr>
    <td class="tabcont">
              <table width="100%" border="0" cellpadding="0" cellspacing="0" summary="content pane">
                <tr>
                  <td nowrap class="listhdrr">Name</td>
                  <td class="listhdrr">Tunnel address</td>
                  <td class="listhdrr">Public key</td>
                  <td class="listhdrr">Last handshake</td>
                  <td class="listhdrr">Transfer</td>
                  <td class="listhdr">Description</td>
                  <td class="list"></td>
				</tr>
                <?php $i = 0; foreach ($a_peer as $peer):
					if (isset($peer['disabled'])) {
						$spans = "<span class=\"gray\">";
						$spane = "</span>";
					} else {
						$spans = $spane = "";
					}
					$st = $wgstatus[$peer['publickey']];
				?>
                <tr valign="top">
                  <td nowrap class="listlr"><?=$spans;?><?=htmlspecialchars($peer['name']);?><?=$spane;?></td>
                  <td class="listr"><?=$spans;?><?=htmlspecialchars($peer['address']);?><?=$spane;?></td>
                  <td class="listr"><?=$spans;?><span class="vexpl"><?=htmlspecialchars(substr($peer['publickey'], 0, 16));?>&hellip;</span><?=$spane;?></td>
                  <td class="listr"><?=$spans;?>
                    <?php if ($st && $st['latesthandshake'] > 0) {
                            echo htmlspecialchars(format_duration(time() - $st['latesthandshake'])) . " ago";
                          } else {
                            echo "never";
                          } ?>
                  <?=$spane;?></td>
                  <td class="listr"><?=$spans;?>
                    <?php if ($st) {
                            echo format_bytes($st['rx']) . " in / " . format_bytes($st['tx']) . " out";
                          } else {
                            echo "&mdash;";
                          } ?>
                  <?=$spane;?></td>
                  <td class="listbg"><?=$spans;?><?=htmlspecialchars($peer['descr']);?>&nbsp;<?=$spane;?></td>
                  <td valign="middle" nowrap class="list">
                    <a href="vpn_wireguard_export.php?tunnel=<?=$tunidx;?>&amp;id=<?=$i;?>&amp;fmt=conf" title="download configuration"><img src="down.gif" width="17" height="17" border="0" alt="download configuration"></a>
                    &nbsp;<a href="vpn_wireguard_export.php?tunnel=<?=$tunidx;?>&amp;id=<?=$i;?>&amp;fmt=qrpage" title="show QR code"><img src="log.gif" width="17" height="17" border="0" alt="show QR code"></a>
                    &nbsp;<a href="vpn_wireguard_peer_edit.php?tunnel=<?=$tunidx;?>&amp;id=<?=$i;?>"><img src="e.gif" title="edit peer" width="17" height="17" border="0" alt="edit peer"></a>
                    &nbsp;<input name="del_<?=$i;?>" type="image" src="x.gif" width="17" height="17" title="delete peer" alt="delete peer" onclick="return confirm('Do you really want to delete this peer?')"></td>
				</tr>
			  <?php $i++; endforeach; ?>
                <tr>
                  <td class="list" colspan="6"></td>
                  <td class="list"> <a href="vpn_wireguard_peer_edit.php?tunnel=<?=$tunidx;?>"><img src="plus.gif" title="add peer" width="17" height="17" border="0" alt="add peer"></a></td>
				</tr>
              </table>
              <p class="vexpl"><span class="vexpl"><strong>Tunnel <?=htmlspecialchars($tunnel['if']);?></strong>
              &nbsp;<?=htmlspecialchars($tunnel['address']);?>/<?=htmlspecialchars($tunnel['subnet']);?>,
              <?=wg_pool_free_count($tunnel);?> addresses free.</span></p>
			</td>
	</tr>
</table>
</form>
<?php include("fend.inc"); ?>
