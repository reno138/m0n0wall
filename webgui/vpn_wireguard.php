<?php
/*
	vpn_wireguard.php
	part of m0n0wall (http://m0n0.ch/wall)

	Copyright (C) 2026 m0n0wall contributors.
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the conditions of the two-clause
	BSD licence carried by the rest of m0n0wall are met.
*/

$pgtitle = array("VPN", "WireGuard", "Tunnels");
require("guiconfig.inc");

if (!is_array($config['wireguard']['tunnel'] ?? null)) {
	$config['wireguard']['tunnel'] = array();
}
$a_tunnel = &$config['wireguard']['tunnel'];

$pconfig['enable'] = isset($config['wireguard']['enable']);

if ($_POST) {

	if (!empty($_POST['apply'])) {
		$retval = 0;
		if (!file_exists($d_sysrebootreqd_path))
			$retval = wg_configure();
		$savemsg = get_std_save_message($retval);
		if ($retval == 0) {
			if (file_exists($d_wireguardconfdirty_path))
				unlink($d_wireguardconfdirty_path);
		}
	} else if (!empty($_POST['submit'])) {
		$pconfig = $_POST;
		$config['wireguard']['enable'] = !empty($_POST['enable']) ? true : false;
		write_config();
		touch($d_wireguardconfdirty_path);
	} else {
		/* delete */
		foreach ($_POST as $pn => $pv) {
			if (preg_match("/del_(\d+)_x/", $pn, $matches)) {
				$id = $matches[1];
				if (!empty($a_tunnel[$id])) {
					unset($a_tunnel[$id]);
					write_config();
					touch($d_wireguardconfdirty_path);
					header("Location: vpn_wireguard.php");
					exit;
				}
			}
		}
	}
}
?>
<?php include("fbegin.inc"); ?>
<form action="vpn_wireguard.php" method="post">
<?php if (!empty($savemsg)) print_info_box($savemsg); ?>
<?php if (file_exists($d_wireguardconfdirty_path)): ?><p>
<?php print_info_box_np("The WireGuard configuration has been changed.<br>You must apply the changes in order for them to take effect.");?><br>
<input name="apply" type="submit" class="formbtn" id="apply" value="Apply changes"></p>
<?php endif; ?>
<table width="100%" border="0" cellpadding="0" cellspacing="0" summary="tab pane">
  <tr><td class="tabnavtbl">
  <ul id="tabnav">
<?php
	$tabs = array('Tunnels' => 'vpn_wireguard.php');
	$i = 0;
	foreach ($a_tunnel as $t) {
		$label = !empty($t['descr']) ? $t['descr'] : ($t['if'] ?? '');
		$tabs["Peers: " . htmlspecialchars($label)] = "vpn_wireguard_peers.php?tunnel=" . $i;
		$i++;
	}
	dynamic_tab_menu($tabs);
?>
  </ul>
  </td></tr>
  <tr>
    <td class="tabcont">
		        <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="checkbox pane">
                <tr>
                  <td class="vtable">
                      <input name="enable" type="checkbox" id="enable" value="yes" <?php if (!empty($pconfig['enable'])) echo "checked";?>>
                      <strong>Enable WireGuard</strong></td>
                </tr>
                <tr>
                  <td> <input name="submit" type="submit" class="formbtn" value="Save">
                  </td>
                </tr>
              </table>
              &nbsp;<br>
              <table width="100%" border="0" cellpadding="0" cellspacing="0" summary="content pane">
                <tr>
                  <td nowrap class="listhdrr">Interface</td>
                  <td class="listhdrr">Tunnel address</td>
                  <td class="listhdrr">Listen port</td>
                  <td class="listhdrr">Peers</td>
                  <td class="listhdrr">Free addresses</td>
                  <td class="listhdr">Description</td>
                  <td class="list"></td>
				</tr>
                <?php $i = 0; foreach ($a_tunnel as $tunnel):
					if (isset($tunnel['disabled'])) {
						$spans = "<span class=\"gray\">";
						$spane = "</span>";
					} else {
						$spans = $spane = "";
					}
					$npeers = is_array($tunnel['peer'] ?? null) ? count($tunnel['peer']) : 0;
				?>
                <tr valign="top">
                  <td nowrap class="listlr"><?=$spans;?><?=htmlspecialchars($tunnel['if'] ?? '');?><?=$spane;?></td>
                  <td class="listr"><?=$spans;?><?=htmlspecialchars($tunnel['address'] ?? '');?>/<?=htmlspecialchars($tunnel['subnet'] ?? '');?><?=$spane;?></td>
                  <td class="listr"><?=$spans;?><?=htmlspecialchars($tunnel['listenport'] ?? '');?><?=$spane;?></td>
                  <td class="listr"><?=$spans;?><a href="vpn_wireguard_peers.php?tunnel=<?=$i;?>"><?=$npeers;?></a><?=$spane;?></td>
                  <td class="listr"><?=$spans;?><?=wg_pool_free_count($tunnel);?><?=$spane;?></td>
                  <td class="listbg"><?=$spans;?><?=htmlspecialchars($tunnel['descr'] ?? '');?>&nbsp;<?=$spane;?></td>
                  <td valign="middle" nowrap class="list"> <a href="vpn_wireguard_edit.php?id=<?=$i;?>"><img src="e.gif" title="edit tunnel" width="17" height="17" border="0" alt="edit tunnel"></a>
                    &nbsp;<input name="del_<?=$i;?>" type="image" src="x.gif" width="17" height="17" title="delete tunnel" alt="delete tunnel" onclick="return confirm('Do you really want to delete this tunnel?')"></td>
				</tr>
			  <?php $i++; endforeach; ?>
                <tr>
                  <td class="list" colspan="6"></td>
                  <td class="list"> <a href="vpn_wireguard_edit.php"><img src="plus.gif" title="add tunnel" width="17" height="17" border="0" alt="add tunnel"></a></td>
				</tr>
              </table>
              <p class="vexpl"><span class="red"><strong>Note:</strong></span>
              WireGuard has no DHCP &mdash; it is a layer&nbsp;3 tunnel with no broadcast
              domain. Peers are instead allocated an address from this tunnel's subnet when
              they are added, and that address is written into the client configuration.</p>
			</td>
	</tr>
</table>
</form>
<?php include("fend.inc"); ?>
