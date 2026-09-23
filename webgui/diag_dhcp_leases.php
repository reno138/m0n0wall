#!/usr/local/bin/php
<?php 
/*
	$Id$
	part of m0n0wall (http://m0n0.ch/wall)
	
	Copyright (C) 2003-2005 Björn Pålsson <bjorn@networksab.com> and Manuel Kasper <mk@neon1.net>.
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

$pgtitle = array("Diagnostics", "DHCP leases");

require("guiconfig.inc");

/* Leases come from dnsmasq now (see dhcp_dnsmasq.inc). Its lease file has no
   start time, so that column is gone; everything else is as it was. */

$order = isset($_GET['order']) && in_array($_GET['order'], array("ip", "mac", "hostname", "end"))
         ? $_GET['order'] : "";
$all   = !empty($_GET['all']) ? 1 : 0;

function leasecmp($a, $b) {
	global $order;
	if ($order == "ip")
		return ip2long($a['ip']) <=> ip2long($b['ip']);
	if ($order == "end")
		return $a['end'] <=> $b['end'];
	return strcmp($a[$order], $b[$order]);
}

function lease_end($end) {
	return ($end == 0) ? "never" : date("Y/m/d H:i:s", $end);
}

$leases = dhcp_dnsmasq_leases_read();
?>
<?php include("fbegin.inc"); ?>
<?php if ($leases !== false):

if ($order)
	usort($leases, "leasecmp");
?>
<table width="100%" border="0" cellpadding="0" cellspacing="0" summary="tab pane">
  <tr>
    <td class="listhdrr"><a href="?all=<?=$all;?>&amp;order=ip">IP address</a></td>
    <td class="listhdrr"><a href="?all=<?=$all;?>&amp;order=mac">MAC address</a></td>
    <td class="listhdrr"><a href="?all=<?=$all;?>&amp;order=hostname">Hostname</a></td>
    <td class="listhdr"><a href="?all=<?=$all;?>&amp;order=end">End</a></td>
    <td class="list"></td>
	</tr>
<?php
foreach ($leases as $data) {
	if (($data['act'] == "active") || $all) {
		if ($data['act'] != "active") {
			$fspans = "<span class=\"gray\">";
			$fspane = "</span>";
		} else {
			$fspans = $fspane = "";
		}
		$data['if'] = "";
		$lip = ip2long($data['ip']);
		if (isset($config['dhcpd']) && is_array($config['dhcpd'])) {
			foreach ($config['dhcpd'] as $dhcpif => $dhcpifconf) {
				if (!is_array($dhcpifconf) || empty($dhcpifconf['range']['from']) || empty($dhcpifconf['range']['to']))
					continue;
				if (($lip >= ip2long($dhcpifconf['range']['from'])) && ($lip <= ip2long($dhcpifconf['range']['to']))) {
					$data['if'] = $dhcpif;
					break;
				}
			}
		}
		echo "<tr>\n";
		echo "<td class=\"listlr\">{$fspans}{$data['ip']}{$fspane}&nbsp;</td>\n";
		echo "<td class=\"listr\">{$fspans}{$data['mac']}{$fspane}&nbsp;</td>\n";
		echo "<td class=\"listr\">{$fspans}" .
			htmlentities($data['hostname']) . "{$fspane}&nbsp;</td>\n";
		echo "<td class=\"listr\">{$fspans}" . lease_end($data['end']) . "{$fspane}&nbsp;</td>\n";
		echo "<td class=\"list\" valign=\"middle\"><a href=\"services_dhcp_edit.php?if={$data['if']}&amp;mac={$data['mac']}\"><img src=\"plus.gif\" width=\"17\" height=\"17\" border=\"0\" title=\"add a static mapping for this MAC address\" alt=\"add a static mapping for this MAC address\"></a></td>\n";
		echo "</tr>\n";
	}
}
?>
</table>
<br>
<form action="diag_dhcp_leases.php" method="GET">
<input type="hidden" name="order" value="<?=htmlspecialchars($order);?>">
<?php if ($all): ?>
<input type="hidden" name="all" value="0">
<input type="submit" class="formbtn" value="Show active leases only">
<?php else: ?>
<input type="hidden" name="all" value="1">
<input type="submit" class="formbtn" value="Show active and expired leases">
<?php endif; ?>
</form>
<?php else: ?>
<strong>No leases file found. Is the DHCP server active?</strong>
<?php endif; ?>
<?php include("fend.inc"); ?>
