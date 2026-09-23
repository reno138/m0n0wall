#!/usr/local/bin/php
<?php 
/*
	$Id$
	part of m0n0wall (http://m0n0.ch/wall)
	
	Copyright (C) 2005-2006 Paul Taylor (paultaylor@winndixie.com) and Manuel Kasper <mk@neon1.net>.
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

$pgtitle = array("Diagnostics", "Firewall states");
require("guiconfig.inc");

/*
 * pf states, from pfctl -vss. Same page as the ipfilter version -- IPv4/IPv6
 * tabs, click an address to filter on it, sortable columns, the row limit
 * from System: Advanced, and the packets/bytes snapshot delta -- with one
 * addition, the pf state (ESTABLISHED:ESTABLISHED, NO_TRAFFIC:SINGLE ...).
 *
 * ipfstat printed one tab-separated line per state. pfctl prints a state
 * line followed by one (udp, icmp) or two (tcp) indented detail lines:
 *
 *   all tcp 192.0.2.240:65420 -> 192.0.2.30:8765       FIN_WAIT_2:FIN_WAIT_2
 *      [2496804046 + 65536] wscale 8  [1289104897 + 65792] wscale 10
 *      age 00:00:02, expires in 00:01:28, 6:6 pkts, 394:2525 bytes, rule 12
 *
 * "<-" marks a state created by an inbound packet, and pfctl then prints the
 * local end first, so the endpoints are reversed to keep Source on the left.
 * A state through NAT has three endpoints; the outer two are shown. IPv6
 * ports are printed in brackets: 2001:db8::1[53]. Packets and bytes are the
 * in:out pair summed, as ipfstat's single figures were; TTL is pf's
 * "expires in".
 */

function natsort2d(&$arrIn, $index = null)
{
	$arrTemp = array();
	$arrOut = array();

	if (is_array($arrIn)) {
		foreach ($arrIn as $key => $value) {
			reset($value);
			$arrTemp[$key] = is_null($index) ? current($value) : $value[$index];
		}
	}

	natsort($arrTemp);

	foreach ($arrTemp as $key => $value)
		$arrOut[$key] = $arrIn[$key];

	$arrIn = $arrOut;
}

/* "192.0.2.30:8765" -> (192.0.2.30, 8765); "2001:db8::1[53]" -> (2001:db8::1, 53);
   no port -> (addr, "") */
function pf_split_endpoint($s) {
	if (($p = strrpos($s, '[')) !== false)
		return array(substr($s, 0, $p), rtrim(substr($s, $p + 1), ']'));
	if (substr_count($s, ':') == 1) {
		$p = strpos($s, ':');
		return array(substr($s, 0, $p), substr($s, $p + 1));
	}
	return array($s, "");
}

/* "01:02:03" -> seconds; hours may exceed 24 */
function pf_hms_to_seconds($t) {
	$secs = 0; $mult = 1;
	foreach (array_reverse(explode(':', $t)) as $part) {
		$secs += (int)$part * $mult;
		$mult *= 60;
	}
	return $secs;
}

function pf_seconds_to_hms($s) {
	return sprintf("%d:%02d:%02d", intdiv($s, 3600), intdiv($s % 3600, 60), $s % 60);
}

/* All states of one address family, as rows the rest of the page understands. */
function pf_states_read($want6) {
	exec("/sbin/pfctl -vss 2>/dev/null", $out);

	$states = array();
	$cur = null;		/* row being assembled; false while skipping the other family */

	foreach ($out as $line) {
		if ($line === "")
			continue;
		if ($line[0] != ' ' && $line[0] != "\t") {
			if (is_array($cur))
				$states[] = $cur;
			$cur = false;

			$f = preg_split('/\s+/', trim($line));
			if (count($f) < 5)
				continue;
			$iface = array_shift($f);
			$proto = array_shift($f);
			$state = array_pop($f);

			$eps = array(); $inbound = false;
			foreach ($f as $tok) {
				if ($tok == '->') continue;
				if ($tok == '<-') { $inbound = true; continue; }
				$eps[] = $tok;
			}
			if (count($eps) < 2)
				continue;
			if ($inbound)
				$eps = array_reverse($eps);

			list($sip, $sport) = pf_split_endpoint($eps[0]);
			list($dip, $dport) = pf_split_endpoint($eps[count($eps) - 1]);
			if ((strpos($sip, ':') !== false) != $want6)
				continue;

			$cur = array('srcip' => $sip, 'srcport' => $sport, 'dstip' => $dip, 'dstport' => $dport,
			             'protocol' => $proto, 'state' => $state, 'iface' => $iface,
			             'packets' => 0, 'bytes' => 0, 'ttl' => 0, 'age' => 0);
		} else if (is_array($cur) &&
		           preg_match('/age ([\d:]+), expires in ([\d:]+), (\d+):(\d+) pkts, (\d+):(\d+) bytes/', $line, $m)) {
			$cur['age']     = pf_hms_to_seconds($m[1]);
			$cur['ttl']     = pf_hms_to_seconds($m[2]);
			$cur['packets'] = $m[3] + $m[4];
			$cur['bytes']   = $m[5] + $m[6];
		}
	}
	if (is_array($cur))
		$states[] = $cur;

	return $states;
}

$is6     = (($_GET['ip'] ?? '') == '6');
$ipArg   = $is6 ? '&ip=6' : '';
$order   = $_GET['order'] ?? '';
$sort    = $_GET['sort'] ?? '';
$sfilter = $_GET['sfilter'] ?? '';
$dfilter = $_GET['dfilter'] ?? '';
$viewing = isset($_GET['view']);

/* sfilter and dfilter filter on source and destination address; $filterPassThru
   carries them (and the family) through every link on the page */
$filterPassThru = $ipArg;
if ($sfilter != '' && !is_ipaddr4or6($sfilter)) $sfilter = '';
if ($dfilter != '' && !is_ipaddr4or6($dfilter)) $dfilter = '';
if ($sfilter != '') $filterPassThru .= '&sfilter=' . urlencode($sfilter);
if ($dfilter != '') $filterPassThru .= '&dfilter=' . urlencode($dfilter);

$linelimit = !empty($config['diag']['ipfstatentries']) ? (int)$config['diag']['ipfstatentries'] : 300;

$data = array();
foreach (pf_states_read($is6) as $st) {
	if ($sfilter != '' && $st['srcip'] != $sfilter) continue;
	if ($dfilter != '' && $st['dstip'] != $dfilter) continue;
	$data[] = $st;
	if (count($data) >= $linelimit)
		break;
}

/* --- packets/bytes snapshot: files hold a serialized map keyed by the 5-tuple --- */
function snapshot_file($fname) {
	global $is6;
	return "/tmp/" . $fname . ($is6 ? "6" : "");
}
function writeStats($fname, &$data) {
	@file_put_contents(snapshot_file($fname), serialize($data));
}
function readStats($fname, &$data) {
	$data = array();
	$f = snapshot_file($fname);
	if (file_exists($f))
		$data = unserialize(file_get_contents($f));
	if (!is_array($data))
		$data = array();
}

if (isset($_GET['clear'])) {
	@unlink(snapshot_file("packets"));
	@unlink(snapshot_file("bytes"));
	header("Location: diag_ipfstat.php?" . ltrim($filterPassThru, '&'));
	exit;
}

if (isset($_GET['new'])) {
	$packets = array(); $bytes = array();
	foreach ($data as $row) {
		$packets[$row['srcip']][$row['srcport']][$row['dstip']][$row['dstport']][$row['protocol']] = $row['packets'];
		$bytes[$row['srcip']][$row['srcport']][$row['dstip']][$row['dstport']][$row['protocol']] = $row['bytes'];
	}
	writeStats("packets", $packets);
	writeStats("bytes", $bytes);
	if ($viewing)
		$filterPassThru .= "&view=1";
	header("Location: diag_ipfstat.php?order=bytes&sort=des" . $filterPassThru);
	exit;
}

$viewPassThru = "";
if ($viewing) {
	readStats("packets", $packets);
	readStats("bytes", $bytes);
	foreach ($data as $key => $row) {
		$p = $packets[$row['srcip']][$row['srcport']][$row['dstip']][$row['dstport']][$row['protocol']] ?? null;
		$b = $bytes[$row['srcip']][$row['srcport']][$row['dstip']][$row['dstport']][$row['protocol']] ?? null;
		if ($p !== null && $b !== null && $row['packets'] - $p > -1 && $row['bytes'] - $b > -1) {
			$data[$key]['packets'] = $row['packets'] - $p;
			$data[$key]['bytes']   = $row['bytes'] - $b;
		}
	}
	$filterPassThru .= "&view=1";
	$viewPassThru = "&view=1";
}

if ($order != '' && in_array($order, array('srcip','srcport','dstip','dstport','protocol','state','packets','bytes','ttl'))) {
	natsort2d($data, $order);
	if ($sort == "des")
		$data = array_reverse($data);
}

function sortOrder($column) {
	global $order, $sort;
	if ($order == $column && $sort != 'des')
		return "&amp;sort=des";
	return "&amp;sort=asc";
}

function displayIP($ip, $col) {
	global $viewPassThru, $sfilter, $dfilter, $ipArg;
	$h = htmlspecialchars($ip);
	if ($col == 'srcip') {
		if ($sfilter != '') return $h;
		return '<a href="?' . ltrim($ipArg, '&') . ($ipArg ? '&amp;' : '') . 'sfilter=' . urlencode($ip) . htmlspecialchars($viewPassThru) . '">' . $h . '</a>';
	}
	if ($dfilter != '') return $h;
	return '<a href="?' . ltrim($ipArg, '&') . ($ipArg ? '&amp;' : '') . 'dfilter=' . urlencode($ip) . htmlspecialchars($viewPassThru) . '">' . $h . '</a>';
}

$snap = snapshot_file("packets");
$lastSnapshot = file_exists($snap) ? date("m/d/y H:i:s", filectime($snap)) : "Never";

include("fbegin.inc");
$filterPassThru = str_replace("&", "&amp;", $filterPassThru);
if (ipv6enabled()):
?>
	<table width="100%" border="0" cellpadding="0" cellspacing="0" summary="tab pane">
	  <tr><td class="tabnavtbl">
	  <ul id="tabnav">
<?php if ($is6): ?>
	    <li class="tabinact1"><a href="diag_ipfstat.php">IPv4</a></li>
	    <li class="tabact">IPv6</li>
<?php else: ?>
	    <li class="tabact">IPv4</li>
	    <li class="tabinact1"><a href="diag_ipfstat.php?ip=6">IPv6</a></li>
<?php endif; ?>
	  </ul>
	  </td></tr>
	  <tr>
	    <td class="tabcont">
<?php endif; ?>
<table width="100%" border="0" cellpadding="0" cellspacing="0">
  <tr>
  	<td class="listhdrr" colspan="9">Statistics snapshot control</td>
  </tr>
  <tr>
    <?php if ($lastSnapshot != 'Never' && !$viewing): ?>
    <td class="listlr"><a href="?view=1&amp;order=bytes&amp;sort=des<?=$filterPassThru;?>">View delta</a></td>
    <td class="listr"><a href="?new=1<?=$filterPassThru;?>">Start new</a></td>
    <td class="listr"><a href="?clear=1<?=$filterPassThru;?>">Clear snapshot</a></td>
    <td class="listr" colspan="6" align="right">Last statistics snapshot: <?=$lastSnapshot;?></td>
    <?php elseif ($lastSnapshot != 'Never'): ?>
    <td class="listlr"><a href="?new=1<?=$filterPassThru;?>">Start new</a></td>
    <td class="listr"><a href="?clear=1<?=$filterPassThru;?>">Clear</a></td>
    <td class="listr" colspan="7" align="right"><span class="red">Viewing delta of statistics snapshot: <?=$lastSnapshot;?></span></td>
    <?php else: ?>
    <td class="listlr"><a href="?new=1<?=$filterPassThru;?>">Start new</a></td>
    <td class="listr" colspan="8" align="right">Last statistics snapshot: <?=$lastSnapshot;?></td>
    <?php endif; ?>
  </tr>
  <tr>
  	<td colspan="9">&nbsp;</td>
  </tr>
  <tr>
    <td class="listhdrr"><a href="?order=srcip<?=sortOrder('srcip') . $filterPassThru;?>">Source</a></td>
    <td class="listhdrr" align="right"><a href="?order=srcport<?=sortOrder('srcport') . $filterPassThru;?>">Port</a></td>
    <td class="listhdrr"><a href="?order=dstip<?=sortOrder('dstip') . $filterPassThru;?>">Destination</a></td>
    <td class="listhdrr" align="right"><a href="?order=dstport<?=sortOrder('dstport') . $filterPassThru;?>">Port</a></td>
    <td class="listhdrr"><a href="?order=protocol<?=sortOrder('protocol') . $filterPassThru;?>">Protocol</a></td>
    <td class="listhdrr"><a href="?order=state<?=sortOrder('state') . $filterPassThru;?>">State</a></td>
    <td class="listhdrr" align="right"><a href="?order=packets<?=sortOrder('packets') . $filterPassThru;?>">Packets</a></td>
    <td class="listhdrr" align="right"><a href="?order=bytes<?=sortOrder('bytes') . $filterPassThru;?>">Bytes</a></td>
    <td class="listhdr" align="right"><a href="?order=ttl<?=sortOrder('ttl') . $filterPassThru;?>">TTL</a></td>
  </tr>
<?php foreach ($data as $entry): ?>
  <tr>
    <td class="listlr"><?=displayIP($entry['srcip'], 'srcip');?></td>
    <td class="listr" align="right"><?=htmlspecialchars($entry['srcport']);?>&nbsp;</td>
    <td class="listr"><?=displayIP($entry['dstip'], 'dstip');?></td>
    <td class="listr" align="right"><?=htmlspecialchars($entry['dstport']);?>&nbsp;</td>
    <td class="listr"><?=htmlspecialchars($entry['protocol']);?></td>
    <td class="listr"><?=htmlspecialchars($entry['state']);?></td>
    <td class="listr" align="right"><?=$entry['packets'];?></td>
    <td class="listr" align="right"><?=$entry['bytes'];?></td>
    <td class="listr" align="right"><?=pf_seconds_to_hms($entry['ttl']);?></td>
  </tr>
<?php endforeach; ?>
</table>
<br><strong>Firewall connection states displayed: <?=count($data);?></strong>
<?php if ($sfilter != '' || $dfilter != ''): ?>
<p>
<form action="diag_ipfstat.php" method="GET">
<input type="hidden" name="order" value="bytes">
<input type="hidden" name="sort" value="des">
<?php if ($is6): ?><input type="hidden" name="ip" value="6"><?php endif; ?>
<?php if ($viewing): ?><input type="hidden" name="view" value="1"><?php endif; ?>
<input type="submit" class="formbtn" value="Remove address filter">
</form>
<?php endif; ?>
<?php if (ipv6enabled()): ?>
	    </td>
	  </tr>
	</table>
<?php endif; ?>
<?php include("fend.inc"); ?>
