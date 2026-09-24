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

$pgtitle = array("Diagnostics", "Logs");
require("guiconfig.inc");

$protocols = explode(" ", "TCP UDP TCP/UDP ICMP ESP AH GRE IPv6 IGMP any");

$actstring = $ifstring = $srcstring = $dststring = $prstring = "";

$nentries = $config['syslog']['nentries'] ?? null;
$resolve = isset($config['syslog']['resolve']);

if (!$nentries)
	$nentries = 50;

if (!empty($_POST['clear'])) {
	/* Truncate the pcap pflogd is writing and signal it to reopen, rather
	   than the text filter.log ipmon used to produce, which nothing writes
	   any more. */
	@file_put_contents("{$g['varlog_path']}/pflog.cap", "");
	$pid = @file_get_contents("{$g['varrun_path']}/pflogd.pid");
	if ($pid)
		mwexec("/bin/kill -HUP " . ((int)$pid));
	/* redirect to avoid reposting form data on refresh */
	header("Location: diag_logs_filter.php");
	exit;
}


if (isset($_GET['act']) && preg_match("/^[pb]+$/", $_GET['act'])) {
	$action = $_GET['act'];
	$ifstring  .= "&act=" . urlencode($action);
	$srcstring .= "&act=" . urlencode($action);
	$dststring .= "&act=" . urlencode($action);
	$prstring  .= "&act=" . urlencode($action);
}

if (isset($_GET['if']) && ($_GET['if'] != "")) {
	$iface = $_GET['if'];
	$actstring .= "&if=" . urlencode($iface);
	$srcstring .= "&if=" . urlencode($iface);
	$dststring .= "&if=" . urlencode($iface);
	$prstring  .= "&if=" . urlencode($iface);
}

if (isset($_GET['pr']) && in_array($_GET['pr'], $protocols)) {
	$proto = $_GET['pr'];
	$actstring .= "&pr=" . urlencode($proto);
	$ifstring  .= "&pr=" . urlencode($proto);
	$srcstring .= "&pr=" . urlencode($proto);
	$dststring .= "&pr=" . urlencode($proto);
}

if (isset($_GET['sp']) && (is_numeric($_GET['sp']))) {
	$srcport = $_GET['sp'];
	$actstring .= "&sp=" . urlencode($srcport);
	$ifstring  .= "&sp=" . urlencode($srcport);
	$dststring .= "&sp=" . urlencode($srcport);
	$prstring  .= "&sp=" . urlencode($srcport);
}

if (isset($_GET['dp']) && (is_numeric($_GET['dp']))) {
	$dstport = $_GET['dp'];
	$actstring .= "&dp=" . urlencode($dstport);
	$ifstring  .= "&dp=" . urlencode($dstport);
	$srcstring .= "&dp=" . urlencode($dstport);
	$prstring  .= "&dp=" . urlencode($dstport);
}


/* The firewall log comes from pf now.
 *
 * ipmon fed text lines to syslog and this page tailed /var/log/filter.log.
 * pf copies matching packets to pflog0 and pflogd writes them to
 * /var/log/pflog.cap as a pcap, so reading and decoding live in
 * filter_pf.inc (pf_filter_log_read); this page filters and renders.
 */

/* Raw view: the capture as tcpdump prints it, one line per packet. */
function dump_pflog($tail) {
	global $g, $config;

	$cap = "{$g['varlog_path']}/pflog.cap";
	if (!file_exists($cap)) {
		echo "<tr><td class=\"listlr\" colspan=\"2\">No firewall log yet. " .
		     "pflogd writes it once a rule with 'log' matches a packet.</td></tr>\n";
		return;
	}
	$out = array();
	exec("/usr/sbin/tcpdump -n -e -q -tttt -r " . escapeshellarg($cap) .
	     " 2>/dev/null | /usr/bin/tail -n " . ((int)$tail), $out);
	if (isset($config['syslog']['reverse']))
		$out = array_reverse($out);
	foreach ($out as $line) {
		echo "<tr valign=\"top\">\n";
		echo "<td class=\"listlr\" colspan=\"2\">" . htmlspecialchars($line) . "</td>\n";
		echo "</tr>\n";
	}
}

/* Parsed view, with the same filters the ipfilter version offered. */
function conv_pflog($tail) {
	global $config, $iface, $action, $proto, $srcport, $dstport;

	$iftable = pf_log_interface_map();
	$entries = pf_filter_log_read($tail, isset($config['syslog']['reverse']));

	$filterlog = array();
	foreach ($entries as $e) {
		$ifn = $e['interface'];
		if (isset($iftable[$ifn]))
			$flent_if = $iftable[$ifn];
		else if (strpos($ifn, "ng") !== false)
			$flent_if = "L2TP";
		else if ($ifn == "enc0")
			$flent_if = "IPsec";
		else if ($ifn == "gif0" || $ifn == "stf0")
			$flent_if = "WAN";
		else
			$flent_if = $ifn;

		if (isset($iface) && $iface != $flent_if)
			continue;

		/* the page filters on the first letter of the action, p or b */
		$act = $e['act'];
		if (isset($action) && !strstr($action, substr($act, 0, 1)))
			continue;

		$protocol = strtoupper($e['proto']);
		if (isset($proto) && $proto != $protocol)
			continue;
		if (isset($srcport) && $srcport !== "" && $srcport != $e['srcport'])
			continue;
		if (isset($dstport) && $dstport !== "" && $dstport != $e['dstport'])
			continue;

		$filterlog[] = array(
			'act'       => $act,
			'time'      => $e['time'],
			'interface' => $flent_if,
			'src'       => format_pflog_ip($e['src'], $e['srcport']),
			'srcport'   => $e['srcport'],
			'dst'       => format_pflog_ip($e['dst'], $e['dstport']),
			'dstport'   => $e['dstport'],
			'proto'     => $protocol,
			'count'     => '',
		);
	}
	return $filterlog;
}

function format_pflog_ip($ip, $port) {
	global $resolve;

	$shown = $resolve ? gethostbyaddr($ip) : $ip;
	if ($shown === false || $shown === "")
		$shown = $ip;
	return ($port !== "") ? $shown . ", port " . $port : $shown;
}

?>

<?php include("fbegin.inc"); ?>
<table width="100%" border="0" cellpadding="0" cellspacing="0" summary="tab pane">
  <tr><td class="tabnavtbl">
  <ul id="tabnav">
<?php 
   	$tabs = array('System' => 'diag_logs.php',
           		  'Firewall' => 'diag_logs_filter.php',
           		  'DHCP' => 'diag_logs_dhcp.php',
           		  'Captive portal' => 'diag_logs_portal.php',
           		  'PPTP/L2TP VPN' => 'diag_logs_vpn.php',
           		  'Settings' => 'diag_logs_settings.php');
	dynamic_tab_menu($tabs);
?> 
  </ul>
  </td></tr>
  <tr>
    <td class="tabcont">
<?php if (!isset($config['syslog']['rawfilter'])):
	$filterlog = conv_pflog($nentries);
?>
		<table width="100%" border="0" cellpadding="0" cellspacing="0" summary="content pane"><tr>
		  <td colspan="6" class="listtopic"> 
			    Last <?=$nentries;?> firewall log entries</td>
			</tr>
			<tr>
			  <td width="10%" class="listhdrr"><a href="?<?=substr($actstring, 1);?>" style="color:black" title="reset action and reload firewall logs page">Act</a></td>
			  <td width="20%" class="listhdrr">Time</td>
			  <td width="10%" class="listhdrr"><a href="?<?=substr($ifstring, 1);?>" style="color:black" title="reset interface and reload firewall logs page">If</a></td>
			  <td width="20%" class="listhdrr"><a href="?<?=substr($srcstring, 1);?>" style="color:black" title="reset source port entry and reload firewall logs page">Source</a></td>
			  <td width="20%" class="listhdrr"><a href="?<?=substr($dststring, 1);?>" style="color:black" title="reset destination port entry and reload firewall logs page">Destination</a></td>
			  <td width="10%" class="listhdrr"><a href="?<?=substr($prstring, 1);?>" style="color:black" title="reset protocol entry and reload firewall logs page">Proto</a></td>
			</tr>
	<?php
	$actstring .= '">';
	$ifstring  .= '" style="color:black" title="click to select interface">';
	$srcstring .= '" style="color:black" title="click to select source port">';
	$dststring .= '" style="color:black" title="click to select destination port">';
	$prstring  .= '" style="color:black" title="click to select protocol">';
	?>
			 <?php foreach ($filterlog as $filterent): ?>
			<tr>
			  <td class="listlr" nowrap>
			  <?php if (strstr(strtolower($filterent['act']), "p"))
			  			$img = "pass.gif";
					 else 
					 	$img = "block.gif";
			 	?>
			  <a href="?act=<?=$filterent['act'];?><?=$actstring;?><img src="<?=$img;?>" width="11" height="11" align="middle" border="0" title="click to select action" alt="click to select action"></a>
			  <?php if (!empty($filterent['count'])) echo $filterent['count'];?></td>
			  <td class="listr" nowrap><?=htmlspecialchars($filterent['time']);?></td>
			  <td class="listr" nowrap>
			    <a href="?if=<?=$filterent['interface'];?><?=$ifstring;?><?=htmlspecialchars($filterent['interface']);?></a></td>
			  <td class="listr" nowrap>
			    <a href="?sp=<?=htmlspecialchars($filterent['srcport']);?><?=$srcstring;?><?=htmlspecialchars($filterent['src']);?></a></td>
			  <td class="listr" nowrap>
			    <a href="?dp=<?=htmlspecialchars($filterent['dstport']);?><?=$dststring;?><?=htmlspecialchars($filterent['dst']);?></a></td>
			  <td class="listr" nowrap>
			    <a href="?pr=<?=htmlspecialchars($filterent['proto']);?><?=$prstring;?><?=htmlspecialchars($filterent['proto']);?></a></td>
			</tr><?php endforeach; ?>
                    </table>
		<br><table width="100%" border="0" cellspacing="0" cellpadding="0" summary="info pane">
                      <tr> 
                        <td width="100%"><strong><span class="red">Note:</span></strong><br>
                          There are many possibilities to filter this log.
                          Just click on the accept (<img src="pass.gif" alt="">) or
			  deny symbol (<img src="block.gif" alt="">) to filter for
			  accepted or denied IP packets. Do the same for the desired
			  interface, source/destination port or protocol. To deselect
			  a selected filter entry, click on the column description above.
                          To reset all filter entries and reload the firewall logs page,
			  click on the &quot;Firewall&quot; tab below &quot;Diagnostics: Logs&quot;.
                        </td>
		      </tr>
		</table>
<?php else: ?>
		<table width="100%" border="0" cellspacing="0" cellpadding="0">
		  <tr> 
			<td colspan="2" class="listtopic"> 
			  Last <?=$nentries;?> firewall log entries</td>
		  </tr>
		  <?php dump_pflog($nentries); ?>
		</table>
<?php endif; ?>
		<br><form action="diag_logs_filter.php" method="post">
<input name="clear" type="submit" class="formbtn" value="Clear log">
</form>
	</td>
  </tr>
</table>
<?php include("fend.inc"); ?>
