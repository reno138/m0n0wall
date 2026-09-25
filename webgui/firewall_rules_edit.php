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

require("guiconfig.inc");

if ($ipv6rules = (($_GET['type'] ?? null) == 'ipv6')) {
	$configname = 'rule6';
	$typelink = '&type=ipv6';
	$maxnetmask = 128;
} else {
	$configname = 'rule';
	$typelink = '';
	$maxnetmask = 32;
}
$pgtitle = array("Firewall", "Rules", "Edit");	/* make group manager happy */
$pgtitle = array("Firewall", ipv6enabled() ? ($ipv6rules ? 'IPv6 Rules' : 'IPv4 Rules') : 'Rules', "Edit");

$specialsrcdst = explode(" ", "any wanip lan pptp l2tp");

if (!is_array($config['filter'][$configname])) {
	$config['filter'][$configname] = array();
}
filter_rules_sort();
$a_filter = &$config['filter'][$configname];

$id = $_GET['id'] ?? null;
if (is_numeric($_POST['id'] ?? null))
	$id = $_POST['id'];
	
$after = $_GET['after'] ?? null;

if (isset($_POST['after']))
	$after = $_POST['after'];

if (isset($_GET['dup'])) {
	$id = $_GET['dup'];
	$after = $_GET['dup'];
}

function is_specialnet($net) {
	global $specialsrcdst;
	
	if (in_array($net, $specialsrcdst) || (strstr($net, "opt") && !is_alias($net)))
		return true;
	else
		return false;
}

function address_to_pconfig($adr, &$padr, &$pmask, &$pnot, &$pbeginport, &$pendport) {
	global $maxnetmask;
		
	if (isset($adr['any']))
		$padr = "any";
	else if (!empty($adr['network']))
		$padr = $adr['network'];
	else if (!empty($adr['address'])) {
		list($padr, $pmask) = explode("/", $adr['address']);
		if (!$pmask)
			$pmask = $maxnetmask;
	}
	
	if (isset($adr['not']))
		$pnot = 1;
	else
		$pnot = 0;
	
	if (!empty($adr['port'])) {
		list($pbeginport, $pendport) = explode("-", $adr['port']);
		if (!$pendport)
			$pendport = $pbeginport;
	} else {
		$pbeginport = "any";
		$pendport = "any";
	}
}

/* "cn, RU , zz" -> array("CN","RU","ZZ"), or false if any entry is not a
   two-letter code. These end up in a pf table name and a filename, so they
   are validated here and again in geoip.inc rather than trusted. */
function country_list_normalise($raw) {
	$out = array();
	foreach (explode(',', (string)$raw) as $cc) {
		$cc = trim($cc);
		if ($cc === '')
			continue;
		if (!is_country_code($cc))
			return false;
		$out[strtoupper($cc)] = true;
	}
	return empty($out) ? false : array_keys($out);
}

function pconfig_to_address(&$adr, $padr, $pmask, $pnot, $pbeginport, $pendport) {
	global $maxnetmask;
	
	$adr = array();
	
	if ($padr == "any")
		$adr['any'] = true;
	else if (is_specialnet($padr))
		$adr['network'] = $padr;
	else {
		$adr['address'] = $padr;
		if ($pmask != $maxnetmask)
			$adr['address'] .= "/" . $pmask;
	}
	
	$adr['not'] = $pnot ? true : false;
	
	if (($pbeginport != 0) && ($pbeginport != "any")) {
		if ($pbeginport != $pendport)
			$adr['port'] = $pbeginport . "-" . $pendport;
		else
			$adr['port'] = $pbeginport;
	}
}

if (isset($id) && !empty($a_filter[$id])) {
	$pconfig['interface'] = $a_filter[$id]['interface'];

	/* Country: handled beside address_to_pconfig() rather than inside it,
	   because that helper is shared with the NAT and shaper pages and a rule
	   side is either a country or an address, never both. */
	if (!empty($a_filter[$id]['source']['country'])) {
		$pconfig['src'] = "country";
		$pconfig['srccountry'] = $a_filter[$id]['source']['country'];
	}
	if (!empty($a_filter[$id]['destination']['country'])) {
		$pconfig['dst'] = "country";
		$pconfig['dstcountry'] = $a_filter[$id]['destination']['country'];
	}
	
	if (!isset($a_filter[$id]['type']))
		$pconfig['type'] = "pass";
	else
		$pconfig['type'] = $a_filter[$id]['type'];
	
	if (isset($a_filter[$id]['protocol']))
		$pconfig['proto'] = $a_filter[$id]['protocol'];
	else
		$pconfig['proto'] = "any";
	
	if ($a_filter[$id]['protocol'] == "icmp" || $a_filter[$id]['protocol'] == "ipv6-icmp")
		$pconfig['icmptype'] = $a_filter[$id]['icmptype'];
	
	address_to_pconfig($a_filter[$id]['source'], $pconfig['src'],
		$pconfig['srcmask'], $pconfig['srcnot'],
		$pconfig['srcbeginport'], $pconfig['srcendport']);
		
	address_to_pconfig($a_filter[$id]['destination'], $pconfig['dst'],
		$pconfig['dstmask'], $pconfig['dstnot'],
		$pconfig['dstbeginport'], $pconfig['dstendport']);

	$pconfig['disabled'] = isset($a_filter[$id]['disabled']);
	$pconfig['log'] = isset($a_filter[$id]['log']);
	/* $pconfig['frags'] intentionally absent -- see the Fragments row. */
	$pconfig['descr'] = $a_filter[$id]['descr'];
	
} else {
	/* defaults */
	if (!empty($_GET['if']))
		$pconfig['interface'] = $_GET['if'];
	$pconfig['type'] = "pass";
	$pconfig['src'] = "any";
	$pconfig['dst'] = "any";
}

if (isset($_GET['dup']))
	unset($id);

if ($_POST) {

	if (($_POST['proto'] != "tcp") && ($_POST['proto'] != "udp") && ($_POST['proto'] != "tcp/udp")) {
		$_POST['srcbeginport'] = 0;
		$_POST['srcendport'] = 0;
		$_POST['dstbeginport'] = 0;
		$_POST['dstendport'] = 0;
	} else {
	
		if (!empty($_POST['srcbeginport_cust']) && empty($_POST['srcbeginport']))
			$_POST['srcbeginport'] = $_POST['srcbeginport_cust'];
		if (!empty($_POST['srcendport_cust']) && empty($_POST['srcendport']))
			$_POST['srcendport'] = $_POST['srcendport_cust'];
	
		if ($_POST['srcbeginport'] == "any") {
			$_POST['srcbeginport'] = 0;
			$_POST['srcendport'] = 0;
		} else {			
			if (!$_POST['srcendport'])
				$_POST['srcendport'] = $_POST['srcbeginport'];
		}
		if ($_POST['srcendport'] == "any")
			$_POST['srcendport'] = $_POST['srcbeginport'];
		
		if (!empty($_POST['dstbeginport_cust']) && empty($_POST['dstbeginport']))
			$_POST['dstbeginport'] = $_POST['dstbeginport_cust'];
		if (!empty($_POST['dstendport_cust']) && empty($_POST['dstendport']))
			$_POST['dstendport'] = $_POST['dstendport_cust'];
		
		if ($_POST['dstbeginport'] == "any") {
			$_POST['dstbeginport'] = 0;
			$_POST['dstendport'] = 0;
		} else {			
			if (!$_POST['dstendport'])
				$_POST['dstendport'] = $_POST['dstbeginport'];
		}
		if ($_POST['dstendport'] == "any")
			$_POST['dstendport'] = $_POST['dstbeginport'];		
	}
		
	if (($_POST['srctype'] ?? '') == "country") {
		$_POST['src'] = "country";
		$_POST['srcmask'] = 0;
	} else if (is_specialnet($_POST['srctype'])) {
		$_POST['src'] = $_POST['srctype'];
		$_POST['srcmask'] = 0;
	} else if ($_POST['srctype'] == "single") {
		$_POST['srcmask'] = $maxnetmask;
	}
	if (($_POST['dsttype'] ?? '') == "country") {
		$_POST['dst'] = "country";
		$_POST['dstmask'] = 0;
	} else if (is_specialnet($_POST['dsttype'])) {
		$_POST['dst'] = $_POST['dsttype'];
		$_POST['dstmask'] = 0;
	}  else if ($_POST['dsttype'] == "single") {
		$_POST['dstmask'] = $maxnetmask;
	}
	
	unset($input_errors);
	$pconfig = $_POST;

	/* input validation */
	$reqdfields = explode(" ", "type interface proto src dst");
	$reqdfieldsn = explode(",", "Type,Interface,Protocol,Source,Destination");
	
	if (!(is_specialnet($_POST['srctype']) || ($_POST['srctype'] == "single")
	      || ($_POST['srctype'] ?? '') == "country")) {
		$reqdfields[] = "srcmask";
		$reqdfieldsn[] = "Source bit count";
	}
	if (!(is_specialnet($_POST['dsttype']) || ($_POST['dsttype'] == "single")
	      || ($_POST['dsttype'] ?? '') == "country")) {
		$reqdfields[] = "dstmask";
		$reqdfieldsn[] = "Destination bit count";
	}
	
	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
	
	if (!$_POST['srcbeginport']) {
		$_POST['srcbeginport'] = 0;
		$_POST['srcendport'] = 0;
	}
	if (!$_POST['dstbeginport']) {
		$_POST['dstbeginport'] = 0;
		$_POST['dstendport'] = 0;
	}
	
	if (($_POST['type'] == "reject") && ($_POST['proto'] != "tcp") && ($_POST['proto'] != "udp")) {
		$input_errors[] = "Reject only works when the protocol is set to either TCP or UDP.";
	}
	
	if (($_POST['srcbeginport'] && !is_port($_POST['srcbeginport']))) {
		$input_errors[] = "The start source port must be an integer between 1 and 65535.";
	}
	if (($_POST['srcendport'] && !is_port($_POST['srcendport']))) {
		$input_errors[] = "The end source port must be an integer between 1 and 65535.";
	}
	if (($_POST['dstbeginport'] && !is_port($_POST['dstbeginport']))) {
		$input_errors[] = "The start destination port must be an integer between 1 and 65535.";
	}
	if (($_POST['dstendport'] && !is_port($_POST['dstendport']))) {
		$input_errors[] = "The end destination port must be an integer between 1 and 65535.";
	}
	
	if (($_POST['srctype'] ?? '') == "country") {
		if (country_list_normalise($_POST['srccountry'] ?? '') === false)
			$input_errors[] = "Source: enter one or more two-letter country codes, separated by commas.";
	} else if (!is_specialnet($_POST['srctype'])) {
		if ($_POST['src'] && !($ipv6rules ? is_ipaddr6($_POST['src']) : is_ipaddroranyalias($_POST['src']))) {
			$input_errors[] = "A valid source IP address or alias must be specified.";
		}
		if (($_POST['srcmask'] && !is_numericint($_POST['srcmask']))) {
			$input_errors[] = "A valid source bit count must be specified.";
		}
	}
	if (($_POST['dsttype'] ?? '') == "country") {
		if (country_list_normalise($_POST['dstcountry'] ?? '') === false)
			$input_errors[] = "Destination: enter one or more two-letter country codes, separated by commas.";
	} else if (!is_specialnet($_POST['dsttype'])) {
		if ($_POST['dst'] && !($ipv6rules ? is_ipaddr6($_POST['dst']) : is_ipaddroranyalias($_POST['dst']))) {
			$input_errors[] = "A valid destination IP address or alias must be specified.";
		}
		if (($_POST['dstmask'] && !is_numericint($_POST['dstmask']))) {
			$input_errors[] = "A valid destination bit count must be specified.";
		}
	}
	
	if ($_POST['srcbeginport'] > $_POST['srcendport']) {
		/* swap */
		$tmp = $_POST['srcendport'];
		$_POST['srcendport'] = $_POST['srcbeginport'];
		$_POST['srcbeginport'] = $tmp;
	}
	if ($_POST['dstbeginport'] > $_POST['dstendport']) {
		/* swap */
		$tmp = $_POST['dstendport'];
		$_POST['dstendport'] = $_POST['dstbeginport'];
		$_POST['dstbeginport'] = $tmp;
	}

	if (!$input_errors) {
		$filterent = array();
		$filterent['type'] = $_POST['type'];
		$filterent['interface'] = $_POST['interface'];
		
		if ($_POST['proto'] != "any")
			$filterent['protocol'] = $_POST['proto'];
		else
			unset($filterent['protocol']);
	
		if (($_POST['proto'] == "icmp" || $_POST['proto'] == "ipv6-icmp") && !empty($_POST['icmptype']))
			$filterent['icmptype'] = $_POST['icmptype'];
		else
			unset($filterent['icmptype']);
		
		pconfig_to_address($filterent['source'], $_POST['src'],
			$_POST['srcmask'], $_POST['srcnot'] ?? null,
			$_POST['srcbeginport'], $_POST['srcendport']);
			
		pconfig_to_address($filterent['destination'], $_POST['dst'],
			$_POST['dstmask'], $_POST['dstnot'] ?? null,
			$_POST['dstbeginport'], $_POST['dstendport']);

		/* Country replaces the address on that side. pconfig_to_address() ran
		   first so 'not' and the ports it parsed are kept; only the address
		   itself is swapped for the country list. */
		foreach (array('src' => 'source', 'dst' => 'destination') as $k => $side) {
			unset($filterent[$side]['country']);
			if (($_POST[$k . 'type'] ?? '') != "country")
				continue;
			$ccs = country_list_normalise($_POST[$k . 'country'] ?? '');
			if ($ccs === false)
				continue;
			unset($filterent[$side]['address'], $filterent[$side]['network'], $filterent[$side]['any']);
			$filterent[$side]['country'] = implode(',', $ccs);
		}
		
		$filterent['disabled'] = !empty($_POST['disabled']) ? true : false;
		$filterent['log'] = !empty($_POST['log']) ? true : false;
		/* 'frags' is not written any more: pf reassembles globally, so there
		   is nothing a per-rule flag could change. Existing keys in a restored
		   config are simply ignored. */
		$filterent['descr'] = $_POST['descr'];
		
		if (isset($id) && !empty($a_filter[$id]))
			$a_filter[$id] = $filterent;
		else {
			if (is_numeric($after))
				array_splice($a_filter, $after+1, 0, array($filterent));
			else
				$a_filter[] = $filterent;
		}
		
		write_config();
		touch($d_filterconfdirty_path);
		
		header("Location: firewall_rules.php?if=" . $_POST['interface'] . $typelink);
		exit;
	}
}
?>
<?php include("fbegin.inc"); ?>
<script type="text/javascript">
<!--
var portsenabled = 1;

function ext_change() {
	if ((document.iform.srcbeginport.selectedIndex == 0) && portsenabled) {
		document.iform.srcbeginport_cust.disabled = 0;
	} else {
		document.iform.srcbeginport_cust.value = "";
		document.iform.srcbeginport_cust.disabled = 1;
	}
	if ((document.iform.srcendport.selectedIndex == 0) && portsenabled) {
		document.iform.srcendport_cust.disabled = 0;
	} else {
		document.iform.srcendport_cust.value = "";
		document.iform.srcendport_cust.disabled = 1;
	}
	if ((document.iform.dstbeginport.selectedIndex == 0) && portsenabled) {
		document.iform.dstbeginport_cust.disabled = 0;
	} else {
		document.iform.dstbeginport_cust.value = "";
		document.iform.dstbeginport_cust.disabled = 1;
	}
	if ((document.iform.dstendport.selectedIndex == 0) && portsenabled) {
		document.iform.dstendport_cust.disabled = 0;
	} else {
		document.iform.dstendport_cust.value = "";
		document.iform.dstendport_cust.disabled = 1;
	}
	
	if (!portsenabled) {
		document.iform.srcbeginport.disabled = 1;
		document.iform.srcendport.disabled = 1;
		document.iform.dstbeginport.disabled = 1;
		document.iform.dstendport.disabled = 1;
	} else {
		document.iform.srcbeginport.disabled = 0;
		document.iform.srcendport.disabled = 0;
		document.iform.dstbeginport.disabled = 0;
		document.iform.dstendport.disabled = 0;
	}
}

function typesel_change() {
	switch (document.iform.srctype.selectedIndex) {
		case 1:	/* single */
			document.iform.src.disabled = 0;
			document.iform.srcmask.value = "";
			document.iform.srcmask.disabled = 1;
			break;
		case 2:	/* network */
			document.iform.src.disabled = 0;
			document.iform.srcmask.disabled = 0;
			break;
		default:
			document.iform.src.value = "";
			document.iform.src.disabled = 1;
			document.iform.srcmask.value = "";
			document.iform.srcmask.disabled = 1;
			break;
	}
	/* by value, not selectedIndex: the Country option is appended after the
	   conditional pptp/l2tp/opt entries, so its index is not fixed */
	document.iform.srccountry.disabled = (document.iform.srctype.value != "country");
	switch (document.iform.dsttype.selectedIndex) {
		case 1:	/* single */
			document.iform.dst.disabled = 0;
			document.iform.dstmask.value = "";
			document.iform.dstmask.disabled = 1;
			break;
		case 2:	/* network */
			document.iform.dst.disabled = 0;
			document.iform.dstmask.disabled = 0;
			break;
		default:
			document.iform.dst.value = "";
			document.iform.dst.disabled = 1;
			document.iform.dstmask.value = "";
			document.iform.dstmask.disabled = 1;
			break;
	}
	document.iform.dstcountry.disabled = (document.iform.dsttype.value != "country");
}

function proto_change() {
	var o = document.iform.proto;
	portsenabled = (o.selectedIndex < 3);

	if (o.selectedIndex == 3) {
		document.iform.icmptype.disabled = 0;
	} else {
		document.iform.icmptype.disabled = 1;
	}
	
	ext_change();
}

function src_rep_change() {
	document.iform.srcendport.selectedIndex = document.iform.srcbeginport.selectedIndex;
}
function dst_rep_change() {
	document.iform.dstendport.selectedIndex = document.iform.dstbeginport.selectedIndex;
}
//-->
</script>
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
            <form action="firewall_rules_edit.php<?=($typelink?'?' . $typelink:'')?>" method="post" name="iform" id="iform">
              <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="content pane">
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Action</td>
                  <td width="78%" class="vtable">
					<select name="type" class="formfld">
                      <?php $types = explode(" ", "Pass Block Reject"); foreach ($types as $type): ?>
                      <option value="<?=strtolower($type);?>" <?php if (strtolower($type) == strtolower($pconfig['type'] ?? '')) echo "selected"; ?>>
                      <?=htmlspecialchars($type);?>
                      </option>
                      <?php endforeach; ?>
                    </select> <br>
                    <span class="vexpl">Choose what to do with packets that match
					the criteria specified below.<br>
Hint: the difference between block and reject is that with reject, a packet (TCP RST or ICMP port unreachable for UDP) is returned to the sender, whereas with block the packet is dropped silently. In either case, the original packet is discarded. Reject only works when the protocol is set to either TCP or UDP (but not &quot;TCP/UDP&quot;) below.</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Disabled</td>
                  <td width="78%" class="vtable"> 
                    <input name="disabled" type="checkbox" id="disabled" value="yes" <?php if (!empty($pconfig['disabled'])) echo "checked"; ?>>
                    <strong>Disable this rule</strong><br>
                    <span class="vexpl">Set this option to disable this rule without
					removing it from the list.</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Interface</td>
                  <td width="78%" class="vtable">
					<select name="interface" class="formfld">
                      <?php
					  if ($ipv6rules)
					      $interfaces = array('wan' => 'WAN', 'lan' => 'LAN', 'ipsec' => 'IPsec');
					  else
					      $interfaces = array('wan' => 'WAN', 'lan' => 'LAN', 'l2tp' => 'L2TP', 'ipsec' => 'IPsec');
					  /* Each enabled WireGuard tunnel is its own interface, so a
					     rule can be bound to one tunnel rather than to "the VPN".
					     Without this the tunnels were up but unreachable by any
					     rule the admin could write. */
					  $interfaces += wg_rule_interfaces();
					  /* opt_interfaces() rather than counting up from 1: a deleted
					     optional interface no longer renumbers the rest, so the
					     numbering can have gaps and a counting loop would stop at the
					     first one. */
					  foreach (opt_interfaces() as $optif) {
					  	$interfaces[$optif] = $config['interfaces'][$optif]['descr'];
					  }
					  foreach ($interfaces as $iface => $ifacename): ?>
                      <option value="<?=$iface;?>" <?php if ($iface == ($pconfig['interface'] ?? null)) echo "selected"; ?>>
                      <?=htmlspecialchars($ifacename);?>
                      </option>
                      <?php endforeach; ?>
                    </select> <br>
                    <span class="vexpl">Choose on which interface packets must 
                    come in to match this rule.</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Protocol</td>
                  <td width="78%" class="vtable">
                    <select name="proto" class="formfld" onchange="proto_change()">
                        <?php
                        $protocols = explode(' ', 'TCP UDP TCP/UDP ' .
                            (!$ipv6rules ? 'ICMP IPv6 IGMP' : 'IPv6-ICMP IPv6-NONXT IPv6-OPTS IPv6-ROUTE IPv6-FRAG') .
                            ' ESP AH GRE any');
                        foreach ($protocols as $proto): ?>
                            <option value="<?=strtolower($proto);?>" <?php if (strtolower($proto) == ($pconfig['proto'] ?? null))
                            echo "selected"; ?>><?=htmlspecialchars($proto);?></option>
                        <?php endforeach; ?>
                    </select> <br>
                    <span class="vexpl">Choose which IP protocol this rule should 
                    match.<br>
                    Hint: in most cases, you should specify <em>TCP</em> &nbsp;here.</span></td>
                </tr>
                <tr>
                  <td valign="top" class="vncell">ICMP type</td>
                  <td class="vtable">
                    <select name="icmptype" class="formfld">
                      <?php
					  
					  if (!$ipv6rules) {
                          /* pf's type names, not ipfilter's. Three differ
                             ("echo"/"timest"/"timestrep" were ipf spellings pf
                             rejects, and pfctl refuses the ENTIRE ruleset over
                             one unknown name). pf_icmptype_v4() still maps the
                             old spellings, so a restored pre-1.9 config loads. */
                          $icmptypes = array(
                            "" => "any",
                            "unreach" => "Destination unreachable",
                            "echoreq" => "Echo request",
                            "echorep" => "Echo reply",
                            "squench" => "Source quench",
                            "redir" => "Redirect",
                            "timex" => "Time exceeded",
                            "paramprob" => "Parameter problem",
                            "timereq" => "Timestamp request",
                            "timerep" => "Timestamp reply",
                            "inforeq" => "Information request",
                            "inforep" => "Information reply",
                            "maskreq" => "Address mask request",
                            "maskrep" => "Address mask reply"
                          );
                      } else {
                          $icmptypes = array(
                            '' => 'any',
                            1 => 'Destination Unreachable',
                            2 => 'Packet Too Big',
                            3 => 'Time Exceeded',
                            4 => 'Parameter Problem',
                            128 => 'Echo Request',
                            129 => 'Echo Reply',
                            130 => 'Multicast Listener Query',
                            131 => 'Multicast Listener Report',
                            132 => 'Multicast Listener Done',
                            133 => 'Router Solicitation',
                            134 => 'Router Advertisement',
                            135 => 'Neighbor Solicitation',
                            136 => 'Neighbor Advertisement',
                            137 => 'Redirect Message'
                          );
                      }
					  
					  /* A rule saved with an ipf-era name must still show up
					     selected rather than silently reverting to "any". */
					  $cursel = $pconfig['icmptype'] ?? null;
					  $legacymap = array('echo' => 'echoreq', 'timest' => 'timereq',
					                     'timestrep' => 'timerep');
					  if (isset($legacymap[$cursel]))
						  $cursel = $legacymap[$cursel];

					  foreach ($icmptypes as $icmptype => $descr): ?>
                      <option value="<?=$icmptype;?>" <?php if ((string) $icmptype === (string) $cursel) echo "selected"; ?>>
                      <?=htmlspecialchars($descr);?>
                      </option>
                      <?php endforeach; ?>
                    </select>
                    <br>
                    <span class="vexpl">If you selected ICMP for the protocol above, you may specify an ICMP type here.</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Source</td>
                  <td width="78%" class="vtable">
<input name="srcnot" type="checkbox" id="srcnot" value="yes" <?php if (!empty($pconfig['srcnot'])) echo "checked"; ?>>
                    <strong>not</strong><br>
                    Use this option to invert the sense of the match.<br>
                    <br>
                    <table border="0" cellspacing="0" cellpadding="0" summary="type-address widget">
                      <tr> 
                        <td>Type:&nbsp;&nbsp;</td>
						<td></td>
                        <td><select name="srctype" class="formfld" onChange="typesel_change()">
							<?php $sel = is_specialnet($pconfig['src']); ?>
                            <option value="any" <?php if ($pconfig['src'] == "any") { echo "selected"; } ?>>
                            any</option>
                            <option value="single" <?php if ((($pconfig['srcmask'] ?? null) == $maxnetmask) && !$sel) { echo "selected"; $sel = 1; } ?>>
                            Single host or alias</option>
                            <option value="network" <?php if (!$sel) echo "selected"; ?>>
                            Network</option>
                            <option value="wanip" <?php if ($pconfig['src'] == "wanip") { echo "selected"; } ?>>
                            WAN address</option>
                            <option value="lan" <?php if ($pconfig['src'] == "lan") { echo "selected"; } ?>>
                            LAN subnet</option>
							<?php if (!$ipv6rules): ?>
                            <option value="l2tp" <?php if ($pconfig['src'] == "l2tp") { echo "selected"; } ?>>
                            L2TP clients</option>
							<?php endif; ?>
							<?php foreach (opt_interfaces() as $i => $optif): ?>
                            <option value="opt<?=$i;?>" <?php if ($pconfig['src'] == "opt" . $i) { echo "selected"; } ?>>
                            <?=htmlspecialchars($config['interfaces'][$optif]['descr']);?> subnet</option>
							<?php endforeach; ?>
                          							<option value="country" <?php if ($pconfig['src'] == "country") { echo "selected"; } ?>>
							Country</option>
							</select></td>
                      </tr>
                      <tr> 
                        <td>Address:&nbsp;&nbsp;</td>
						<td><?=$mandfldhtmlspc;?></td>
                        <td><input name="src" type="text" class="<?=($ipv6rules ? 'formfld' : 'formfldalias')?>" id="src" size="20" value="<?php if (!is_specialnet($pconfig['src'])) echo htmlspecialchars($pconfig['src']);?>">
                        /
						<select name="srcmask" class="formfld" id="srcmask">
						<?php for ($i = ($maxnetmask - 1); $i > 0; $i--): ?>
						<option value="<?=$i;?>" <?php if ($i == ($pconfig['srcmask'] ?? null)) echo "selected"; ?>><?=$i;?></option>
						<?php endfor; ?>
						</select>
						
						<br><span class="vexpl">Country codes (ISO 3166-1 alpha-2), comma separated &mdash; e.g. <em>CN, RU</em>. Only used when the type above is <em>Country</em>. Matching is by pf table; see <a href="firewall_geoip.php">Firewall: GeoIP</a> for the data and its age.</span>
						<br><input name="srccountry" type="text" class="formfld" id="srccountry" size="30" value="<?=htmlspecialchars($pconfig['srccountry'] ?? '');?>"></td>
					  </tr>
                    </table></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Source port range 
                  </td>
                  <td width="78%" class="vtable"> 
                    <table border="0" cellspacing="0" cellpadding="0" summary="from-to widget">
                      <tr> 
                        <td>from:&nbsp;&nbsp;</td>
                        <td><select name="srcbeginport" class="formfld" onchange="src_rep_change();ext_change()">
                            <option value="">(other)</option>
                            <option value="any" <?php $bfound = 0; if (($pconfig['srcbeginport'] ?? null) == "any") { echo "selected"; $bfound = 1; } ?>>any</option>
                            <?php foreach ($wkports as $wkport => $wkportdesc): ?>
                            <option value="<?=$wkport;?>" <?php if ($wkport == ($pconfig['srcbeginport'] ?? null)) {
																echo "selected";
																$bfound = 1;
															}?>>
                            <?=htmlspecialchars($wkportdesc);?>
                            </option>
                            <?php endforeach; ?>
                          </select> <input name="srcbeginport_cust" type="text" size="5" value="<?php if (!$bfound && !empty($pconfig['srcbeginport'])) echo htmlspecialchars($pconfig['srcbeginport']); ?>"></td>
                      </tr>
                      <tr> 
                        <td>to:</td>
                        <td><select name="srcendport" class="formfld" onchange="ext_change()">
                            <option value="">(other)</option>
                            <option value="any" <?php $bfound = 0; if (($pconfig['srcendport'] ?? null) == "any") { echo "selected"; $bfound = 1; } ?>>any</option>
                            <?php foreach ($wkports as $wkport => $wkportdesc): ?>
                            <option value="<?=$wkport;?>" <?php if ($wkport == ($pconfig['srcendport'] ?? null)) {
																echo "selected";
																$bfound = 1;
															}?>>
                            <?=htmlspecialchars($wkportdesc);?>
                            </option>
                            <?php endforeach; ?>
                          </select> <input name="srcendport_cust" type="text" size="5" value="<?php if (!$bfound && !empty($pconfig['srcendport'])) echo htmlspecialchars($pconfig['srcendport']); ?>"></td>
                      </tr>
                    </table>
                    <br> 
                    <span class="vexpl">Specify the port or port range for 
                    the source of the packet for this rule. This is usually not equal to the destination port range (and is often &quot;any&quot;). <br>
                    Hint: you can leave the <em>'to'</em> field empty if you only 
                    want to filter a single port</span></td>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Destination</td>
                  <td width="78%" class="vtable"> 
                    <input name="dstnot" type="checkbox" id="dstnot" value="yes" <?php if (!empty($pconfig['dstnot'])) echo "checked"; ?>> 
                    <strong>not</strong><br>
                    Use this option to invert the sense of the match.<br>
                    <br>
                    <table border="0" cellspacing="0" cellpadding="0" summary="type-address widget">
                      <tr> 
                        <td>Type:&nbsp;&nbsp;</td>
						<td></td>
                        <td><select name="dsttype" class="formfld" onChange="typesel_change()">
                            <?php $sel = is_specialnet($pconfig['dst']); ?>
                            <option value="any" <?php if ($pconfig['dst'] == "any") { echo "selected"; } ?>>
                            any</option>
                            <option value="single" <?php if ((($pconfig['dstmask'] ?? null) == $maxnetmask) && !$sel) { echo "selected"; $sel = 1; } ?>>
                            Single host or alias</option>
                            <option value="network" <?php if (!$sel) echo "selected"; ?>>
                            Network</option>
                            <option value="wanip" <?php if ($pconfig['dst'] == "wanip") { echo "selected"; } ?>>
                            WAN address</option>
                            <option value="lan" <?php if ($pconfig['dst'] == "lan") { echo "selected"; } ?>>
                            LAN subnet</option>
							<?php if (!$ipv6rules): ?>
                            <option value="l2tp" <?php if ($pconfig['dst'] == "l2tp") { echo "selected"; } ?>>
                            L2TP clients</option>
							<?php endif; ?>
							<?php foreach (opt_interfaces() as $i => $optif): ?>
                            <option value="opt<?=$i;?>" <?php if ($pconfig['dst'] == "opt" . $i) { echo "selected"; } ?>>
                            <?=htmlspecialchars($config['interfaces'][$optif]['descr']);?> subnet</option>
							<?php endforeach; ?>
                          							<option value="country" <?php if ($pconfig['dst'] == "country") { echo "selected"; } ?>>
							Country</option>
							</select></td>
                      </tr>
                      <tr> 
                        <td>Address:&nbsp;&nbsp;</td>
						<td><?=$mandfldhtmlspc;?></td>
                        <td><input name="dst" type="text" class="<?=($ipv6rules ? 'formfld' : 'formfldalias')?>" id="dst" size="20" value="<?php if (!is_specialnet($pconfig['dst'])) echo htmlspecialchars($pconfig['dst']);?>">
                          / 
                          <select name="dstmask" class="formfld" id="dstmask">
						<?php for ($i = ($maxnetmask - 1); $i > 0; $i--): ?>
						<option value="<?=$i;?>" <?php if ($i == ($pconfig['dstmask'] ?? null)) echo "selected"; ?>><?=$i;?></option>
						<?php endfor; ?>
						</select>
						<br><span class="vexpl">Country codes (ISO 3166-1 alpha-2), comma separated &mdash; e.g. <em>CN, RU</em>. Only used when the type above is <em>Country</em>. Matching is by pf table; see <a href="firewall_geoip.php">Firewall: GeoIP</a> for the data and its age.</span>
						<br><input name="dstcountry" type="text" class="formfld" id="dstcountry" size="30" value="<?=htmlspecialchars($pconfig['dstcountry'] ?? '');?>"></td>
                      </tr>
                    </table></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Destination port 
                    range </td>
                  <td width="78%" class="vtable"> 
                    <table border="0" cellspacing="0" cellpadding="0" summary="from-to widget">
                      <tr> 
                        <td>from:&nbsp;&nbsp;</td>
                        <td><select name="dstbeginport" class="formfld" onchange="dst_rep_change();ext_change()">
                            <option value="">(other)</option>
                            <option value="any" <?php $bfound = 0; if (($pconfig['dstbeginport'] ?? null) == "any") { echo "selected"; $bfound = 1; } ?>>any</option>
                            <?php foreach ($wkports as $wkport => $wkportdesc): ?>
                            <option value="<?=$wkport;?>" <?php if ($wkport == ($pconfig['dstbeginport'] ?? null)) {
																echo "selected";
																$bfound = 1;
															}?>>
                            <?=htmlspecialchars($wkportdesc);?>
                            </option>
                            <?php endforeach; ?>
                          </select> <input name="dstbeginport_cust" type="text" size="5" value="<?php if (!$bfound && !empty($pconfig['dstbeginport'])) echo htmlspecialchars($pconfig['dstbeginport']); ?>"></td>
                      </tr>
                      <tr> 
                        <td>to:</td>
                        <td><select name="dstendport" class="formfld" onchange="ext_change()">
                            <option value="">(other)</option>
                            <option value="any" <?php $bfound = 0; if (($pconfig['dstendport'] ?? null) == "any") { echo "selected"; $bfound = 1; } ?>>any</option>
                            <?php foreach ($wkports as $wkport => $wkportdesc): ?>
                            <option value="<?=$wkport;?>" <?php if ($wkport == ($pconfig['dstendport'] ?? null)) {
																echo "selected";
																$bfound = 1;
															}?>>
                            <?=htmlspecialchars($wkportdesc);?>
                            </option>
                            <?php endforeach; ?>
                          </select> <input name="dstendport_cust" type="text" size="5" value="<?php if (!$bfound && !empty($pconfig['dstendport'])) echo htmlspecialchars($pconfig['dstendport']); ?>"></td>
                      </tr>
                    </table>
                    <br> <span class="vexpl">Specify the port or port range for 
                    the destination of the packet for this rule.<br>
                    Hint: you can leave the <em>'to'</em> field empty if you only 
                    want to filter a single port</span></td>
                
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Fragments</td>
                  <td width="78%" class="vtable"> 
                    <strong>Handled automatically</strong><br>
                    <span class="vexpl">There is no longer a per-rule setting here.
                    Fragments are reassembled before the rules are consulted
                    (<em>scrub in all fragment reassemble</em>), so every rule sees
                    whole packets and fragmented traffic is matched correctly
                    without an option. The old per-rule checkbox was an ipfilter
                    requirement; under pf it could not have any effect.</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Log</td>
                  <td width="78%" class="vtable"> 
                    <input name="log" type="checkbox" id="log" value="yes" <?php if (!empty($pconfig['log'])) echo "checked"; ?>>
                    <strong>Log packets that are handled by this rule</strong><br>
                    <span class="vexpl">Hint: the firewall has limited local log 
                    space. Don't turn on logging for everything. If you want to 
                    do a lot of logging, consider using a remote syslog server 
                    (see the <a href="diag_logs_settings.php">Diagnostics: System 
                    logs: Settings</a> page).</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">Description</td>
                  <td width="78%" class="vtable"> 
                    <input name="descr" type="text" class="formfld" id="descr" size="40" value="<?=htmlspecialchars($pconfig['descr'] ?? '');?>"> 
                    <br> <span class="vexpl">You may enter a description here 
                    for your reference (not parsed).</span></td>
                </tr>
                <tr> 
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%"> 
                    <input name="Submit" type="submit" class="formbtn" value="Save"> 
                    <?php if (isset($id) && !empty($a_filter[$id])): ?>
                    <input name="id" type="hidden" value="<?=htmlspecialchars($id);?>"> 
                    <?php endif; ?>
                    <input name="after" type="hidden" value="<?=htmlspecialchars($after ?? '');?>"> 
                  </td>
                </tr>
              </table>
</form>
<script type="text/javascript">
<!--
ext_change();
typesel_change();
proto_change();
//-->
</script>
<?php include("fend.inc"); ?>
