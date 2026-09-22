<?php
/*
	filter_pf.inc
	part of m0n0wall (http://m0n0.ch/wall)

	pf rule generation, replacing the ipfilter/ipnat generation in filter.inc.

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

/* ===========================================================================
 * ipfilter -> pf: the translation decisions
 * ===========================================================================
 *
 * This is NOT a syntax port. ipf and pf differ semantically in ways that
 * silently invert behaviour if translated literally. Each decision below was
 * verified against pf.conf(5) rather than assumed.
 *
 * 1. MATCH ORDER.  ipf filter rules are last-match-wins, overridden by
 *    'quick'. pf is identical: last match wins, and 'quick' makes a rule
 *    final. m0n0wall marks essentially every rule 'quick', so ordering
 *    carries over unchanged. Translation rules (nat/rdr/binat) are
 *    FIRST-match in pf, and ipnat is also first-match, so the deliberate
 *    portmap-rule-before-ipmap-rule ordering in filter_nat_rules_generate_if()
 *    keeps working.
 *
 * 2. PORT RANGES -- the trap.  ipf's '><' is EXCLUSIVE of both endpoints,
 *    which is why filter.inc does $lo-- and $hi++ before emitting it. pf's
 *    'port lo:hi' is INCLUSIVE. So the adjustment must NOT be carried over.
 *    Porting that arithmetic verbatim would widen every port range by one at
 *    each end -- a silent firewall hole. See pf_port_spec().
 *
 * 3. RULE GROUPS.  ipf 'head N' / 'group N' scopes a block of rules behind a
 *    head rule. Every head here is 'block in quick on <if> all', so the group
 *    means nothing more than "these rules apply to traffic in on <if>".
 *    pf has no groups; 'on <if>' plus the closing 'block all' expresses the
 *    same thing, so groups are dropped rather than emulated with anchors.
 *
 * 4. 'skip N'.  ipf can jump N rules forward. pf cannot. The two uses here
 *    (the TCP-flags preamble and the static-route spoofcheck) are rewritten
 *    as ordinary ordered pass/block rules.
 *
 * 5. 'with short' / 'with ipopts'.  pf handles both through normalisation and
 *    defaults: 'scrub' drops malformed short packets, and pf blocks IP options
 *    unless a rule says 'allow-opts'. Both ipf rules therefore disappear.
 *
 * 6. 'keep state' / 'keep frags'.  pf keeps state on pass rules by default,
 *    and fragment handling belongs in 'scrub ... fragment reassemble' rather
 *    than per-rule. Kept explicit where it aids readability.
 *
 * 7. NAT TARGETS.  ipnat spells "this interface's address" as '0/32'. pf
 *    spells it '($if)', with the parentheses meaning "re-read the address if
 *    it changes" -- which m0n0wall needs on a DHCP or PPPoE WAN.
 *
 * 8. PROTOCOL LISTS.  ipf accepts 'proto tcp/udp'. pf requires a list,
 *    'proto { tcp udp }'.
 *
 * 9. FTP PROXY.  ipnat has one built in ('proxy port 21 ftp/tcp'). pf does
 *    not; it needs the separate ftp-proxy(8) daemon plus an anchor. That is a
 *    feature port, not a translation, and is deliberately left for its own
 *    change -- pf_nat_rules_generate() emits the anchor placeholder and notes
 *    it.
 *
 * Anything marked XXX-VERIFY below needs checking against a live pfctl on
 * FreeBSD; it cannot be settled by reading the manual alone.
 * ===========================================================================
 */

/* Return a pf port specification for an m0n0wall "port" or "lo-hi" string.
 *
 * ipf needed exclusive-range arithmetic; pf does not. Getting this wrong
 * widens every range by one port at each end, so it is unit-tested.
 */
function pf_port_spec($portstr) {
	if ($portstr === "" || $portstr === null)
		return "";

	$p = explode("-", $portstr);
	$lo = $p[0];
	$hi = isset($p[1]) ? $p[1] : "";

	if ($hi === "" || $lo == $hi)
		return "port " . $lo;
	if ($lo == 1 && $hi == 65535)
		return "";                       /* every port: say nothing */
	if ($hi == 65535)
		return "port >= " . $lo;
	if ($lo == 1)
		return "port <= " . $hi;

	/* pf ranges are inclusive -- no +/-1 fudge, unlike ipf's '><' */
	return "port " . $lo . ":" . $hi;
}

/* Translate an m0n0wall protocol token into a pf 'proto' clause. */
function pf_proto_spec($proto) {
	if (!$proto || $proto == "any")
		return "";
	if ($proto == "tcp/udp")
		return "proto { tcp udp }";      /* pf has no 'tcp/udp' token */
	return "proto " . $proto;
}

/* pf address token, honouring m0n0wall's "not" flag. */
function pf_addr_spec($addr, $not = false) {
	if ($addr === "any" || $addr === "" || $addr === null)
		$a = "any";
	else
		$a = $addr;
	return ($not ? "! " : "") . $a;
}

/* Collapse repeated whitespace so generated rules compare cleanly in tests. */
function pf_tidy($line) {
	return trim(preg_replace('/[ \t]+/', ' ', $line));
}

/* ---------------------------------------------------------------------------
 * Translation rules (binat / nat / rdr)
 *
 * pf evaluates these FIRST-match, in the order binat, then rdr for inbound and
 * nat for outbound. ipnat is also first-match, so m0n0wall's deliberate rule
 * ordering carries over unchanged.
 * ------------------------------------------------------------------------ */

/* One outbound NAT mapping. Mirrors filter_nat_rules_generate_if().
 *
 * ipnat emitted up to three rules per mapping: an ftp proxy rule, a portmap
 * rule and a plain ip rule, ordered so that port randomisation is either
 * always on or only on collision. pf expresses the whole thing in one rule:
 * 'port lo:hi' randomises, its absence does not.
 */
function pf_nat_rule_generate_if($if, $src, $dst, $target, $portmap = true) {
	global $config;

	$tgt = $target ? $target : "($if)";   /* ipnat's '0/32' == pf's '($if)' */

	$from = "from " . ($src !== "" ? $src : "any");
	$to   = "to "   . ($dst !== "" ? $dst : "any");

	$rangelow  = 1024;
	$rangehigh = 64535;
	if (!empty($config['nat']['portrange-low']) && !empty($config['nat']['portrange-high'])) {
		$rangelow  = $config['nat']['portrange-low'];
		$rangehigh = $config['nat']['portrange-high'];
	}

	if ($portmap) {
		/* static-port off: let pf rewrite the source port from the pool */
		return pf_tidy("nat on $if $from $to -> $tgt port $rangelow:$rangehigh") . "\n";
	}
	/* 'Disable port mapping' in the GUI: preserve the source port */
	return pf_tidy("nat on $if $from $to -> $tgt static-port") . "\n";
}

function pf_nat_rules_generate() {
	global $config, $g;

	$wancfg = $config['interfaces']['wan'];
	$lancfg = $config['interfaces']['lan'];
	$pptpdcfg = $config['pptpd'];
	$wanif = get_real_wan_interface();
	$lansa = gen_subnet($lancfg['ipaddr'], $lancfg['subnet']);

	$rules = "";

	/* --- binat: 1:1 mappings. Must precede nat/rdr, and pf enforces that. */
	if (isset($config['nat']['onetoone']) && is_array($config['nat']['onetoone'])) {
		foreach ($config['nat']['onetoone'] as $natent) {
			$sn = is_numeric($natent['subnet']) ? $natent['subnet'] : 32;
			if (empty($natent['interface']) || $natent['interface'] == "wan")
				$natif = $wanif;
			else
				$natif = $config['interfaces'][$natent['interface']]['if'];

			$rules .= pf_tidy("binat on $natif from {$natent['internal']}/{$sn} " .
			                  "to any -> {$natent['external']}/{$sn}") . "\n";
		}
	}

	/* --- rdr: inbound port forwards. These must come before nat so that
	 *     redirected traffic is not first consumed by an outbound mapping. */
	if (isset($config['nat']['rule']) && is_array($config['nat']['rule'])) {
		foreach ($config['nat']['rule'] as $rule) {
			$target = alias_expand_host($rule['target']);
			if (!$target)
				continue;                   /* unresolvable alias */

			if (!empty($rule['external-address'])) {
				$extaddr = ($rule['external-address'] == 'wan')
					? get_current_wan_address(false) : $rule['external-address'];
			} else {
				$extaddr = "any";
			}

			if (empty($rule['interface']) || $rule['interface'] == "wan")
				$natif = $wanif;
			else
				$natif = $config['interfaces'][$rule['interface']]['if'];

			$proto = pf_proto_spec($rule['protocol']);
			$eport = pf_port_spec($rule['external-port']);
			$lport = !empty($rule['local-port']) ? "port {$rule['local-port']}" : "";

			$rules .= pf_tidy("rdr on $natif $proto from any to $extaddr $eport " .
			                  "-> $target $lport") . "\n";
		}
	}

	/* --- nat: outbound. Advanced (per-rule) or standard (per-interface). */
	if (!empty($config['nat']['advancedoutbound']['enable'])) {
		if (is_array($config['nat']['advancedoutbound']['rule'])) {
			foreach ($config['nat']['advancedoutbound']['rule'] as $obent) {
				$src = $obent['source']['network'];
				$dst = "";
				if (!isset($obent['destination']['any'])) {
					$dst = (isset($obent['destination']['not']) ? "! " : "")
					     . $obent['destination']['network'];
				}
				if (empty($obent['interface']) || $obent['interface'] == "wan")
					$natif = $wanif;
				else
					$natif = $config['interfaces'][$obent['interface']]['if'];

				$rules .= pf_nat_rule_generate_if($natif, $src, $dst,
					$obent['target'], !isset($obent['noportmap']));
			}
		}
	} else {
		$rules .= pf_nat_rule_generate_if($wanif,
			$lansa . "/" . $lancfg['subnet'], "", null);

		for ($i = 1; isset($config['interfaces']['opt' . $i]); $i++) {
			$optcfg = $config['interfaces']['opt' . $i];
			if (isset($optcfg['enable']) && !$optcfg['bridge']) {
				$optsa = gen_subnet($optcfg['ipaddr'], $optcfg['subnet']);
				$rules .= pf_nat_rule_generate_if($wanif,
					$optsa . "/" . $optcfg['subnet'], "", null);
			}
		}

		if (isset($config['staticroutes']['route']) && is_array($config['staticroutes']['route'])) {
			foreach ($config['staticroutes']['route'] as $route) {
				if ($route['interface'] != "wan")
					$rules .= pf_nat_rule_generate_if($wanif, $route['network'], "", null);
			}
		}
	}

	/* FTP: ipnat had a built-in proxy ('proxy port 21 ftp/tcp'). pf does not.
	 * The equivalent is the ftp-proxy(8) daemon redirecting into this anchor.
	 * Emitting the anchor now keeps the ruleset shape stable; wiring the
	 * daemon is a separate change. */
	$rules .= "\n# ftp-proxy(8) hooks in here -- pf has no built-in FTP proxy\n";
	$rules .= "anchor \"ftp-proxy/*\"\n";

	return $rules;
}

/* ---------------------------------------------------------------------------
 * Filter rules
 * ------------------------------------------------------------------------ */

/* Options and normalisation. pf demands a strict section order:
 * options, normalisation, queueing, translation, filtering.
 */
function pf_options_generate() {
	global $config;

	$out  = "# ---- options ----\n";
	/* 'drop' matches ipf's silent discard; m0n0wall's reject rules ask for a
	   response explicitly, per rule. */
	$out .= "set block-policy drop\n";
	$out .= "set skip on lo0\n";          /* replaces the two explicit lo0 passes */
	$out .= "set optimization normal\n";

	if (!empty($config['filter']['tcpidletimeout'])) {
		$t = $config['filter']['tcpidletimeout'] * 2;
		$out .= "set timeout tcp.established $t\n";
	}

	$out .= "\n# ---- normalisation ----\n";
	/* Replaces ipf's 'block in all with short' and the per-rule 'keep frags'. */
	$out .= "scrub in all fragment reassemble\n";
	/* pf drops IP options unless a rule says allow-opts, so ipf's
	   'block in all with ipopts' needs no equivalent. */
	return $out;
}

/* The per-interface base rules: DHCP, anti-spoof, private-network blocking.
 * ipf expressed the per-interface default-deny with 'head'/'group'; in pf the
 * closing 'block all' plus 'on <if>' scoping says the same thing.
 */
function pf_base_rules_generate($lanif, $wanif, $lanip, $lansa, $lansn, $optcfg, $log) {
	global $config;

	$out  = "\n# ---- base rules ----\n";

	$out .= "\n# DHCP server on LAN\n";
	$out .= "pass in quick on $lanif proto udp from any port 68 to 255.255.255.255 port 67\n";
	$out .= "pass in quick on $lanif proto udp from any port 68 to $lanip port 67\n";
	$out .= "pass out quick on $lanif proto udp from $lanip port 67 to any port 68\n";

	foreach ($optcfg as $on => $oc) {
		if (((isset($config['dhcpd'][$on]['enable']) || isset($config['dhcrelay'][$on]['enable'])) && !$oc['bridge']) ||
		    ($oc['bridge'] && (isset($config['dhcpd'][$oc['bridge_if']]['enable']) || isset($config['dhcrelay'][$oc['bridge_if']]['enable'])))) {
			$out .= "\n# DHCP server on $on\n";
			$out .= "pass in quick on {$oc['if']} proto udp from any port 68 to 255.255.255.255 port 67\n";
			$out .= "pass in quick on {$oc['if']} proto udp from any port 68 to {$oc['ip']} port 67\n";
			$out .= "pass out quick on {$oc['if']} proto udp from {$oc['ip']} port 67 to any port 68\n";
		}
	}

	$out .= "\n# WAN spoof check\n";
	$out .= "block in $log quick on $wanif from $lansa/$lansn to any\n";
	foreach ($optcfg as $oc) {
		if (!$oc['bridge'])
			$out .= "block in $log quick on $wanif from {$oc['sa']}/{$oc['sn']} to any\n";
	}

	$out .= "\n# our DHCP client out to the WAN\n";
	$out .= "pass out quick on $wanif proto udp from any port 68 to any port 67\n";
	$out .= "block in $log quick on $wanif proto udp from any port 67 to $lansa/$lansn port 68\n";
	$out .= "pass in quick on $wanif proto udp from any port 67 to any port 68\n";

	if (isset($config['interfaces']['wan']['blockpriv'])) {
		$out .= "\n# block private networks on WAN\n";
		/* pf tables beat four separate rules: one lookup, and it reads better
		   in pfctl -sr output. */
		$out .= "table <priv> const { 10.0.0.0/8, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }\n";
		$out .= "block in $log quick on $wanif from <priv> to any\n";
	}

	return $out;
}

/* LAN/OPT anti-spoof.
 *
 * ipf used 'skip N' to jump over the block when the source matched a statically
 * routed network. pf has no skip, so the same intent is expressed directly:
 * pass the legitimate sources first (quick), then block the rest.
 */
function pf_spoofcheck_generate($ifname, $if, $sa, $sn, $log, $ipv6 = false) {
	global $config;

	$out = "";
	$strtconf = 'route' . ($ipv6 ? '6' : '');

	if (is_array($config['staticroutes'][$strtconf]) && count($config['staticroutes'][$strtconf])) {
		foreach ($config['staticroutes'][$strtconf] as $route) {
			if ($route['interface'] == $ifname)
				$out .= "pass in quick on $if from {$route['network']} to any\n";
		}
		$out .= "pass in quick on $if from $sa/$sn to any\n";
		$out .= "block in $log quick on $if all\n";
	} else {
		$out .= "block in $log quick on $if from ! $sa/$sn to any\n";
	}
	return $out;
}

/* IKE / ESP / AH, unchanged in meaning from filter_rules_ipsec_generate(). */
function pf_ipsec_rules_generate($ifname, $ip) {
	$out  = "\n# IPsec: IKE, NAT-T, ESP, AH\n";
	$out .= "pass in quick on $ifname proto udp from any to $ip port { 500 4500 }\n";
	$out .= "pass out quick on $ifname proto udp from $ip port { 500 4500 } to any\n";
	$out .= "pass in quick on $ifname proto { esp ah } from any to $ip\n";
	$out .= "pass out quick on $ifname proto { esp ah } from $ip to any\n";
	return $out;
}

/* ---------------------------------------------------------------------------
 * User-defined rules
 * ------------------------------------------------------------------------ */

/* Resolve one of m0n0wall's symbolic network tokens ("lan", "wanip", "opt1",
 * "pptp", "l2tp") to a literal pf address. Returns null when unresolvable, so
 * the caller can drop the rule rather than emit a broken one.
 *
 * NOTE: filter.inc had a genuine bug here -- in the destination branch the
 * 'l2tp' case assigned $src instead of $dst, which left $dst empty and made
 * the whole rule be dropped silently. Fixed there; this shares one code path
 * for both directions so it cannot recur.
 */
function pf_resolve_network($token, $ctx) {
	if ($token === "" || $token === null)
		return null;

	if (strstr($token, "opt")) {
		if (!isset($ctx['optcfg'][$token]))
			return null;
		return $ctx['optcfg'][$token]['sa'] . "/" . $ctx['optcfg'][$token]['sn'];
	}

	switch ($token) {
		case 'wanip': return $ctx['curwanip'];
		case 'lan':   return $ctx['lansa'] . "/" . $ctx['lansn'];
		case 'pptp':  return isset($ctx['pptpsa']) ? $ctx['pptpsa'] . "/" . $ctx['pptpsn'] : null;
		case 'l2tp':  return isset($ctx['l2tpsa']) ? $ctx['l2tpsa'] . "/" . $ctx['l2tpsn'] : null;
	}
	return null;
}

/* Resolve one side (source or destination) of a rule to a pf address token. */
function pf_rule_endpoint($side, $ctx) {
	if (isset($side['any']))
		return "any";
	if (!empty($side['network']))
		return pf_resolve_network($side['network'], $ctx);
	if (!empty($side['address']))
		return alias_expand($side['address']);
	return null;
}

/* Translate one m0n0wall filter rule into a pf rule line.
 *
 * Returns "" when the rule should not be emitted (disabled, unresolvable
 * alias, interface not present), matching filter.inc's 'continue' cases.
 *
 * $iface is the pf interface the rule binds to. For the pptp/l2tp/ipsec
 * pseudo-interfaces the caller loops and supplies ng0, l2tp0, enc0 and so on,
 * exactly as filter.inc did.
 */
function pf_user_rule_generate($rule, $ctx, $iface) {
	if (isset($rule['disabled']))
		return "";

	$type = isset($rule['type']) ? $rule['type'] : "pass";
	if ($type != "pass" && $type != "block" && $type != "reject")
		$type = "pass";                 /* default for pre-1.3 rules */

	/* action. pf spells the reject responses the same way ipf did. */
	if ($type == "reject") {
		if ($rule['protocol'] == "tcp")
			$line = "block return-rst";
		else if ($rule['protocol'] == "udp")
			$line = "block return-icmp(port-unr)";
		else
			$line = "block";
	} else {
		$line = $type;
	}

	$line .= " in";
	if (isset($rule['log']))
		$line .= " log";
	$line .= " quick";

	if ($iface)
		$line .= " on $iface";

	$proto = pf_proto_spec(isset($rule['protocol']) ? $rule['protocol'] : "");
	if ($proto !== "")
		$line .= " " . $proto;

	/* source */
	$src = pf_rule_endpoint($rule['source'], $ctx);
	if ($src === null || $src === "" || $src === "/")
		return "";
	$line .= " from " . pf_addr_spec($src, isset($rule['source']['not']));

	$portproto = array("tcp", "udp", "tcp/udp");
	if (in_array($rule['protocol'], $portproto) && !empty($rule['source']['port'])) {
		$ps = pf_port_spec($rule['source']['port']);
		if ($ps !== "") $line .= " " . $ps;
	}

	/* destination */
	$dst = pf_rule_endpoint($rule['destination'], $ctx);
	if ($dst === null || $dst === "" || $dst === "/")
		return "";
	$line .= " to " . pf_addr_spec($dst, isset($rule['destination']['not']));

	if (in_array($rule['protocol'], $portproto) && !empty($rule['destination']['port'])) {
		$ps = pf_port_spec($rule['destination']['port']);
		if ($ps !== "") $line .= " " . $ps;
	}

	if (($rule['protocol'] == "icmp" || $rule['protocol'] == "ipv6-icmp")
	    && !empty($rule['icmptype']))
		$line .= " icmp-type {$rule['icmptype']}";

	/* pf keeps state on pass rules by default, but say so explicitly: it
	   documents intent and survives a future change to the default. */
	if ($type == "pass")
		$line .= " keep state";

	/* ipf needed 'flags S/SA' to make return-rst fire only on a SYN. pf's
	   return-rst already applies to the connection attempt, but stating the
	   flags keeps behaviour identical rather than merely equivalent. */
	if ($type == "reject" && $rule['protocol'] == "tcp")
		$line .= " flags S/SA";

	return pf_tidy($line) . "\n";
}
