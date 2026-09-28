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

/* geoip.inc provides the country tables pf_tables_generate() declares and the
   <geo_XX> names pf_rule_endpoint() emits. Required here rather than left to
   functions.inc's ordering: this file was once loaded only by the tests
   because nothing required it, and a dependency that works by luck of load
   order is the same mistake one level down. */
require_once("geoip.inc");

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

			/* The external address, with the dynamic-WAN case handled.
			
			   'wan' means "whatever address the WAN currently has", and
			   get_current_wan_address() returns NULL on a DHCP, PPPoE, PPTP or
			   modem WAN that has no address yet -- at boot, before the lease, or
			   whenever the link is down. That null used to be interpolated
			   straight into the rdr line below, producing
			
			       rdr on em0 proto tcp from any to port 8080 -> 10.0.0.5 port 80
			
			   which pfctl rejects. pfctl rejects the FILE, not the line, so a
			   single port forward on a dynamic WAN meant the firewall booted with
			   NO RULESET AT ALL. Using the interface name instead is both correct
			   and better than the original: pf resolves '(em0)' at match time, so
			   the rule keeps working across a lease change without a reload.
			
			   pf needs the parentheses for that -- a bare interface name is
			   expanded once when the ruleset loads. */
			if (!empty($rule['external-address'])) {
				$extaddr = ($rule['external-address'] == 'wan')
					? "(" . get_real_wan_interface(false) . ":0)"
					: $rule['external-address'];
			} else {
				$extaddr = "any";
			}

			if (empty($rule['interface']) || $rule['interface'] == "wan")
				$natif = $wanif;
			else
				$natif = $config['interfaces'][$rule['interface']]['if'];

			$proto = pf_proto_spec($rule['protocol']);
			$eport = pf_port_spec($rule['external-port']);

			/* A port RANGE has to be mapped sequentially, not collapsed.
			   'rdr ... port 8000:8010 -> 10.0.0.5 port 8000' would send the
			   whole range to the single port 8000; pf spells the sequential
			   form 'port 8000:*', which walks the target ports up in step with
			   the matched ones. ipfilter did this implicitly with its
			   'port = x -> y' range syntax, so the behaviour is restored, not
			   invented. */
			$lport = "";
			if (!empty($rule['local-port'])) {
				$lport = "port {$rule['local-port']}";
				$ep = explode("-", $rule['external-port']);
				if (isset($ep[1]) && $ep[1] !== "" && $ep[0] != $ep[1])
					$lport .= ":*";
			}

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

		/* opt_interfaces(), not a loop counting up from opt1: deleting an
		   optional interface no longer renumbers the ones above it, so the
		   numbering can have gaps and a counting loop stops at the first one.
		   See util.inc. */
		foreach (opt_interfaces() as $optif) {
			$optcfg = $config['interfaces'][$optif];
			if (isset($optcfg['enable']) && empty($optcfg['bridge'])) {
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

	/* Country tables are large: one country runs to tens of thousands of
	   prefixes and pf's default limit is 200000 entries for ALL tables
	   together, so a couple of countries can exhaust it and pfctl then
	   rejects the whole rule set. Raised only when a rule actually uses a
	   country, so a firewall that does not runs with the stock limit. */
	if (count(geoip_countries_in_use()) > 0)
		$out .= "set limit table-entries 1000000\n";

	if (!empty($config['filter']['tcpidletimeout'])) {
		/* No *2 here. ipfilter's net.inet.ipf.fr_tcpidletimeout was in
		   half-second ticks, so filter.inc doubled the GUI's seconds to get
		   ticks. pf's 'set timeout tcp.established' is already in SECONDS --
		   carrying the doubling over silently gave every install twice the
		   idle timeout the GUI showed. */
		$t = (int) $config['filter']['tcpidletimeout'];
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
		if (((isset($config['dhcpd'][$on]['enable']) || isset($config['dhcrelay'][$on]['enable'])) && empty($oc['bridge'])) ||
		    (!empty($oc['bridge']) && (isset($config['dhcpd'][$oc['bridge_if']]['enable']) || isset($config['dhcrelay'][$oc['bridge_if']]['enable'])))) {
			$out .= "\n# DHCP server on $on\n";
			$out .= "pass in quick on {$oc['if']} proto udp from any port 68 to 255.255.255.255 port 67\n";
			$out .= "pass in quick on {$oc['if']} proto udp from any port 68 to {$oc['ip']} port 67\n";
			$out .= "pass out quick on {$oc['if']} proto udp from {$oc['ip']} port 67 to any port 68\n";
		}
	}

	$out .= "\n# WAN spoof check\n";
	$out .= "block in $log quick on $wanif from $lansa/$lansn to any\n";
	foreach ($optcfg as $oc) {
		if (empty($oc['bridge']) && $oc['sa'] !== "")
			$out .= "block in $log quick on $wanif from {$oc['sa']}/{$oc['sn']} to any\n";
	}

	$out .= "\n# our DHCP client out to the WAN\n";
	$out .= "pass out quick on $wanif proto udp from any port 68 to any port 67\n";
	$out .= "block in $log quick on $wanif proto udp from any port 67 to $lansa/$lansn port 68\n";
	$out .= "pass in quick on $wanif proto udp from any port 67 to any port 68\n";

	if (isset($config['interfaces']['wan']['blockpriv'])) {
		/* The <priv> table itself is declared in the tables section -- pf.conf
		   has a strict section order and a table declared here is a parse
		   error. See pf_tables_generate(). */
		$out .= "\n# block private networks on WAN\n";
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
/* The source networks that may legitimately arrive on one interface: its own
 * prefix plus every static route (of the same family) pointing out of it. */
function pf_spoof_networks($ifname, $sa, $sn, $ipv6) {
	global $config;

	$nets = array("$sa/$sn");
	$strtconf = 'route' . ($ipv6 ? '6' : '');
	if (!empty($config['staticroutes'][$strtconf]) && is_array($config['staticroutes'][$strtconf])) {
		foreach ($config['staticroutes'][$strtconf] as $route) {
			if (($route['interface'] ?? '') == $ifname && !empty($route['network']))
				$nets[] = $route['network'];
		}
	}
	return $nets;
}

function pf_spoof_table_name($ifname, $ipv6) {
	return "spoof_" . $ifname . ($ipv6 ? "6" : "");
}

/* The table a spoof check needs, or "" when a single prefix says it all.
 * Emitted in the tables section -- pf.conf rejects a table declared among
 * the filter rules. */
function pf_spoof_table_generate($ifname, $sa, $sn, $ipv6) {
	$nets = pf_spoof_networks($ifname, $sa, $sn, $ipv6);
	if (count($nets) < 2)
		return "";
	return "table <" . pf_spoof_table_name($ifname, $ipv6) . "> const { " .
	       implode(", ", $nets) . " }\n";
}

/* Block anything arriving on $if from outside the networks that belong there.
 *
 * The allowed set is the interface's prefix plus its static routes. With
 * routes, this used to emit "pass in quick ... from <net> to any" for each
 * network and then "block ... all" -- and in pf a quick PASS ends evaluation,
 * so every packet from LAN was passed before a single user rule was read. Any
 * static route on an interface silently disabled every block rule written for
 * it. The set is now a table and the check is one negated block, which passes
 * nothing and leaves the decision to the user's rules.
 *
 * Every rule names its address family: an unqualified rule here applies to
 * both, so a v6 check could otherwise block IPv4. */
function pf_spoofcheck_generate($ifname, $if, $sa, $sn, $log, $ipv6 = false) {
	$af = $ipv6 ? "inet6" : "inet";
	$out = "";

	/* Link-local sources are legitimate on any IPv6 link and never inside
	   the prefix: multicast listener reports, DHCPv6 solicits and the like go
	   fe80:: -> ff02::. Unicast link-local and neighbour discovery are passed
	   by the IPv6 base rules; this covers link-scope multicast, which would
	   otherwise be blocked -- and logged, for every host, continuously. Link
	   scope is never forwarded, so it opens nothing. */
	if ($ipv6)
		$out .= "pass in quick on $if inet6 from fe80::/10 to ff02::/16\n";

	$nets = pf_spoof_networks($ifname, $sa, $sn, $ipv6);
	$src = (count($nets) < 2) ? $nets[0] : "<" . pf_spoof_table_name($ifname, $ipv6) . ">";
	$out .= "block in $log quick on $if $af from ! $src to any\n";
	return $out;
}

/* The wg interfaces that wg_configure() will actually have brought up. Same
 * enable/disable test as wireguard.inc, so the ruleset cannot disagree with
 * the interfaces that exist. */
function pf_wg_interfaces() {
	global $config;

	$ifs = array();
	if (!isset($config['wireguard']['tunnel']) || !is_array($config['wireguard']['tunnel']))
		return $ifs;
	foreach ($config['wireguard']['tunnel'] as $t) {
		if (isset($t['disabled']) || empty($t['if']))
			continue;
		$ifs[] = $t['if'];
	}
	return $ifs;
}

/* Has the admin written any rule bound to a WireGuard interface? */
function pf_wg_has_user_rules() {
	global $config;

	foreach (array('rule', 'rule6') as $k) {
		if (!isset($config['filter'][$k]) || !is_array($config['filter'][$k]))
			continue;
		foreach ($config['filter'][$k] as $r) {
			if (isset($r['disabled']))
				continue;
			if (isset($r['interface']) && substr($r['interface'], 0, 2) === "wg")
				return true;
		}
	}
	return false;
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
		case 'pptp':  return null;        /* PPTP removed from this port */
		case 'l2tp':  return isset($ctx['l2tpsa']) ? $ctx['l2tpsa'] . "/" . $ctx['l2tpsn'] : null;
	}
	return null;
}

/* Resolve one side (source or destination) of a rule to a pf address token. */
function pf_rule_endpoint($side, $ctx) {
	if (isset($side['any']))
		return "any";
	/* Country before the rest: a rule may name several, and pf takes a list
	   of tables inside braces, so "from { <geo_CN>, <geo_RU> }" is one rule
	   rather than one rule per country. */
	if (!empty($side['country'])) {
		/* Fail closed, if asked. An empty table matches nothing, so a block
		   rule over a country with no data silently carries the traffic it
		   was meant to stop. Widening it to "any" blocks everything the rest
		   of the rule matches until a refresh succeeds. Only the caller knows
		   whether this rule blocks or passes, so it passes that in via
		   $side['_failclosed'], set by pf_user_rule_generate(). */
		if (!empty($side['_failclosed']) && geoip_list_has_empty($side['country']))
			return "any";
		$tbls = array();
		foreach (explode(',', $side['country']) as $cc) {
			$cc = trim($cc);
			if (is_country_code($cc))
				$tbls[] = "<" . geoip_table_name($cc) . ">";
		}
		if (empty($tbls))
			return null;
		return (count($tbls) == 1) ? $tbls[0] : "{ " . implode(", ", $tbls) . " }";
	}
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
/* ipfilter and pf do not agree on three ICMP type names, and pfctl rejects the
 * WHOLE ruleset when it meets one it does not know -- so a single rule saying
 * "Echo" left the firewall with no rules at all, which is how this was found.
 *
 *   ipf 'echo'      -> pf 'echoreq'
 *   ipf 'timest'    -> pf 'timereq'
 *   ipf 'timestrep' -> pf 'timerep'
 *
 * The other eleven names are spelled identically in both. Configs saved by the
 * old GUI (and any restored 1.8 config.xml) still hold the ipf spellings, so
 * translating here rather than only fixing the GUI keeps them loadable. A name
 * pf still does not know returns null and the qualifier is dropped -- broader
 * than asked, but the alternative is a firewall that loads nothing.
 */
function pf_icmptype_v4($t) {
	static $legacy = array(
		'echo'      => 'echoreq',
		'timest'    => 'timereq',
		'timestrep' => 'timerep',
	);
	static $known = array(
		'echoreq', 'echorep', 'unreach', 'squench', 'redir', 'timex',
		'paramprob', 'timereq', 'timerep', 'inforeq', 'inforep',
		'maskreq', 'maskrep', 'althost', 'routeradv', 'routersol',
		'trace', 'dataconv', 'mobredir', 'skip', 'photuris',
	);

	$t = trim($t);
	if (isset($legacy[$t]))
		$t = $legacy[$t];
	if (is_numeric($t))
		return $t;
	if (in_array($t, $known))
		return $t;

	log_error("pf: dropping unknown ICMP type '$t' from a rule; " .
	          "pfctl would reject the entire ruleset.");
	return null;
}

function pf_user_rule_generate($rule, $ctx, $iface, $af = "") {
	if (isset($rule['disabled']))
		return "";

	$type = isset($rule['type']) ? $rule['type'] : "pass";
	if ($type != "pass" && $type != "block" && $type != "reject")
		$type = "pass";                 /* default for pre-1.3 rules */

	$ruleproto = isset($rule['protocol']) ? $rule['protocol'] : "";

	/* action. pf spells the reject responses the same way ipf did. */
	if ($type == "reject") {
		if ($ruleproto == "tcp")
			$line = "block return-rst";
		else if ($ruleproto == "udp")
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

	/* 'inet' / 'inet6'. ipf kept two separate rulesets; pf filters both
	   families from one, so the family is stated per rule instead. It
	   matters for rules that say "any", which would otherwise match both. */
	if ($af !== "")
		$line .= " " . $af;

	$proto = pf_proto_spec($ruleproto);
	if ($proto !== "")
		$line .= " " . $proto;

	/* Fail-closed applies only to rules that BLOCK: an empty country table
	   passes nothing, so a pass rule is already closed. Signalled through the
	   side array because pf_rule_endpoint() is shared with the NAT and shaper
	   paths and has no idea what action it is serving. */
	$failclosed = ($type != "pass") && geoip_fail_closed();

	/* source */
	$srcside = $rule['source'];
	if ($failclosed) $srcside['_failclosed'] = true;
	$src = pf_rule_endpoint($srcside, $ctx);
	if ($src === null || $src === "" || $src === "/")
		return "";
	$line .= " from " . pf_addr_spec($src, isset($rule['source']['not']));

	$portproto = array("tcp", "udp", "tcp/udp");
	if (in_array($ruleproto, $portproto) && !empty($rule['source']['port'])) {
		$ps = pf_port_spec($rule['source']['port']);
		if ($ps !== "") $line .= " " . $ps;
	}

	/* destination */
	$dstside = $rule['destination'];
	if ($failclosed) $dstside['_failclosed'] = true;
	$dst = pf_rule_endpoint($dstside, $ctx);
	if ($dst === null || $dst === "" || $dst === "/")
		return "";
	$line .= " to " . pf_addr_spec($dst, isset($rule['destination']['not']));

	if (in_array($ruleproto, $portproto) && !empty($rule['destination']['port'])) {
		$ps = pf_port_spec($rule['destination']['port']);
		if ($ps !== "") $line .= " " . $ps;
	}

	if (($ruleproto == "icmp" || $ruleproto == "ipv6-icmp")
	    && !empty($rule['icmptype'])) {
		/* ICMPv6 has its own keyword in pf, and its types are numeric. */
		if ($ruleproto == "ipv6-icmp")
			$line .= " icmp6-type {$rule['icmptype']}";
		else {
			$t = pf_icmptype_v4($rule['icmptype']);
			if ($t !== null)
				$line .= " icmp-type $t";
		}
	}

	/* pf keeps state on pass rules by default, but say so explicitly: it
	   documents intent and survives a future change to the default. */
	if ($type == "pass")
		$line .= " keep state";

	/* ipf needed 'flags S/SA' to make return-rst fire only on a SYN. pf's
	   return-rst already applies to the connection attempt, but stating the
	   flags keeps behaviour identical rather than merely equivalent. */
	if ($type == "reject" && $ruleproto == "tcp")
		$line .= " flags S/SA";

	return pf_tidy($line) . "\n";
}

/* ---------------------------------------------------------------------------
 * Assembly
 *
 * pf.conf sections must appear in this order, or pfctl refuses the file:
 *   macros -> tables -> options -> normalisation -> queueing -> translation
 *   -> filtering
 * Everything below exists to honour that.
 * ------------------------------------------------------------------------ */

function pf_tables_generate() {
	global $config;

	$out = "";
	if (isset($config['interfaces']['wan']['blockpriv'])) {
		/* One table lookup instead of four rules, and it reads better in
		   'pfctl -sr' output. RFC1918 plus loopback, matching what filter.inc
		   blocked. */
		$out .= "table <priv> const { 10.0.0.0/8, 127.0.0.0/8, " .
		        "172.16.0.0/12, 192.168.0.0/16 }\n";
	}

	/* One table per country any rule refers to. Declared even when the file is
	   missing -- 'persist' keeps an empty table alive, so the rule set always
	   loads and the rule simply matches nothing until geoip_update() has run.
	   See the header of geoip.inc: this fails open on purpose, and the GeoIP
	   status page is where you confirm the tables are actually populated. */
	foreach (geoip_countries_in_use() as $cc) {
		$tbl  = geoip_table_name($cc);
		$file = geoip_file($cc);
		if (file_exists($file))
			$out .= "table <{$tbl}> persist file \"{$file}\"\n";
		else
			$out .= "table <{$tbl}> persist\t# no data yet: matches nothing\n";
	}

	return $out;
}

/* Build the interface context the rule generators need. Mirrors the setup at
 * the top of filter_rules_generate(). */
function pf_build_context($ipv6 = false) {
	global $config;

	$lancfg = $config['interfaces']['lan'];
	$ctx = array();
	$ctx['ipv6']     = $ipv6;
	$ctx['lanif']    = $lancfg['if'];
	$ctx['wanif']    = get_real_wan_interface($ipv6);
	$ctx['curwanip'] = get_current_wan_address($ipv6);
	/* ?? '': an interface configured for IPv4 only has no ipaddr6/subnet6 at
	   all, which is the normal case on a dual-stack-capable build. Reading them
	   bare warned on every IPv6 ruleset build. */
	$ctx['lanip']    = $lancfg[$ipv6 ? 'ipaddr6' : 'ipaddr'] ?? '';
	$ctx['lansn']    = $lancfg[$ipv6 ? 'subnet6' : 'subnet'] ?? '';
	$ctx['lansa']    = $ipv6 ? gen_subnet6($ctx['lanip'], $ctx['lansn'])
	                         : gen_subnet($ctx['lanip'], $ctx['lansn']);

	$ctx['optcfg'] = array();
	foreach (opt_interfaces() as $optif) {
		$oc = $config['interfaces'][$optif];
		if (!isset($oc['enable']) || empty($oc['if']))
			continue;
		/* Every key the consumers read is initialised, so a plain
		   $oc['bridge'] / $oc['sa'] test cannot raise "Undefined array key".
		   Those warnings printed into the Apply-changes page and onto the boot
		   console for any ordinary config that had an OPT interface. */
		$oic = array('if' => $oc['if'], 'bridge' => 0, 'bridge_if' => '',
		             'ip' => '', 'sn' => '', 'sa' => '');
		if (!empty($oc['bridge'])) {
			$oic['bridge'] = 1;
			$oic['bridge_if'] = $oc['bridge'];
		} else {
			/* same as the LAN above: an OPT interface with only IPv4 has no
			   ipaddr6, and it is skipped two lines down anyway */
			$oic['ip'] = $oc[$ipv6 ? 'ipaddr6' : 'ipaddr'] ?? '';
			$oic['sn'] = $oc[$ipv6 ? 'subnet6' : 'subnet'] ?? '';
			if (empty($oic['ip']))
				continue;
			$oic['sa'] = $ipv6 ? gen_subnet6($oic['ip'], $oic['sn'])
			                   : gen_subnet($oic['ip'], $oic['sn']);
		}
		$ctx['optcfg'][$optif] = $oic;
	}

	/* No pptpsa/pptpsn: PPTP is removed, and pf_resolve_network() answers null
	   for the 'pptp' token so a restored config's pptp rules are skipped. */
	if (isset($config['l2tp']['mode']) && $config['l2tp']['mode'] == "server" && !$ipv6) {
		$ctx['l2tpsa'] = $config['l2tp']['remoteip'];
		$ctx['l2tpsn'] = subnet_size_to_cidr(!empty($config['l2tp']['nunits'])
		                   ? $config['l2tp']['nunits'] : 16);
	}

	return $ctx;
}

/* The whole ruleset. */
/* The WHOLE ruleset, both families, in one file: the IPv4 base from the v4
 * context, the IPv6 base and v6 user rules layered on when IPv6 is enabled.
 * There used to be an $ipv6 parameter; passing true fed IPv6 addresses into the
 * IPv4 base rules and, for a LAN with no v6 prefix, emitted "from / to any".
 * Nothing in production ever passed it, so it only ever misled a caller. */
function pf_rules_generate() {
	global $config;

	$ctx = pf_build_context(false);
	$log = !isset($config['syslog']['nologdefaultblock']) ? "log" : "";

	$out  = "# Generated by m0n0wall -- do not edit by hand.\n";
	$out .= "# Section order is fixed by pf.conf(5).\n\n";

	/* --- macros --- */
	$out .= "# ---- macros ----\n";
	$out .= "wan_if = \"{$ctx['wanif']}\"\n";
	$out .= "lan_if = \"{$ctx['lanif']}\"\n";
	foreach ($ctx['optcfg'] as $on => $oc)
		$out .= "{$on}_if = \"{$oc['if']}\"\n";

	/* Which interfaces get an anti-spoof check, worked out once: the tables
	   section needs the list for any multi-network table, and the rules
	   below need the same list, so the two cannot disagree.
	   
	   Skipped for LAN when it is bridged and the bridge is filtering or has
	   spoof checks turned off. IPv6 is checked only on interfaces that HAVE a
	   v6 prefix -- IPv6 on WAN only is an ordinary configuration, and an empty
	   prefix would emit "from ! /". It had no IPv6 check at all before: a LAN
	   host could source any v6 address it liked. */
	$lanbridge = false;
	foreach ($ctx['optcfg'] as $oc) {
		if (!empty($oc['bridge']) && $oc['bridge_if'] == "lan") { $lanbridge = true; break; }
	}
	$lanspoof = !$lanbridge ||
		(!isset($config['bridge']['filteringbridge']) && !isset($config['bridge']['nospoofcheck']));
	$spoof = array();
	$ctxs = array(false => $ctx);
	if (ipv6enabled())
		$ctxs[true] = pf_build_context(true);
	foreach ($ctxs as $v6 => $c) {
		$fam = $v6 ? " IPv6" : "";
		if ($lanspoof && !empty($c['lanip']) && !empty($c['lansa']))
			$spoof[] = array("LAN$fam", 'lan', $c['lanif'], $c['lansa'], $c['lansn'], (bool)$v6);
		foreach ($c['optcfg'] as $on => $oc) {
			if (!empty($oc['ip']) && empty($oc['bridge']))
				$spoof[] = array("$on$fam", $on, $oc['if'], $oc['sa'], $oc['sn'], (bool)$v6);
		}
	}

	/* --- tables --- */
	$tables = pf_tables_generate() . pf_tables_v6_generate();
	foreach ($spoof as $sp)
		$tables .= pf_spoof_table_generate($sp[1], $sp[3], $sp[4], $sp[5]);
	if ($tables !== "")
		$out .= "\n# ---- tables ----\n" . $tables;

	/* --- options + normalisation --- */
	$out .= "\n" . pf_options_generate();

	/* --- translation --- */
	$out .= "\n# ---- translation ----\n";
	$out .= pf_nat_rules_generate();

	/* --- filtering --- */
	$out .= "\n# ---- filtering ----\n";
	/* Default deny, stated first. Every pass below is 'quick', so this is only
	   reached when nothing matched. ipf said the same thing with per-interface
	   group heads plus a closing block. */
	$out .= "block in $log all\n";
	$out .= "block out $log all\n";

	$out .= pf_base_rules_generate($ctx['lanif'], $ctx['wanif'], $ctx['lanip'],
	                               $ctx['lansa'], $ctx['lansn'], $ctx['optcfg'], $log);

	if (ipv6enabled())
		$out .= pf_base_rules_v6_generate($ctx['lanif'], $ctx['wanif'],
		                                  $ctx['optcfg'], $log);

	/* anti-spoof -- the list was worked out above, with the tables */
	foreach ($spoof as $sp) {
		$out .= "\n# {$sp[0]} anti-spoof\n";
		$out .= pf_spoofcheck_generate($sp[1], $sp[2], $sp[3], $sp[4], $log, $sp[5]);
	}

	/* let the firewall itself out, and decrypted IPsec through */
	$out .= "\n# the firewall's own traffic\n";
	$out .= "pass out quick on {$ctx['lanif']} all keep state\n";
	$out .= "pass out quick on {$ctx['wanif']} all keep state\n";
	foreach ($ctx['optcfg'] as $oc)
		$out .= "pass out quick on {$oc['if']} all keep state\n";
	if (isset($config['ipsec']['enable']) ||
	    (isset($config['l2tp']['mode']) && $config['l2tp']['mode'] == "server"))
		$out .= "pass out quick on enc0 all keep state\n";

	/* IKE / NAT-T / ESP / AH inbound on the WAN.
	   pf_ipsec_rules_generate() was written with the rest of this file but
	   never called, so the default 'block in all' above dropped every IKE
	   packet: strongSwan would load its connections, log nothing, and no
	   tunnel could ever be established from outside.
	
	   L2TP/IPsec counts: it is enabled from its own page, independently of the
	   IPsec tunnel feature, and its clients need exactly the same ports open. */
	$l2tp_ipsec = (($config['l2tp']['mode'] ?? '') == 'server')
	              && !empty($config['l2tp']['ipsec']['psk']);
	if ((isset($config['ipsec']['enable']) || $l2tp_ipsec) && !empty($ctx['curwanip'])) {
		$out .= pf_ipsec_rules_generate($ctx['wanif'], $ctx['curwanip']);
	}

	/* WireGuard. Same class of gap: wg_configure() brings the interfaces up
	   and 'block in/out all' then drops everything that comes out of them, so
	   a tunnel could hand-shake and still pass no traffic.

	   A wg interface carries already-authenticated traffic from a peer the
	   admin configured by public key, so it is treated like a trusted
	   interface by default -- but only while the admin has written no rules
	   of their own for it. As soon as one 'wg' rule exists, these blanket
	   passes are withheld and the user's rules decide, exactly as they would
	   on LAN. */
	$wgifs = pf_wg_interfaces();
	if ($wgifs) {
		$out .= "\n# WireGuard tunnels\n";
		$wgruled = pf_wg_has_user_rules();
		foreach ($wgifs as $wgif) {
			$out .= "pass out quick on $wgif all keep state\n";
			if (!$wgruled)
				$out .= "pass in quick on $wgif all keep state\n";
		}
		if ($wgruled)
			$out .= "# inbound governed by the user's 'WireGuard' rules below\n";
	}

	if (!isset($config['system']['webgui']['noantilockout'])) {
		$out .= "\n# anti-lockout: never strand the admin outside the webGUI\n";
		$out .= "pass in quick on {$ctx['lanif']} from {$ctx['lansa']}/{$ctx['lansn']} " .
		        "to {$ctx['lanip']} keep state\n";
	}

	$out .= pf_captiveportal_rules_generate($ctx);

	/* --- user rules ---
	 * Both families in one pass. ipf needed two rulesets and two pfctl-
	 * equivalent loads; pf qualifies each rule with inet or inet6 instead. */
	$out .= "\n# ---- user-defined rules ----\n";
	foreach (array('rule' => 'inet', 'rule6' => 'inet6') as $rulekey => $af) {
		if ($af === 'inet6' && !ipv6enabled())
			continue;
		if (!isset($config['filter'][$rulekey]) || !is_array($config['filter'][$rulekey]))
			continue;
		$ctx6 = ($af === 'inet6') ? pf_build_context(true) : $ctx;
		foreach ($config['filter'][$rulekey] as $rule) {
			$iface = pf_rule_interface($rule, $ctx6);
			if ($iface === null)
				continue;
			$out .= pf_user_rule_generate($rule, $ctx6, $iface, $af);
		}
	}

	return $out;
}

/* Which pf interface does this rule bind to? null means "skip this rule",
 * covering filter.inc's several 'continue' cases. */
function pf_rule_interface($rule, $ctx) {
	global $config;

	switch ($rule['interface']) {
		case 'pptp':
			/* PPTP is removed from this port. A restored pre-1.9 config can
			   still carry pptp rules; skipping them is correct -- there is no
			   interface for them to bind to. */
			return null;
		case 'l2tp':
			/* One interface per client, so a rule has to cover them all.
			   'l2tp0' alone left every client after the first with no rules,
			   and the default block then dropped it. nunits is the configured
			   ceiling, so the brace list is exactly as wide as the server. */
			if (!isset($config['l2tp']['mode']) || $config['l2tp']['mode'] != "server")
				return null;
			$n = !empty($config['l2tp']['nunits']) ? (int) $config['l2tp']['nunits'] : 16;
			if ($n < 1) $n = 1;
			if ($n == 1) return "l2tp0";
			$ifs = array();
			for ($i = 0; $i < $n; $i++)
				$ifs[] = "l2tp$i";
			return "{ " . implode(" ", $ifs) . " }";
		case 'ipsec':
			return isset($config['ipsec']['enable']) ? "enc0" : null;
		case 'lan':
			return $ctx['lanif'];
		case 'wan':
			return $ctx['wanif'];
	}
	if (strstr($rule['interface'], "opt")) {
		return isset($ctx['optcfg'][$rule['interface']])
		       ? $ctx['optcfg'][$rule['interface']]['if'] : null;
	}
	/* A WireGuard tunnel is selected by its own interface name, and only while
	   that tunnel still exists and is enabled. */
	if (substr($rule['interface'], 0, 2) === "wg")
		return in_array($rule['interface'], pf_wg_interfaces())
		       ? $rule['interface'] : null;
	return null;
}

/* ---------------------------------------------------------------------------
 * Loading the ruleset
 *
 * Replaces filter_configure(). The shape differs from the ipf version in one
 * important way: ipf and ipnat were loaded through two separate pipes, so a
 * syntax error in the filter rules still left the NAT rules applied and the
 * box in a half-configured state. pf takes one file containing every section,
 * and pfctl validates the whole thing before committing, so the ruleset is
 * applied atomically or not at all.
 * ------------------------------------------------------------------------ */

function pf_filter_configure($ipv4only = false) {
	global $config, $g;

	if ($g['booting'])
		echo "Configuring firewall... ";

	lock_file("{$g['varrun_path']}/filter.lock");

	/* m0n0wall keeps few ports for itself so that NAT has the rest to
	   randomise from. Unchanged from the ipf path. */
	mwexec("/sbin/sysctl net.inet.ip.portrange.first=64536");
	mwexec("/sbin/sysctl net.inet.ip.portrange.hifirst=64536");

	$rules = pf_rules_generate();
	$rulefile = "{$g['varetc_path']}/pf.conf";

	if (file_put_contents($rulefile, $rules) === false) {
		printf("Cannot write %s in pf_filter_configure()\n", $rulefile);
		unlock_file("{$g['varrun_path']}/filter.lock");
		return 1;
	}

	/* Validate before loading. A firewall that fails to parse its ruleset
	   must keep the previous one, not end up with nothing. */
	$out = array();
	$rc = 0;
	exec("/sbin/pfctl -n -f " . escapeshellarg($rulefile) . " 2>&1", $out, $rc);
	if ($rc != 0) {
		printf("Generated pf ruleset is invalid, keeping the previous one:\n%s\n",
		       implode("\n", $out));
		unlock_file("{$g['varrun_path']}/filter.lock");
		return 1;
	}

	mwexec("/sbin/pfctl -f " . escapeshellarg($rulefile));
	mwexec("/sbin/pfctl -e");           /* harmless if already enabled */

	if ($g['booting'])
		echo "done\n";

	unlock_file("{$g['varrun_path']}/filter.lock");
	return 0;
}

/* ipf needed an explicit resync after an interface changed address. pf
   re-reads '($if)' targets by itself, so this only has to reload the ruleset
   so that literal addresses baked into rules are refreshed. */
function pf_filter_resync() {
	return pf_filter_configure();
}

function pf_flush_state_table() {
	return mwexec("/sbin/pfctl -F states");
}

function pf_flush_nat_table() {
	/* pf keeps translations in the state table; there is no separate NAT
	   table to flush as there was with ipnat. */
	return mwexec("/sbin/pfctl -F states");
}

/* ---------------------------------------------------------------------------
 * IPv6
 *
 * A structural simplification, not just a translation. ipf needed a wholly
 * separate ruleset for v6: filter_rules_generate_ipv6() built it,
 * filter_configure6() piped it to 'ipf -6' behind its own lock file, and the
 * rule-group numbers had to be shifted by 10000 so the two rulesets would not
 * collide.
 *
 * pf filters both address families from one ruleset, with 'inet' and 'inet6'
 * qualifying a rule where the family matters. So all of that machinery
 * disappears: one file, one pfctl load, one lock.
 * ------------------------------------------------------------------------ */

function pf_base_rules_v6_generate($lanif, $wanif, $optcfg, $log) {
	global $config;

	$out  = "\n# ---- IPv6 base rules ----\n";

	/* Neighbour discovery and the ICMPv6 types that must never be filtered,
	   or IPv6 breaks in ways that look like routing faults. Types 133-136 are
	   RS/RA/NS/NA; 1/2/3 are unreachable, packet-too-big (needed for PMTUD)
	   and time-exceeded. */
	$out .= "pass quick inet6 proto ipv6-icmp all icmp6-type { 133, 134, 135, 136 }\n";
	$out .= "pass quick inet6 proto ipv6-icmp all icmp6-type { 1, 2, 3 }\n";

	$out .= "\n# link-local\n";
	$out .= "pass quick on $lanif inet6 from fe80::/10 to fe80::/10\n";
	foreach ($optcfg as $oc)
		$out .= "pass quick on {$oc['if']} inet6 from fe80::/10 to fe80::/10\n";

	$out .= "\n# DHCPv6\n";
	$out .= "pass in quick on $lanif inet6 proto udp from any port 546 to ff02::1:2 port 547\n";
	foreach ($optcfg as $on => $oc) {
		if ((isset($config['dhcpd'][$on]['v6enable']) && empty($oc['bridge'])) ||
		    (!empty($oc['bridge']) && isset($config['dhcpd'][$oc['bridge_if']]['v6enable'])))
			$out .= "pass in quick on {$oc['if']} inet6 proto udp from any port 546 to ff02::1:2 port 547\n";
	}
	/* our own DHCPv6 client. ipf noted it could not restrict this because it
	   lacked ipfw's 'me'; pf has '(self)', so it can be tightened here. */
	$out .= "pass out quick on $wanif inet6 proto udp from any port 546 to any port 547\n";
	$out .= "pass in quick on $wanif inet6 proto udp from any to (self) port 546\n";

	/* Transition tunnels.
	
	   A 6to4, tunnel-broker or AICCU WAN carries IPv6 inside IPv4 protocol 41,
	   which arrives on the PHYSICAL WAN -- so these are inet rules, not inet6 --
	   and emerges decapsulated on stf0/gif0/tun0. filter.inc passed both; this
	   file passed neither, so selecting any tunnelled IPv6 mode produced a WAN
	   that came up and carried nothing.
	
	   The echo-request allowance is what tunnel brokers ping to decide the
	   endpoint is still alive; without it the tunnel is torn down at the far
	   end after a few minutes. */
	$v6mode = $config['interfaces']['wan']['ipaddr6'] ?? '';
	$tunnelled = ($v6mode == "6to4" || $v6mode == "aiccu"
	              || !empty($config['interfaces']['wan']['tunnel6']));
	if ($tunnelled) {
		$out .= "\n# IPv6 transition tunnel\n";
		if ($v6mode != "aiccu" || !isset($config['interfaces']['wan']['aiccu']['ayiya'])) {
			$out .= "pass in quick on $wanif inet proto ipencap from any to (self) keep state\n";
			$out .= "pass out quick on $wanif inet proto ipencap from (self) to any keep state\n";
		}
		$out .= "pass in quick on $wanif inet proto icmp from any to (self) " .
		        "icmp-type echoreq keep state\n";
		$tunif = get_real_wan_interface(true);
		if ($tunif && $tunif != $wanif)
			$out .= "pass quick on $tunif all keep state\n";
	}

	if (isset($config['interfaces']['wan']['blockpriv'])) {
		$out .= "\n# reject IPv6 transition/site-local abuse on the WAN\n";
		$out .= "block in $log quick on $wanif inet6 from <priv6> to any\n";
		$out .= "block in $log quick on $wanif inet6 from any to <priv6>\n";
	}

	return $out;
}

/* The v6 table that goes with the rules above. Kept beside pf_tables_generate()
 * so both land in the tables section.
 *
 * Contents follow FreeBSD's own /etc/rc.firewall6 and the list filter.inc
 * blocked: site-local, IPv4-mapped and IPv4-compatible space, and the 6to4
 * prefixes that embed private or reserved IPv4 addresses.
 */
function pf_tables_v6_generate() {
	global $config;

	if (!isset($config['interfaces']['wan']['blockpriv']))
		return "";

	return "table <priv6> const { fec0::/10, ::ffff:0.0.0.0/96, ::224.0.0.0/100, " .
	       "::127.0.0.0/104, ::0.0.0.0/104, ::255.0.0.0/104, " .
	       "2002:e000::/20, 2002:7f00::/24, 2002:0000::/24, 2002:ff00::/24, " .
	       "2002:0a00::/24, 2002:ac10::/28, 2002:c0a8::/32 }\n";
}

/* ---------------------------------------------------------------------------
 * Coexisting with ipfw
 *
 * m0n0wall keeps ipfw for two things the pf move does not touch: traffic
 * shaping via dummynet (shaper.inc) and the captive portal
 * (captiveportal.inc). So after this change the box runs TWO packet filters
 * at once, and both register on the same pfil hooks.
 *
 * FreeBSD does not merge them. pfil calls each registered filter in the order
 * they are linked, and pfilctl(8) controls that order. By default a newly
 * registered hook is PREPENDED -- it becomes the first filter on input and
 * the last on output -- so the order depends on module load order, which is
 * not something to leave to chance on a firewall.
 *
 * What we want on input is pf first, then dummynet: there is no sense shaping
 * a packet that is about to be dropped. Concretely:
 *
 *     pfilctl heads                  # the filtering points
 *     pfilctl hooks                  # the registered filters
 *     pfilctl link -i pf inet        # pf first on input
 *     pfilctl link -o -a pf inet     # ...and appended on output
 *
 * shaper.inc additionally sets net.inet.ip.fw.one_pass=1 so that ipfw stops
 * evaluating once a packet has been handed to a pipe. That stays correct
 * here: it concerns ipfw's own rule evaluation, not its position relative
 * to pf.
 *
 * XXX-VERIFY: the exact link order, and whether the captive portal's ipfw
 * rules still see the addresses they expect once pf has already translated
 * them. This cannot be settled by reading manuals -- it needs a box with
 * shaping and the portal both enabled, and a packet capture.
 * ------------------------------------------------------------------------ */

/* Start pflogd, which writes the pflog0 capture to a file the GUI reads.
 *
 * Replaces ipmon, which belonged to ipfilter. pf logs via a pseudo-interface
 * rather than a daemon reading a device, so pflogd is a plain tcpdump-style
 * writer rather than a log parser.
 */
function pf_pflogd_start() {
	global $g;

	/* killall, not killbypid: pflogd's -p is not honoured in this build --
	   it accepts the flag and writes no pidfile -- so there is nothing to
	   read back. We record the pid ourselves below instead. */
	mwexec("/usr/bin/killall pflogd");

	mwexec("/sbin/ifconfig pflog0 create 2>/dev/null");
	mwexec("/sbin/ifconfig pflog0 up");

	/* pflogd chroots to /var/empty and drops privileges to _pflogd. That
	   account has to exist in the image or it exits immediately with
	   "unknown user _pflogd" and the firewall log stays empty forever --
	   see build/files/master.passwd. */
	$rc = mwexec("/sbin/pflogd -f {$g['varlog_path']}/pflog.cap");

	/* Write the pidfile ourselves, so newsyslog can signal a reopen when it
	   rotates the capture. The privileged parent is the one to signal; the
	   child runs as _pflogd and re-executes itself on SIGHUP. */
	$out = array();
	exec("/bin/ps -axo pid,command", $out);
	foreach ($out as $line) {
		if (preg_match('/^\s*(\d+)\s+pflogd:\s+\[priv\]/', $line, $m)) {
			@file_put_contents("{$g['varrun_path']}/pflogd.pid", $m[1] . "\n");
			break;
		}
	}

	return $rc;
}

/* ---------------------------------------------------------------------------
 * Reading the filter log
 *
 * ipfilter's ipmon fed text lines to syslog, which landed in
 * /var/log/filter.log and which diag_logs_filter.php parsed. pf has no ipmon:
 * matching packets are copied to the pflog0 interface and pflogd writes them
 * to /var/log/pflog.cap as a pcap. So the log is now binary, and the only
 * thing in the image that can decode it is tcpdump.
 *
 * -q is deliberate: without it tcpdump describes TCP as "Flags [S], seq ..."
 * and never names the protocol, which is the one field the log page filters
 * on. With it every line ends in a protocol name and a length:
 *
 *   2026-09-24 14:02:33.123456 rule 5/0(match): block in on vtnet0: \
 *       192.0.2.30.54321 > 192.0.2.240.65001: tcp 0
 *
 * -tttt gives the absolute date and time; the default prints time only, and
 * -ttt prints a delta from the previous packet, which is useless in a log.
 * ------------------------------------------------------------------------ */

/* Split "192.0.2.30.54321" into address and port, or "2001:db8::1.443" for
   IPv6. tcpdump separates the port with a dot in both families, so an IPv6
   address has to be recognised by its colons rather than by counting dots. */
function pf_log_split_endpoint($tok) {
	$tok = rtrim($tok, ":");
	$dot = strrpos($tok, ".");
	if ($dot === false)
		return array($tok, "");
	$maybe_port = substr($tok, $dot + 1);
	if ($maybe_port === "" || !ctype_digit($maybe_port))
		return array($tok, "");
	$addr = substr($tok, 0, $dot);
	if (strpos($tok, ":") !== false)          /* IPv6 plus port */
		return array($addr, $maybe_port);
	if (substr_count($addr, ".") == 3)        /* IPv4 plus port */
		return array($addr, $maybe_port);
	return array($tok, "");                   /* bare IPv4, no port */
}

/* The last $nentries packets pf logged, newest last.
 *
 * Returns an array of entries with act, time, interface, src, srcport, dst,
 * dstport, proto, rulenr -- the shape diag_logs_filter.php renders. Returns
 * an empty array when there is nothing to read; the caller distinguishes "no
 * packets" from "no log" by testing for the capture file itself. */
function pf_filter_log_read($nentries = 50, $reverse = false) {
	global $g;

	$cap = "{$g['varlog_path']}/pflog.cap";
	if (!file_exists($cap))
		return array();

	$out = array();
	exec("/usr/sbin/tcpdump -n -e -q -tttt -r " . escapeshellarg($cap) .
	     " 2>/dev/null | /usr/bin/tail -n " . ((int)$nentries), $out);

	$entries = array();
	foreach ($out as $line) {
		if (!preg_match('/^(\S+ \S+) rule ([\d\-]+)\/\S*\((\w+)\): ' .
		                '(pass|block|rdr|nat) (in|out) on (\S+): (.*)$/', $line, $m))
			continue;

		$e = array(
			'time'      => $m[1],
			'rulenr'    => $m[2],
			'act'       => $m[4],
			'interface' => $m[6],
			'src' => '', 'srcport' => '', 'dst' => '', 'dstport' => '', 'proto' => '',
		);

		/* "192.0.2.30.54321 > 192.0.2.240.65001: tcp 0", and the v6 form
		   "2001:db8::1.54321 > 2001:db8::2.80: tcp 0".
		
		   Splitting the destination at the FIRST colon truncated every IPv6
		   address at its first group and left the rest of the address sitting
		   in the protocol column. Neither address can contain whitespace, so
		   the separator to anchor on is the colon that is FOLLOWED by
		   whitespace -- greedy \S+ then backtracks to exactly that one. */
		$rest = $m[7];
		if (preg_match('/^(\S+) > (\S+):\s*(\S*)/', $rest, $r)) {
			list($e['src'], $e['srcport']) = pf_log_split_endpoint($r[1]);
			list($e['dst'], $e['dstport']) = pf_log_split_endpoint($r[2]);
			$e['proto'] = strtoupper(rtrim($r[3], ','));
		} else {
			$e['proto'] = '';
		}
		$entries[] = $e;
	}

	if ($reverse)
		$entries = array_reverse($entries);

	return $entries;
}

/* Interface name to the label the GUI uses ("LAN", "WAN", a description). */
function pf_log_interface_map() {
	global $config;

	$map = array();
	if (!empty($config['interfaces']['lan']['if']))
		$map[$config['interfaces']['lan']['if']] = "LAN";
	$wanif = function_exists('get_real_wan_interface') ? get_real_wan_interface() : '';
	if (!empty($wanif))
		$map[$wanif] = "WAN";
	foreach (opt_interfaces() as $i => $optif) {
		$oc = $config['interfaces'][$optif];
		if (!empty($oc['if']))
			$map[$oc['if']] = !empty($oc['descr']) ? $oc['descr'] : ('OPT' . $i);
	}
	return $map;
}

/* ---------------------------------------------------------------------------
 * Captive portal
 *
 * The portal's web servers listen on 8000 and 8001 of the portal interface,
 * and anyone on that network can reach them BEFORE authenticating. That makes
 * the per-source connection cap a real control rather than a nicety.
 *
 * m0n0wall did it with a patched mini_httpd (-maxperip). lighttpd 1.4.84 no
 * longer ships mod_evasive, so it is done here instead -- which is better
 * placed anyway: pf drops the connection before a worker is allocated rather
 * than after, and the state limit is enforced in the kernel.
 * ------------------------------------------------------------------------ */
function pf_captiveportal_rules_generate($ctx) {
	global $config;

	if (!isset($config['captiveportal']['enable']))
		return "";

	$cp = $config['captiveportal'];
	$if = isset($ctx['optcfg'][$cp['interface']]['if'])
	      ? $ctx['optcfg'][$cp['interface']]['if']
	      : (($cp['interface'] == 'lan') ? $ctx['lanif'] : null);
	if (!$if)
		return "";

	/* The GUI field is 'maxprocperip' ("maximum concurrent connections per
	   client IP address"). This used to read 'nomaxperip', a key NO page has
	   ever written, so the cap was permanently 4 whatever the admin typed --
	   and captiveportal.inc read the real key only into a -maxperip argument
	   for the mini_httpd that no longer exists.
	
	   Semantics follow the page: blank means the old mini_httpd default of 4,
	   and an explicit 0 means no limit. */
	if (!isset($cp['maxprocperip']) || $cp['maxprocperip'] === "" || $cp['maxprocperip'] === false)
		$perip = 4;
	else
		$perip = (int) $cp['maxprocperip'];

	$ports = "{ 8000 8001 }";
	$out  = "\n# captive portal web servers\n";
	if ($perip > 0) {
		$out .= "pass in quick on $if inet proto tcp to port $ports " .
		        "keep state (max-src-conn $perip, source-track rule)\n";
		$out .= "# 'max-src-conn $perip' replaces mini_httpd's -maxperip. Exceeding it\n";
		$out .= "# drops the connection in the kernel, before a worker is allocated.\n";
	} else {
		$out .= "pass in quick on $if inet proto tcp to port $ports keep state\n";
	}
	return $out;
}


/* ---------------------------------------------------------------------------
 * Canonical names.
 *
 * 26 call sites across the tree say filter_configure(). Rather than edit all
 * of them -- and risk missing one, which would silently leave a code path
 * generating ipfilter rules for a firewall that has no ipfilter -- the
 * canonical names resolve here. filter.inc's versions are renamed
 * _ipf_superseded and are unreachable.
 * ------------------------------------------------------------------------ */

function filter_configure($ipv4only = false) { return pf_filter_configure($ipv4only); }
function filter_resync()                     { return pf_filter_resync(); }
/* One unified ruleset -- but the callers (the IPv6 Rules 'Apply changes'
 * button and rc.newwanip6) are asking for the rules to be REBUILT, and
 * returning 0 without doing so reported success while changing nothing. The v6
 * rules live in the same file, so a normal reload is the correct answer. */
function filter_configure6()                 { return pf_filter_configure(); }
function filter_ipmon_start()                { return pf_pflogd_start(); }
function filter_flush_state_table()          { return pf_flush_state_table(); }
function filter_flush_state_table_ipv6()     { return pf_flush_state_table(); }
function filter_flush_nat_table()            { return pf_flush_nat_table(); }
