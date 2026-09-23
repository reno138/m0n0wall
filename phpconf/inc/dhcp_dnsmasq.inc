<?php
/*
	dhcp_dnsmasq.inc
	part of m0n0wall (http://m0n0.ch/wall)

	DHCP server configuration, generated for dnsmasq.

	Copyright (C) 2026 m0n0wall contributors.
	Derived from m0n0wall, Copyright (C) 2003-2007 Manuel Kasper <mk@neon1.net>.
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the conditions of the two-clause
	BSD licence carried by the rest of m0n0wall are met.
*/

/* ===========================================================================
 * Why this exists
 *
 * m0n0wall drove ISC dhcpd, which reached end of maintenance at the end of
 * 2022. Kea is ISC's own successor and was the plan, until its dependency
 * closure turned out to be boost-libs, icu, python312 and a full gcc -- about
 * 400 MB for a DHCP server, on an appliance whose entire root filesystem is
 * unpacked into RAM.
 *
 * dnsmasq is already in the image for DNS forwarding and serves DHCP as well,
 * so this replaces two daemons with one.
 *
 * THE CONFIGURATION MODEL DOES NOT CHANGE. This reads exactly the same
 * $config['dhcpd'] structure the webGUI has always written -- range,
 * staticmap, domain, dnsserver, winsserver, gateway, defaultleasetime,
 * maxleasetime, denyunknown, next-server, filename. The GUI pages needed no
 * changes, and an existing config.xml keeps working untouched.
 *
 * WHERE FIDELITY IS LOST, and it is worth being honest about it:
 *
 *   maxleasetime   dnsmasq has one lease time per range, not a default and a
 *                  maximum. defaultleasetime is used; maxleasetime is ignored
 *                  and the GUI says so.
 *   denyunknown    ISC's "deny unknown clients" becomes dhcp-ignore=tag:!known,
 *                  which is equivalent: only hosts with a static mapping are
 *                  served.
 *   netbios-node-type  emitted as raw option 46, since dnsmasq has no name
 *                  for it.
 * ===========================================================================
 */

/* Generate the dnsmasq DHCP configuration from $config['dhcpd'].
 *
 * Returned as text rather than written to a file so it can be unit-tested
 * without a filesystem, which is how the port was verified against the old
 * ISC output.
 */
/* Lease database. dnsmasq writes its own -- one lease per line: expiry
 * (epoch), MAC, address, name, client-id -- which is NOT the ISC format the
 * old lease page parsed. Anything that reads leases must go through this. */
function dhcp_dnsmasq_leasefile() {
	global $g;
	return "{$g['vardb_path']}/dnsmasq.leases";
}

/* Read dnsmasq's lease database.
 *
 * One lease per line: "<expiry> <mac> <ip> <hostname|*> <client-id|*>",
 * expiry as epoch seconds (0 = infinite). DHCPv6 leases use the same file
 * with an IAID in the MAC column and a leading "duid ..." line; they are
 * skipped here. dnsmasq removes expired leases when it next rewrites the
 * file, so "expired" is only ever seen briefly. There is no start time in
 * this format, which is why the lease page no longer has a Start column.
 *
 * Returns false when there is no lease file (DHCP never started), otherwise
 * an array keyed by IP with ip, mac, hostname, end, act ("active"|"expired")
 * and clientid. Both diag_dhcp_leases.php and diag_arp.php use this; neither
 * should ever parse the file itself again. */
function dhcp_dnsmasq_leases_read() {
	$lines = @file(dhcp_dnsmasq_leasefile(), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
	if ($lines === false)
		return false;

	$now = time();
	$leases = array();
	foreach ($lines as $line) {
		$f = preg_split('/\s+/', trim($line));
		if (count($f) < 4 || $f[0] == "duid" || !is_ipaddr($f[2]))
			continue;
		$end = (int)$f[0];
		$leases[$f[2]] = array(
			'ip'       => $f[2],
			'mac'      => $f[1],
			'hostname' => ($f[3] == "*") ? "" : $f[3],
			'end'      => $end,
			'act'      => ($end == 0 || $end > $now) ? "active" : "expired",
			'clientid' => (isset($f[4]) && $f[4] != "*") ? $f[4] : "",
		);
	}
	return $leases;
}

/* The interfaces DHCP is actually served on: enabled in $config['dhcpd'] with
 * a usable range, on an interface that exists and (LAN aside) is enabled,
 * real and not bridged. One place for the rule, used both to build the
 * configuration and to decide whether dnsmasq has to run at all. */
function dhcp_dnsmasq_enabled_interfaces() {
	global $config;

	$dhcpdcfg = isset($config['dhcpd']) && is_array($config['dhcpd'])
	            ? $config['dhcpd'] : array();
	$enabled = array();

	foreach ($dhcpdcfg as $dhcpif => $dhcpifconf) {
		if (!is_array($dhcpifconf) || !isset($dhcpifconf['enable']))
			continue;

		$ifcfg = isset($config['interfaces'][$dhcpif]) ? $config['interfaces'][$dhcpif] : null;
		if (!$ifcfg)
			continue;
		if ($dhcpif != "lan" &&
		    (!isset($ifcfg['enable']) || empty($ifcfg['if']) || !empty($ifcfg['bridge'])))
			continue;
		if (empty($dhcpifconf['range']['from']) || empty($dhcpifconf['range']['to']))
			continue;

		$enabled[$dhcpif] = array('dhcp' => $dhcpifconf, 'if' => $ifcfg);
	}
	return $enabled;
}

function dhcp_dnsmasq_config_generate() {
	global $config;

	$syscfg = $config['system'];

	$out  = "# DHCP server configuration -- generated by m0n0wall.\n";
	$out .= "# Served by dnsmasq; see dhcp_dnsmasq.inc for the mapping from\n";
	$out .= "# the ISC dhcpd options the webGUI still speaks in.\n\n";

	$any = false;

	foreach (dhcp_dnsmasq_enabled_interfaces() as $dhcpif => $e) {
		$dhcpifconf = $e['dhcp'];
		$ifcfg      = $e['if'];

		$any  = true;
		$if   = $ifcfg['if'];
		$mask = gen_subnet_mask($ifcfg['subnet']);

		/* Lease time. ISC had default and max; dnsmasq has one. */
		$lease = !empty($dhcpifconf['defaultleasetime'])
		         ? $dhcpifconf['defaultleasetime'] . "s" : "7200s";

		$out .= "# --- {$dhcpif} ({$if}) ---\n";
		$out .= "dhcp-range=set:{$dhcpif},{$dhcpifconf['range']['from']},"
		      . "{$dhcpifconf['range']['to']},{$mask},{$lease}\n";

		/* Router. ISC: option routers. dnsmasq option 3. */
		$routers = !empty($dhcpifconf['gateway']) ? $dhcpifconf['gateway'] : $ifcfg['ipaddr'];
		$out .= "dhcp-option=tag:{$dhcpif},3,{$routers}\n";

		/* DNS servers. Same precedence the ISC generator used: an explicit
		   per-interface list, else this firewall if the forwarder is on,
		   else the system servers. */
		$dnsservers = array();
		if (isset($dhcpifconf['dnsserver']) && is_array($dhcpifconf['dnsserver'])
		    && !empty($dhcpifconf['dnsserver'][0])) {
			$dnsservers = $dhcpifconf['dnsserver'];
		} else if (isset($config['dnsmasq']['enable'])) {
			$dnsservers = array($ifcfg['ipaddr']);
		} else if (isset($syscfg['dnsserver']) && is_array($syscfg['dnsserver'])
		           && !empty($syscfg['dnsserver'][0])) {
			$dnsservers = $syscfg['dnsserver'];
		}
		$dnsservers = array_filter($dnsservers, "is_ipaddr");
		if (!empty($dnsservers))
			$out .= "dhcp-option=tag:{$dhcpif},6," . implode(",", $dnsservers) . "\n";

		/* Domain name, option 15. */
		if (!empty($dhcpifconf['domain']))
			$out .= "dhcp-option=tag:{$dhcpif},15,{$dhcpifconf['domain']}\n";
		else if (!empty($syscfg['domain']))
			$out .= "dhcp-option=tag:{$dhcpif},15,{$syscfg['domain']}\n";

		/* WINS, options 44 and 46. dnsmasq has no name for node type. */
		if (isset($dhcpifconf['winsserver']) && is_array($dhcpifconf['winsserver'])
		    && !empty($dhcpifconf['winsserver'][0])) {
			$wins = array_filter($dhcpifconf['winsserver'], "is_ipaddr");
			if (!empty($wins)) {
				$out .= "dhcp-option=tag:{$dhcpif},44," . implode(",", $wins) . "\n";
				$out .= "dhcp-option=tag:{$dhcpif},46,8\n";
			}
		}

		/* PXE. ISC: next-server + filename. dnsmasq: dhcp-boot. */
		if (!empty($dhcpifconf['filename'])) {
			$boot = $dhcpifconf['filename'];
			if (!empty($dhcpifconf['next-server']))
				$boot .= ",," . $dhcpifconf['next-server'];
			$out .= "dhcp-boot=tag:{$dhcpif},{$boot}\n";
		}

		/* ISC "deny unknown clients": serve only hosts with a static mapping. */
		if (isset($dhcpifconf['denyunknown']))
			$out .= "dhcp-ignore=tag:!known\n";

		/* Static mappings. ISC host{} blocks become dhcp-host lines. */
		if (isset($dhcpifconf['staticmap']) && is_array($dhcpifconf['staticmap'])) {
			foreach ($dhcpifconf['staticmap'] as $sm) {
				if (empty($sm['mac']))
					continue;
				/* v6 mappings are not ours to serve here */
				if (!empty($sm['ipaddr']) && is_ipaddr6($sm['ipaddr']))
					continue;
				$parts = array($sm['mac']);
				if (!empty($sm['ipaddr']))
					$parts[] = $sm['ipaddr'];
				if (!empty($sm['hostname']))
					$parts[] = $sm['hostname'];
				$out .= "dhcp-host=" . implode(",", $parts) . "\n";
			}
		}

		$out .= "\n";
	}

	if (!$any)
		$out .= "# no interface has DHCP enabled\n";
	else
		$out .= "dhcp-authoritative\n";

	return $out;
}

/* DHCP is dnsmasq's job now, and services_dnsmasq_configure() writes both
 * halves of its configuration and (re)starts it. rc.bootup calls that before
 * this, so at boot there is nothing left to do; at runtime a DHCP change is
 * applied by regenerating and restarting, which also reloads the filter.
 *
 * This used to write the DHCP file and then call services_dnsmasq_configure(),
 * which called back here: infinite mutual recursion at 1 Hz on every runtime
 * reconfigure. Now the DHCP file is written by services_dnsmasq_configure()
 * itself, before the daemon starts, and this only delegates. */
function services_dhcpd_configure() {
	global $g;

	if ($g['booting'])
		return 0;

	return services_dnsmasq_configure();
}
