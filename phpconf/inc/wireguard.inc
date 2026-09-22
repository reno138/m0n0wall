<?php
/*
	wireguard.inc
	part of m0n0wall (http://m0n0.ch/wall)

	WireGuard tunnel and peer management.

	Copyright (C) 2026 m0n0wall contributors.
	Derived from m0n0wall, Copyright (C) 2003-2007 Manuel Kasper <mk@neon1.net>.
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the conditions of the two-clause
	BSD licence carried by the rest of m0n0wall are met.
*/

/* ===========================================================================
 * Design notes
 *
 * WIREGUARD CANNOT DO DHCP. It is a layer-3 tunnel with no broadcast domain:
 * a wg(4) interface carries no broadcast or multicast, so DHCP discovery has
 * nowhere to happen. A "DHCP scope bound to the WG interface" is therefore not
 * possible.
 *
 * It is also not needed. This module keeps an address POOL per tunnel and
 * allocates the next free address when a peer is added, writing it into the
 * generated client config. From the administrator's point of view that is the
 * same experience as a DHCP scope, with far less machinery and no failure mode
 * where a client cannot get a lease. Peers may also be pinned to a static
 * address.
 *
 * KEYS. A peer's private key should never leave the client. The preferred flow
 * is that the client generates its own pair and the administrator pastes in
 * the public key. m0n0wall can generate both for convenience -- the GUI must
 * say plainly that doing so means the private key existed on the firewall.
 *
 * TOPOLOGY. This is hub-and-spoke, not mesh: peers reach each other through
 * the firewall. True mesh needs every peer to hold every other peer's key and
 * current endpoint, which is the coordination problem Headscale solves and is
 * deliberately out of scope here.
 * ===========================================================================
 */

/* wg(4) is in FreeBSD base; wg(8)/wg-quick come from the wireguard-tools port. */
define('WG_BIN', '/usr/local/bin/wg');

/* ---------------------------------------------------------------------------
 * Address pool management (IPAM)
 * ------------------------------------------------------------------------ */

/* Every address a tunnel has already committed: its own, plus every peer's. */
function wg_addresses_in_use($tunnel) {
	$used = array();
	if (!empty($tunnel['address']))
		$used[] = $tunnel['address'];
	if (isset($tunnel['peer']) && is_array($tunnel['peer'])) {
		foreach ($tunnel['peer'] as $peer) {
			if (!empty($peer['address']))
				$used[] = $peer['address'];
		}
	}
	return $used;
}

/* Allocate the lowest free host address in the tunnel's subnet.
 *
 * Skips the network and broadcast addresses even though a point-to-point
 * tunnel has no broadcast: peers are routed into the same subnet as ordinary
 * LAN hosts often enough that handing out the .0 or .255 invites confusion.
 *
 * Returns null when the pool is exhausted, so the caller can report that
 * rather than emit a duplicate.
 */
function wg_allocate_address($tunnel) {
	if (empty($tunnel['address']) || empty($tunnel['subnet']))
		return null;

	$bits = (int)$tunnel['subnet'];
	if ($bits < 1 || $bits > 30)
		return null;                    /* /31 and /32 leave no host space */

	$net   = ip2long(gen_subnet($tunnel['address'], $bits));
	$count = 1 << (32 - $bits);
	$used  = array_flip(wg_addresses_in_use($tunnel));

	for ($i = 1; $i < $count - 1; $i++) {
		$cand = long2ip($net + $i);
		if (!isset($used[$cand]))
			return $cand;
	}
	return null;                        /* pool exhausted */
}

/* How many addresses remain, for the GUI to show before the pool runs dry. */
function wg_pool_free_count($tunnel) {
	if (empty($tunnel['subnet']))
		return 0;
	$bits = (int)$tunnel['subnet'];
	if ($bits < 1 || $bits > 30)
		return 0;
	$total = (1 << (32 - $bits)) - 2;   /* less network and broadcast */
	return max(0, $total - count(wg_addresses_in_use($tunnel)));
}

/* ---------------------------------------------------------------------------
 * Validation
 * ------------------------------------------------------------------------ */

/* A WireGuard key is 32 bytes, base64-encoded: 44 characters ending in '='. */
function wg_is_valid_key($key) {
	if (!is_string($key) || strlen($key) != 44 || substr($key, -1) !== '=')
		return false;
	if (!preg_match('|^[A-Za-z0-9+/]{43}=$|', $key))
		return false;
	$raw = base64_decode($key, true);
	return ($raw !== false && strlen($raw) === 32);
}

/* Peer names become filenames in the generated config download, so keep them
 * boring on purpose. */
function wg_is_valid_peername($name) {
	return (bool)preg_match('/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,30}$/', $name);
}

function wg_is_valid_endpoint($ep) {
	if ($ep === '' || $ep === null)
		return true;                    /* optional: roaming clients have none */
	if (!preg_match('/^(.+):(\d+)$/', $ep, $m))
		return false;
	$host = $m[1]; $port = (int)$m[2];
	if ($port < 1 || $port > 65535)
		return false;
	$host = trim($host, '[]');          /* [2001:db8::1]:51820 */
	return (is_ipaddr($host) || is_ipaddr6($host) || is_domain($host) || is_hostname($host));
}

/* ---------------------------------------------------------------------------
 * Config generation
 * ------------------------------------------------------------------------ */

/* The server-side wg(8) config for one tunnel.
 *
 * AllowedIPs is the whole security model here: wg(4) uses cryptokey routing,
 * so a peer may only send traffic from the addresses listed against its key.
 * Each peer therefore gets a /32, not the tunnel subnet -- listing the subnet
 * would let any single peer spoof every other.
 */
function wg_tunnel_config_generate($tunnel) {
	$out  = "[Interface]\n";
	$out .= "PrivateKey = {$tunnel['privatekey']}\n";
	$out .= "ListenPort = " . (!empty($tunnel['listenport']) ? $tunnel['listenport'] : 51820) . "\n";

	if (!empty($tunnel['mtu']))
		$out .= "MTU = {$tunnel['mtu']}\n";

	if (isset($tunnel['peer']) && is_array($tunnel['peer'])) {
		foreach ($tunnel['peer'] as $peer) {
			if (isset($peer['disabled']))
				continue;
			$out .= "\n# {$peer['name']}\n";
			$out .= "[Peer]\n";
			$out .= "PublicKey = {$peer['publickey']}\n";
			if (!empty($peer['presharedkey']))
				$out .= "PresharedKey = {$peer['presharedkey']}\n";

			/* one /32 per peer -- see the note above */
			$allowed = array($peer['address'] . '/32');
			if (!empty($peer['routes'])) {
				foreach (preg_split('/[\s,]+/', trim($peer['routes'])) as $r) {
					if ($r !== '')
						$allowed[] = $r;
				}
			}
			$out .= "AllowedIPs = " . implode(', ', $allowed) . "\n";

			if (!empty($peer['endpoint']))
				$out .= "Endpoint = {$peer['endpoint']}\n";
			if (!empty($peer['keepalive']))
				$out .= "PersistentKeepalive = {$peer['keepalive']}\n";
		}
	}
	return $out;
}

/* The client-side config the administrator downloads or scans.
 *
 * $privatekey is passed separately and is only non-empty when m0n0wall
 * generated the pair. When the client supplied its own public key this is
 * left as a placeholder, because the firewall never had the private half --
 * which is the preferred flow.
 */
function wg_peer_config_generate($tunnel, $peer, $privatekey = '', $server_endpoint = '') {
	$out  = "[Interface]\n";
	$out .= "PrivateKey = " . ($privatekey !== '' ? $privatekey
	                          : "<insert this device's private key>") . "\n";
	$out .= "Address = {$peer['address']}/32\n";
	if (!empty($tunnel['dns']))
		$out .= "DNS = {$tunnel['dns']}\n";
	if (!empty($tunnel['mtu']))
		$out .= "MTU = {$tunnel['mtu']}\n";

	$out .= "\n[Peer]\n";
	$out .= "PublicKey = {$tunnel['publickey']}\n";
	if (!empty($peer['presharedkey']))
		$out .= "PresharedKey = {$peer['presharedkey']}\n";

	/* What the client routes down the tunnel. Default to the tunnel subnet
	   plus anything the admin marked as reachable; 0.0.0.0/0 for full tunnel. */
	if (!empty($peer['clientallowed']))
		$allowed = $peer['clientallowed'];
	else
		$allowed = gen_subnet($tunnel['address'], $tunnel['subnet']) . '/' . $tunnel['subnet'];
	$out .= "AllowedIPs = $allowed\n";

	if ($server_endpoint !== '')
		$out .= "Endpoint = $server_endpoint\n";
	if (!empty($peer['keepalive']))
		$out .= "PersistentKeepalive = {$peer['keepalive']}\n";

	return $out;
}

/* ---------------------------------------------------------------------------
 * Bringing tunnels up
 * ------------------------------------------------------------------------ */

function wg_configure() {
	global $config, $g;

	if (!isset($config['wireguard']['tunnel']) || !is_array($config['wireguard']['tunnel']))
		return 0;

	foreach ($config['wireguard']['tunnel'] as $tunnel) {
		if (!isset($tunnel['enable']))
			continue;

		$if = $tunnel['if'];
		$conf = "{$g['varetc_path']}/{$if}.conf";

		/* 0600: the file holds the tunnel's private key. */
		$old = umask(0077);
		file_put_contents($conf, wg_tunnel_config_generate($tunnel));
		umask($old);
		@chmod($conf, 0600);

		mwexec("/sbin/ifconfig $if create 2>/dev/null");
		mwexec(WG_BIN . " setconf $if " . escapeshellarg($conf));
		mwexec("/sbin/ifconfig $if inet {$tunnel['address']}/{$tunnel['subnet']} up");

		/* Routes for anything reachable through a peer. */
		if (isset($tunnel['peer']) && is_array($tunnel['peer'])) {
			foreach ($tunnel['peer'] as $peer) {
				if (isset($peer['disabled']) || empty($peer['routes']))
					continue;
				foreach (preg_split('/[\s,]+/', trim($peer['routes'])) as $r) {
					if ($r !== '')
						mwexec("/sbin/route add -net " . escapeshellarg($r) . " -iface $if");
				}
			}
		}
	}
	return 0;
}

/* Live peer state for the status page: last handshake and byte counters. */
function wg_get_peer_status($if) {
	$out = array();
	exec(WG_BIN . " show " . escapeshellarg($if) . " dump 2>/dev/null", $lines);
	/* first line is the interface itself; peers follow */
	for ($i = 1; $i < count($lines); $i++) {
		$f = explode("\t", $lines[$i]);
		if (count($f) < 8)
			continue;
		$out[$f[0]] = array(
			'publickey'      => $f[0],
			'endpoint'       => $f[2],
			'allowedips'     => $f[3],
			'latesthandshake'=> (int)$f[4],
			'rx'             => (int)$f[5],
			'tx'             => (int)$f[6],
		);
	}
	return $out;
}
