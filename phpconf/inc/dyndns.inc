<?php
/*
	dyndns.inc
	part of m0n0wall (http://m0n0.ch/wall)

	Dynamic DNS updates, performed natively over HTTPS.

	Copyright (C) 2026 m0n0wall contributors.
	Derived from m0n0wall, Copyright (C) 2003-2007 Manuel Kasper <mk@neon1.net>.
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the conditions of the two-clause
	BSD licence carried by the rest of m0n0wall are met.
*/

/* ===========================================================================
 * Why this replaces ez-ipupdate
 *
 * m0n0wall shelled out to ez-ipupdate, whose last release was 2002 and whose
 * provider list -- DHS, ODS, DyNS, HN.ORG, EZ-IP, TZO -- is now almost
 * entirely dead or paid. Its successors (inadyn, ddclient) are alive but are
 * another binary in an image that is unpacked into RAM.
 *
 * Every dynamic DNS provider worth supporting today is an HTTPS request.
 * PHP's openssl and json extensions are already in the image for the webGUI,
 * and the https stream wrapper is built in, so this needs NO additional
 * package and NO additional executable. One fewer moving part, and updates
 * become debuggable from the GUI instead of from a daemon's log.
 *
 * TWO SHAPES OF PROVIDER:
 *
 *   dyndns2   the de-facto standard: GET /nic/update?hostname=&myip= with
 *             HTTP Basic auth. One implementation covers DynDNS, No-IP,
 *             Dynu, Namecheap-compatible endpoints and many others -- the
 *             only difference is the hostname.
 *   token     a single GET with a token in the query string. DuckDNS, deSEC,
 *             dynv6, afraid.org and Hurricane Electric all work this way.
 *
 * Cloudflare is neither, and is handled separately because it is the one
 * most self-hosters actually use: it needs a record lookup, then a PATCH
 * with a JSON body and a bearer token.
 * ===========================================================================
 */

/* Provider registry.
 *
 * 'proto' selects the implementation; everything else is presentation and
 * the endpoint. Adding a dyndns2-compatible provider is one line here.
 */
function dyndns_providers() {
	return array(
		/* --- dyndns2 protocol ------------------------------------------ */
		'dyndns'     => array('name' => 'DynDNS',              'proto' => 'dyndns2',
		                      'host' => 'members.dyndns.org'),
		'noip'       => array('name' => 'No-IP',               'proto' => 'dyndns2',
		                      'host' => 'dynupdate.no-ip.com'),
		'dynu'       => array('name' => 'Dynu',                'proto' => 'dyndns2',
		                      'host' => 'api.dynu.com'),
		'ovh'        => array('name' => 'OVH',                 'proto' => 'dyndns2',
		                      'host' => 'www.ovh.com'),
		'spdyn'      => array('name' => 'SPDYN',               'proto' => 'dyndns2',
		                      'host' => 'update.spdyn.de'),

		/* --- single-GET token providers -------------------------------- */
		'duckdns'    => array('name' => 'Duck DNS',            'proto' => 'token',
		                      'url'  => 'https://www.duckdns.org/update?domains={host}&token={pass}&ip={ip}',
		                      'ok'   => 'OK'),
		'desec'      => array('name' => 'deSEC',               'proto' => 'token',
		                      'url'  => 'https://update.dedyn.io/?hostname={host}&myipv4={ip}',
		                      'auth' => 'bearer'),
		'dynv6'      => array('name' => 'dynv6',               'proto' => 'token',
		                      'url'  => 'https://dynv6.com/api/update?hostname={host}&token={pass}&ipv4={ip}'),
		'afraid'     => array('name' => 'FreeDNS (afraid.org)','proto' => 'token',
		                      'url'  => 'https://freedns.afraid.org/dynamic/update.php?{pass}&address={ip}'),
		'he'         => array('name' => 'Hurricane Electric', 'proto' => 'dyndns2',
		                      'host' => 'dyn.dns.he.net'),

		/* --- API providers --------------------------------------------- */
		'cloudflare' => array('name' => 'Cloudflare',          'proto' => 'cloudflare'),
	);
}

/* Perform an HTTPS request and return array(http_code, body).
 *
 * Deliberately uses the stream wrapper rather than curl: the curl extension
 * is not in the image and does not need to be.
 */
function dyndns_http($url, $opts = array()) {
	$headers = isset($opts['headers']) ? $opts['headers'] : array();
	$headers[] = "User-Agent: m0n0wall/" . trim(@file_get_contents("/etc/version"));

	$ctx = array('http' => array(
		'method'        => isset($opts['method']) ? $opts['method'] : 'GET',
		'header'        => implode("\r\n", $headers),
		'timeout'       => 20,
		/* We want the body on a 4xx/5xx, not a warning and false. */
		'ignore_errors' => true,
	));
	if (isset($opts['body']))
		$ctx['http']['content'] = $opts['body'];

	/* Verify the certificate. An unverified dynamic DNS update leaks the
	   credentials to anyone able to intercept it. */
	$ctx['ssl'] = array(
		'verify_peer'      => true,
		'verify_peer_name' => true,
		'cafile'           => '/usr/local/etc/ssl/cert.pem',
	);

	$body = @file_get_contents($url, false, stream_context_create($ctx));

	/* PHP 8.4 deprecated the magic $http_response_header variable in favour
	   of http_get_last_response_headers(). Note that merely MENTIONING the
	   old variable raises the deprecation, even inside a branch that never
	   runs -- so there is no version fallback here. The image ships PHP 8.4. */
	$hdrs = http_get_last_response_headers();

	$code = 0;
	if (is_array($hdrs)) {
		foreach ($hdrs as $h) {
			if (preg_match('|^HTTP/\S+\s+(\d{3})|', $h, $m)) $code = (int)$m[1];
		}
	}
	return array($code, $body === false ? '' : trim($body));
}

/* Build the update URL for a token-style provider. */
function dyndns_token_url($prov, $host, $user, $pass, $ip) {
	$url = $prov['url'];
	$url = str_replace('{host}', rawurlencode($host), $url);
	$url = str_replace('{user}', rawurlencode($user), $url);
	$url = str_replace('{pass}', rawurlencode($pass), $url);
	$url = str_replace('{ip}',   rawurlencode($ip),   $url);
	return $url;
}

/* Send one update. Returns array(bool success, string message).
 *
 * The message is shown in the GUI, so it carries the provider's own response
 * where there is one -- "nochg", "badauth", "abuse" and so on are far more
 * useful to an administrator than a generic failure.
 */
function dyndns_update($type, $host, $user, $pass, $ip, $extra = array()) {
	$provs = dyndns_providers();
	if (!isset($provs[$type]))
		return array(false, "Unknown provider '{$type}'.");
	$p = $provs[$type];

	switch ($p['proto']) {

	case 'dyndns2':
		$url = "https://{$p['host']}/nic/update?hostname=" . rawurlencode($host)
		     . "&myip=" . rawurlencode($ip);
		list($code, $body) = dyndns_http($url, array('headers' => array(
			'Authorization: Basic ' . base64_encode("$user:$pass"))));
		if ($code != 200)
			return array(false, "HTTP $code from {$p['host']}" . ($body ? ": $body" : ""));
		/* dyndns2 returns its verdict in the body, not the status code. */
		$word = strtok($body, " \n");
		if ($word == "good")   return array(true,  "Updated to $ip.");
		if ($word == "nochg")  return array(true,  "Already set to $ip (no change).");
		if ($word == "badauth")return array(false, "Authentication rejected.");
		if ($word == "abuse")  return array(false, "The provider has flagged this account for abuse.");
		if ($word == "nohost") return array(false, "The provider does not know hostname '$host'.");
		return array(false, "Provider said: $body");

	case 'token':
		$url  = dyndns_token_url($p, $host, $user, $pass, $ip);
		$opts = array();
		if (isset($p['auth']) && $p['auth'] == 'bearer')
			$opts['headers'] = array("Authorization: Token " . $pass);
		list($code, $body) = dyndns_http($url, $opts);
		if ($code != 200)
			return array(false, "HTTP $code" . ($body ? ": $body" : ""));
		if (isset($p['ok']) && strpos($body, $p['ok']) === false)
			return array(false, "Provider said: " . ($body !== '' ? $body : '(empty response)'));
		return array(true, "Updated to $ip." . ($body !== '' ? " Provider said: $body" : ""));

	case 'cloudflare':
		/* Cloudflare needs the record's id before it can be changed, so this
		   is a lookup followed by a PATCH. $user is the zone id and $pass is
		   an API token scoped to DNS:Edit for that zone. */
		if (empty($user))
			return array(false, "Cloudflare needs the Zone ID in the username field.");
		$base = "https://api.cloudflare.com/client/v4/zones/" . rawurlencode($user) . "/dns_records";
		$auth = array("Authorization: Bearer $pass", "Content-Type: application/json");

		list($code, $body) = dyndns_http($base . "?type=A&name=" . rawurlencode($host),
		                                 array('headers' => $auth));
		if ($code != 200)
			return array(false, "Cloudflare lookup failed, HTTP $code.");
		$j = json_decode($body, true);
		if (!isset($j['success']) || !$j['success'] || empty($j['result']))
			return array(false, "Cloudflare has no A record for '$host' in that zone.");
		$rec = $j['result'][0];
		if (isset($rec['content']) && $rec['content'] === $ip)
			return array(true, "Already set to $ip (no change).");

		list($code, $body) = dyndns_http($base . "/" . rawurlencode($rec['id']),
			array('method' => 'PATCH', 'headers' => $auth,
			      'body' => json_encode(array('content' => $ip))));
		$j = json_decode($body, true);
		if ($code == 200 && isset($j['success']) && $j['success'])
			return array(true, "Updated to $ip.");
		$err = isset($j['errors'][0]['message']) ? $j['errors'][0]['message'] : "HTTP $code";
		return array(false, "Cloudflare rejected the update: $err");
	}

	return array(false, "Provider '{$type}' has no implementation.");
}

/* ---------------------------------------------------------------------------
 * The m0n0wall entry points
 * ------------------------------------------------------------------------ */

/* Replaces the ez-ipupdate config generator and launch.
 *
 * There is no daemon any more: an update is sent when the WAN address
 * changes, which is what rc.newwanip already signals, and the result is
 * cached so a reboot does not re-announce an unchanged address.
 */
function services_dyndns_configure() {
	global $config, $g;

	if (!isset($config['dyndns']['enable']))
		return 0;

	if ($g['booting']) {
		/* A dynamic WAN has no address yet; dhclient and ppp-linkup run
		   rc.newwanip once it does, and that sends the update. A static WAN
		   has its address now and nothing else will fire, so send it here --
		   otherwise a static-WAN box never updated after a reboot. */
		$wantype = isset($config['interfaces']['wan']['ipaddr'])
		           ? $config['interfaces']['wan']['ipaddr'] : '';
		if (in_array($wantype, array('dhcp', 'pppoe', 'pptp', 'bigpond', ''))) {
			echo "Dynamic DNS will update when the WAN address is known.\n";
			return 0;
		}
	}

	return services_dyndns_send();
}

/* Send the update if the address has actually changed. */
function services_dyndns_send($force = false) {
	global $config, $g;

	$cfg = $config['dyndns'];
	if (!isset($cfg['enable']))
		return 0;

	$ip = get_current_wan_address(false);
	if (!$ip || !is_ipaddr($ip)) {
		log_error("Dynamic DNS: no WAN address yet, not updating.");
		return 1;
	}

	$cachefile = "{$g['vardb_path']}/dyndns.cache";
	$cached = @file_get_contents($cachefile);
	if (!$force && $cached !== false && trim($cached) === $ip) {
		/* Providers treat needless updates as abuse, and some will block an
		   account for it. Never re-announce an unchanged address. */
		return 0;
	}

	list($ok, $msg) = dyndns_update($cfg['type'], $cfg['host'],
	                                $cfg['username'], $cfg['password'], $ip);

	if ($ok) {
		@file_put_contents($cachefile, $ip);
		log_error("Dynamic DNS ({$cfg['type']}, {$cfg['host']}): $msg");
		return 0;
	}

	log_error("Dynamic DNS ({$cfg['type']}, {$cfg['host']}) FAILED: $msg");
	return 1;
}

/* Called when the WAN address changes, and by the GUI's "force update". */
function services_dyndns_reset() {
	global $g;
	@unlink("{$g['vardb_path']}/dyndns.cache");
	return 0;
}
