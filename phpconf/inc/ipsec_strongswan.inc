<?php
/*
	ipsec_strongswan.inc
	part of m0n0wall (http://m0n0.ch/wall)

	IPsec configuration, generated for strongSwan.

	Copyright (C) 2026 m0n0wall contributors.
	Derived from m0n0wall, Copyright (C) 2003-2007 Manuel Kasper <mk@neon1.net>.
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the conditions of the two-clause
	BSD licence carried by the rest of m0n0wall are met.
*/

/* ===========================================================================
 * Why this replaces racoon
 *
 * m0n0wall drove racoon from ipsec-tools, whose last release was 0.8.2 in
 * 2014. The FreeBSD port was marked for expiry in January 2025 as
 * "deprecated by upstream in 2014, contains security issues" and survives
 * only because one volunteer adopted it. That is not a foundation.
 *
 * strongSwan is the maintained implementation, and the model is genuinely
 * different rather than a syntax change:
 *
 *   racoon                        strongSwan
 *   ---------------------------   --------------------------------------
 *   racoon.conf + spd.conf        swanctl.conf, one file
 *   setkey writes SPD entries     the daemon installs them from the config
 *   psk.txt                       a secrets {} section
 *   separate enc/hash/dh fields   one proposal string, aes256-sha256-modp2048
 *   IKEv1 only in practice        IKEv2 by default, IKEv1 on request
 *
 * THE CONFIG MODEL IS UNCHANGED. This reads the same $config['ipsec'] keys
 * the webGUI already writes -- p1 mode/encryption/hash/dhgroup/lifetime,
 * p2 protocol/encryption-algorithm-option/hash-algorithm-option/pfsgroup,
 * local-subnet, remote-subnet, remote-gateway. Existing tunnels keep working.
 *
 * Nothing about setkey survives: strongSwan installs its own policies, so the
 * whole spd.conf apparatus disappears.
 * ===========================================================================
 */

define('SWANCTL_BIN', '/usr/local/sbin/swanctl');
define('CHARON_BIN',  '/usr/local/libexec/ipsec/charon');

/* --- algorithm mapping ----------------------------------------------------
 * racoon and strongSwan spell these differently, and a wrong name produces a
 * tunnel that negotiates nothing with a message about no proposal chosen.
 */
function ipsec_ss_enc($alg, $keylen = null) {
	switch ($alg) {
		case 'des':       return 'des';
		case '3des':      return '3des';
		case 'blowfish':  return 'blowfish' . ($keylen ? $keylen : '');
		case 'cast128':   return 'cast128';
		case 'aes':
		case 'rijndael':  return 'aes' . ($keylen ? $keylen : '128');
		case 'aes128':    return 'aes128';
		case 'aes192':    return 'aes192';
		case 'aes256':    return 'aes256';
		case 'aes128gcm16': return 'aes128gcm16';
		case 'aes256gcm16': return 'aes256gcm16';
	}
	return 'aes256';
}

function ipsec_ss_hash($alg) {
	switch ($alg) {
		case 'md5':       return 'md5';
		case 'sha1':      return 'sha1';
		case 'sha256':    return 'sha256';
		case 'sha384':    return 'sha384';
		case 'sha512':    return 'sha512';
		case 'aesxcbc':   return 'aesxcbc';
	}
	return 'sha256';
}

/* Diffie-Hellman group number to strongSwan's name. */
function ipsec_ss_dh($group) {
	$map = array(
		1  => 'modp768',   2  => 'modp1024',  5  => 'modp1536',
		14 => 'modp2048', 15 => 'modp3072', 16 => 'modp4096',
		17 => 'modp6144', 18 => 'modp8192',
		19 => 'ecp256',   20 => 'ecp384',   21 => 'ecp521',
		31 => 'curve25519',
	);
	$g = (int)$group;
	return isset($map[$g]) ? $map[$g] : 'modp2048';
}

/* Build an IKE (phase 1) proposal string. */
function ipsec_ss_p1_proposal($p1) {
	$enc  = ipsec_ss_enc(isset($p1['encryption-algorithm']) ? $p1['encryption-algorithm'] : '',
	                     isset($p1['encryption-algorithm-keylen']) ? $p1['encryption-algorithm-keylen'] : null);
	$hash = ipsec_ss_hash(isset($p1['hash-algorithm']) ? $p1['hash-algorithm'] : '');
	$dh   = ipsec_ss_dh(isset($p1['dhgroup']) ? $p1['dhgroup'] : 14);
	return "{$enc}-{$hash}-{$dh}";
}

/* Build an ESP (phase 2) proposal string.
 *
 * m0n0wall lets phase 2 offer SEVERAL algorithms, as repeated
 * encryption-algorithm-option and hash-algorithm-option elements. strongSwan
 * expresses that as a comma-separated list of complete proposals, so this is
 * a cross product rather than a direct translation.
 */
function ipsec_ss_p2_proposals($p2) {
	$encs = array();
	if (isset($p2['encryption-algorithm-option'])) {
		$e = $p2['encryption-algorithm-option'];
		foreach ((is_array($e) ? $e : array($e)) as $alg)
			$encs[] = ipsec_ss_enc($alg);
	}
	if (empty($encs)) $encs = array('aes256');

	$hashes = array();
	if (isset($p2['hash-algorithm-option'])) {
		$h = $p2['hash-algorithm-option'];
		foreach ((is_array($h) ? $h : array($h)) as $alg)
			$hashes[] = ipsec_ss_hash($alg);
	}
	if (empty($hashes)) $hashes = array('sha256');

	/* PFS group, or 'noesn' meaning no new DH exchange for the child SA. */
	$pfs = (!empty($p2['pfsgroup']) && $p2['pfsgroup'] != '0')
	       ? ipsec_ss_dh($p2['pfsgroup']) : null;

	$out = array();
	foreach ($encs as $e)
		foreach ($hashes as $h)
			$out[] = $pfs ? "{$e}-{$h}-{$pfs}" : "{$e}-{$h}";
	return implode(',', array_unique($out));
}

/* A connection name safe for swanctl: it becomes a section key. */
function ipsec_ss_conn_name($i, $tunnel) {
	$d = isset($tunnel['descr']) ? preg_replace('/[^a-zA-Z0-9_-]/', '', $tunnel['descr']) : '';
	return $d !== '' ? "con{$i}_{$d}" : "con{$i}";
}

/* ---------------------------------------------------------------------------
 * swanctl.conf generation
 * ------------------------------------------------------------------------ */

/* Generate swanctl.conf from $config['ipsec'].
 *
 * Returned as text so it can be unit-tested without a filesystem, which is
 * how the racoon-to-strongSwan mapping was verified.
 */
function ipsec_ss_config_generate() {
	global $config;

	$ipseccfg = isset($config['ipsec']) && is_array($config['ipsec']) ? $config['ipsec'] : array();
	$tunnels  = (isset($ipseccfg['tunnel']) && is_array($ipseccfg['tunnel']))
	            ? $ipseccfg['tunnel'] : array();

	$conns   = "";
	$secrets = "";
	$n = 0;

	foreach ($tunnels as $i => $tunnel) {
		if (isset($tunnel['disabled']))
			continue;
		if (empty($tunnel['remote-gateway']))
			continue;

		$name = ipsec_ss_conn_name($i, $tunnel);
		$p1   = isset($tunnel['p1']) ? $tunnel['p1'] : array();
		$p2   = isset($tunnel['p2']) ? $tunnel['p2'] : array();
		$n++;

		/* Which address we speak from. An explicit interface wins; otherwise
		   let strongSwan choose by route, which is what %any means. */
		$local_addr = '%any';
		if (!empty($tunnel['interface'])) {
			$ifn = $tunnel['interface'];
			if ($ifn == 'wan')
				$local_addr = '%any';   /* resolved at runtime; WAN may be dynamic */
			else if (isset($config['interfaces'][$ifn]['ipaddr'])
			         && is_ipaddr($config['interfaces'][$ifn]['ipaddr']))
				$local_addr = $config['interfaces'][$ifn]['ipaddr'];
		}

		/* IKE version. m0n0wall's p1 'mode' is an IKEv1 concept (main or
		   aggressive). Anything else, including empty, means IKEv2 -- which
		   is what a tunnel created today should be. */
		$mode = isset($p1['mode']) ? $p1['mode'] : '';
		$ikev1 = ($mode == 'main' || $mode == 'aggressive');

		$conns .= "\t{$name} {\n";
		$conns .= "\t\tlocal_addrs  = {$local_addr}\n";
		$conns .= "\t\tremote_addrs = {$tunnel['remote-gateway']}\n";
		$conns .= "\t\tversion      = " . ($ikev1 ? "1" : "2") . "\n";
		if ($ikev1 && $mode == 'aggressive')
			$conns .= "\t\taggressive   = yes\n";
		$conns .= "\t\tproposals    = " . ipsec_ss_p1_proposal($p1) . "\n";

		if (!empty($p1['lifetime']))
			$conns .= "\t\trekey_time   = {$p1['lifetime']}s\n";

		/* Dead peer detection. racoon called this dpddelay. */
		if (!empty($tunnel['dpddelay'])) {
			$conns .= "\t\tdpd_delay    = {$tunnel['dpddelay']}s\n";
			$conns .= "\t\tdpd_timeout  = " . ((int)$tunnel['dpddelay'] * 4) . "s\n";
		}

		/* Authentication. A pre-shared key or a certificate. */
		$usepsk = !empty($p1['pre-shared-key']);

		$conns .= "\t\tlocal {\n";
		if ($usepsk) {
			$conns .= "\t\t\tauth = psk\n";
			if (!empty($p1['myident']))
				$conns .= "\t\t\tid   = {$p1['myident']}\n";
		} else {
			$conns .= "\t\t\tauth  = pubkey\n";
			if (!empty($p1['cert']))
				$conns .= "\t\t\tcerts = {$name}-local.crt\n";
		}
		$conns .= "\t\t}\n";

		$conns .= "\t\tremote {\n";
		$conns .= "\t\t\tauth = " . ($usepsk ? "psk" : "pubkey") . "\n";
		$conns .= "\t\t\tid   = {$tunnel['remote-gateway']}\n";
		$conns .= "\t\t}\n";

		/* The child SA carries the actual traffic selectors. */
		$local_ts = ipsec_ss_local_ts($tunnel);
		$conns .= "\t\tchildren {\n";
		$conns .= "\t\t\t{$name} {\n";
		if ($local_ts !== null)
			$conns .= "\t\t\t\tlocal_ts      = {$local_ts}\n";
		if (!empty($tunnel['remote-subnet']))
			$conns .= "\t\t\t\tremote_ts     = {$tunnel['remote-subnet']}\n";
		$conns .= "\t\t\t\tesp_proposals = " . ipsec_ss_p2_proposals($p2) . "\n";
		if (!empty($p2['lifetime']))
			$conns .= "\t\t\t\trekey_time    = {$p2['lifetime']}s\n";
		/* 'auto' in m0n0wall meant bring it up at boot; otherwise install a
		   trap policy and start on the first matching packet. */
		$conns .= "\t\t\t\tstart_action  = " .
		          (isset($tunnel['auto']) ? "start" : "trap") . "\n";
		$conns .= "\t\t\t\tdpd_action    = restart\n";
		$conns .= "\t\t\t}\n";
		$conns .= "\t\t}\n";
		$conns .= "\t}\n";

		if ($usepsk) {
			$secrets .= "\tike-{$name} {\n";
			$secrets .= "\t\tid     = {$tunnel['remote-gateway']}\n";
			$secrets .= "\t\tsecret = \"{$p1['pre-shared-key']}\"\n";
			$secrets .= "\t}\n";
		}
	}

	$out  = "# IPsec configuration -- generated by m0n0wall.\n";
	$out .= "# strongSwan replaces racoon; see ipsec_strongswan.inc.\n\n";
	$out .= "connections {\n" . ($conns !== "" ? $conns : "\t# no enabled tunnels\n") . "}\n\n";
	$out .= "secrets {\n" . $secrets . "}\n";

	return $out;
}

/* The local traffic selector.
 *
 * m0n0wall's local-subnet is either a symbolic network ("lan", "opt1") or an
 * explicit address and mask, so this mirrors the resolution the racoon
 * generator did.
 */
function ipsec_ss_local_ts($tunnel) {
	global $config;

	if (!isset($tunnel['local-subnet']) || !is_array($tunnel['local-subnet']))
		return null;
	$ls = $tunnel['local-subnet'];

	if (!empty($ls['network'])) {
		$net = $ls['network'];
		if ($net == 'lan' || strpos($net, 'opt') === 0) {
			if (!isset($config['interfaces'][$net]['ipaddr']))
				return null;
			$ifc = $config['interfaces'][$net];
			return gen_subnet($ifc['ipaddr'], $ifc['subnet']) . "/" . $ifc['subnet'];
		}
		return null;
	}
	if (!empty($ls['address']))
		return $ls['address'] . (!empty($ls['netbits']) ? "/{$ls['netbits']}" : "/32");

	return null;
}

/* ---------------------------------------------------------------------------
 * Starting it
 * ------------------------------------------------------------------------ */

function vpn_ipsec_configure($ipchg = false) {
	global $config, $g;

	$conf = "{$g['varetc_path']}/swanctl.conf";

	if (!isset($config['ipsec']['enable'])) {
		/* Tear down cleanly rather than leaving policies installed. */
		mwexec(SWANCTL_BIN . " --terminate --ike-all 2>/dev/null");
		killbyname("charon");
		@unlink($conf);
		return 0;
	}

	if ($g['booting'])
		echo "Configuring IPsec... ";

	/* 0600: the file holds pre-shared keys. */
	$old = umask(0077);
	file_put_contents($conf, ipsec_ss_config_generate());
	umask($old);
	@chmod($conf, 0600);

	/* charon reads swanctl.conf from its own directory. */
	@mkdir("/usr/local/etc/swanctl", 0700, true);
	@copy($conf, "/usr/local/etc/swanctl/swanctl.conf");

	if (!is_process_running("charon")) {
		mwexec_bg(CHARON_BIN);
		/* charon needs a moment before it will accept a vici connection. */
		sleep(2);
	}

	/* --load-all installs connections, secrets and pools in one call.
	   Unlike racoon, there is no separate setkey step: strongSwan installs
	   its own policies. */
	$rc = mwexec(SWANCTL_BIN . " --load-all --noprompt");

	if ($g['booting'])
		echo ($rc == 0 ? "done\n" : "failed\n");

	return $rc;
}

function is_process_running($name) {
	$out = array();
	exec("/usr/bin/pgrep -x " . escapeshellarg($name) . " 2>/dev/null", $out);
	return !empty($out);
}
