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

define('SWANCTL_DIR', '/usr/local/etc/swanctl');
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
		/* the GUI's own label for 256-bit Rijndael */
		case 'rijndael 256':
		case 'rijndael256': return 'aes256';
		case 'aes128':    return 'aes128';
		case 'aes192':    return 'aes192';
		case 'aes256':    return 'aes256';
		case 'aes128gcm16': return 'aes128gcm16';
		case 'aes256gcm16': return 'aes256gcm16';
	}
	return 'aes256';
}

/* Local IKE identity. The GUI stores myident as an array whose single key
   names the type: myaddress (use the local address, which strongSwan does by
   default), address, fqdn, ufqdn, asn1dn. Interpolating the array itself
   emitted "id = Array" as every tunnel's identity, so peers rejected the
   phase-1 exchange. Returns null when strongSwan's default is right. */
function ipsec_ss_myident($p1) {
	if (empty($p1['myident']) || !is_array($p1['myident']))
		return null;

	foreach (array('address', 'fqdn', 'ufqdn', 'asn1dn') as $type) {
		if (!empty($p1['myident'][$type]))
			return ($type == 'asn1dn')
			       ? '"' . $p1['myident'][$type] . '"'
			       : $p1['myident'][$type];
	}
	return null;		/* myaddress, or an empty element */
}

function ipsec_ss_hash($alg) {
	/* The webGUI stores phase-2 hashes as hmac_sha1, hmac_md5, hmac_sha256...
	   (racoon's names). Without stripping the prefix nothing matched and
	   every proposal silently fell through to sha256, so a peer configured
	   for SHA-1 answered NO_PROPOSAL_CHOSEN. */
	$alg = preg_replace('/^hmac[-_]/', '', strtolower(trim($alg)));

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
			$myid = ipsec_ss_myident($p1);
			if ($myid !== null)
				$conns .= "\t\t\tid   = {$myid}\n";
		} else {
			$conns .= "\t\t\tauth  = pubkey\n";
			if (!empty($p1['cert']))
				$conns .= "\t\t\tcerts = {$name}-local.crt\n";
		}
		$conns .= "\t\t}\n";

		$conns .= "\t\tremote {\n";
		$conns .= "\t\t\tauth = " . ($usepsk ? "psk" : "pubkey") . "\n";
		$conns .= "\t\t\tid   = {$tunnel['remote-gateway']}\n";
		/* Pin the peer to the certificate the operator pasted in, when they
		   supplied one; otherwise any certificate a trusted CA signed is
		   accepted. ipsec_ss_write_credentials() writes the file. */
		if (!$usepsk && !empty($p1['peercert']))
			$conns .= "\t\t\tcerts = {$name}-peer.crt\n";
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
		} else if (!empty($p1['private-key'])) {
			/* swanctl loads the key by naming it here; it does not scan the
			   private/ directory on its own. */
			$secrets .= "\tprivate-{$name} {\n";
			$secrets .= "\t\tfile = {$name}.key\n";
			$secrets .= "\t}\n";
		}
	}

	/* Road-warrior clients. One connection accepting any remote address --
	   this is $config['ipsec']['mobileclients'], which the VPN > IPsec >
	   Mobile clients page has always written and which nothing read until
	   now, so those settings configured nothing at all. */
	$mob = isset($ipseccfg['mobileclients']) && is_array($ipseccfg['mobileclients'])
	       ? $ipseccfg['mobileclients'] : array();
	if (isset($mob['enable'])) {
		$mp1    = isset($mob['p1']) ? $mob['p1'] : array();
		$mmode  = isset($mp1['mode']) ? $mp1['mode'] : '';
		$mikev1 = ($mmode == 'main' || $mmode == 'aggressive');
		$musepsk = (isset($mp1['authentication_method']) &&
		            $mp1['authentication_method'] == 'pre_shared_key')
		           || empty($mp1['cert']);

		$conns .= "\tmobile {\n";
		$conns .= "\t\tlocal_addrs  = %any\n";
		/* the defining difference from a site-to-site tunnel */
		$conns .= "\t\tremote_addrs = %any\n";
		$conns .= "\t\tversion      = " . ($mikev1 ? "1" : "2") . "\n";
		if ($mikev1 && $mmode == 'aggressive')
			$conns .= "\t\taggressive   = yes\n";
		$conns .= "\t\tproposals    = " . ipsec_ss_p1_proposal($mp1) . "\n";
		if (!empty($mp1['lifetime']))
			$conns .= "\t\trekey_time   = {$mp1['lifetime']}s\n";
		if (!empty($mob['dpddelay'])) {
			$conns .= "\t\tdpd_delay    = {$mob['dpddelay']}s\n";
			$conns .= "\t\tdpd_timeout  = " . ((int)$mob['dpddelay'] * 4) . "s\n";
		}

		$conns .= "\t\tlocal {\n";
		if ($musepsk) {
			$conns .= "\t\t\tauth = psk\n";
			$mid = ipsec_ss_myident($mp1);
			if ($mid !== null)
				$conns .= "\t\t\tid   = {$mid}\n";
		} else {
			$conns .= "\t\t\tauth  = pubkey\n";
			$conns .= "\t\t\tcerts = mobile-local.crt\n";
		}
		$conns .= "\t\t}\n";

		/* No id: the whole point is that we do not know who will connect.
		   Each client authenticates with its own identity, matched against
		   the secrets below. */
		$conns .= "\t\tremote {\n";
		$conns .= "\t\t\tauth = " . ($musepsk ? "psk" : "pubkey") . "\n";
		$conns .= "\t\t}\n";

		$conns .= "\t\tchildren {\n";
		$conns .= "\t\t\tmobile {\n";
		$lan_ts = ipsec_ss_local_ts(array('local-subnet' => array('network' => 'lan')));
		if ($lan_ts !== null)
			$conns .= "\t\t\t\tlocal_ts      = {$lan_ts}\n";
		$conns .= "\t\t\t\tesp_proposals = " .
		          ipsec_ss_p2_proposals(isset($mob['p2']) ? $mob['p2'] : array()) . "\n";
		/* Never 'start' or 'trap': we cannot initiate to a roaming client,
		   and a trap policy would black-hole LAN traffic. */
		$conns .= "\t\t\t\tstart_action  = none\n";
		$conns .= "\t\t\t\tdpd_action    = clear\n";
		$conns .= "\t\t\t}\n";
		$conns .= "\t\t}\n";
		$conns .= "\t}\n";
		$n++;

		/* One secret per identity, from VPN > IPsec > Pre-shared keys. */
		$mkeys = (isset($ipseccfg['mobilekey']) && is_array($ipseccfg['mobilekey']))
		         ? $ipseccfg['mobilekey'] : array();
		$k = 0;
		foreach ($mkeys as $mk) {
			if (empty($mk['ident']) || !isset($mk['pre-shared-key']))
				continue;
			$secrets .= "\tike-mobile{$k} {\n";
			$secrets .= "\t\tid     = {$mk['ident']}\n";
			$secrets .= "\t\tsecret = \"{$mk['pre-shared-key']}\"\n";
			$secrets .= "\t}\n";
			$k++;
		}
		if (!$musepsk && !empty($mp1['private-key'])) {
			$secrets .= "\tprivate-mobile {\n";
			$secrets .= "\t\tfile = mobile.key\n";
			$secrets .= "\t}\n";
		}
	}

	/* ---------------------------------------------------------------------
	 * L2TP/IPsec.
	 *
	 * This was MISSING ENTIRELY. vpn_ipsec_l2tp_configure() in vpn.inc starts
	 * mpd5 listening on UDP/1701 and the page collects a pre-shared key, but
	 * nothing ever generated the IPsec half -- racoon used to, and strongSwan
	 * had no L2TP awareness at all. So enabling "L2TP/IPsec" produced a bare,
	 * unauthenticated, unencrypted L2TP listener: no standard client would talk
	 * to it, and anyone who did get a session would have had none of the
	 * protection the page's name promises. The PSK configured nothing.
	 *
	 * The shape is fixed by what L2TP/IPsec clients (Windows, macOS, iOS,
	 * Android) actually do, and differs from every other connection here:
	 *
	 *   version = 1     they are all IKEv1. This is the one place IKEv1 is
	 *                   still required rather than merely tolerated.
	 *   mode = transport  L2TP carries its own PPP session, so IPsec protects
	 *                   the UDP/1701 datagrams in place. A tunnel-mode SA --
	 *                   the default, and what every other conn here uses --
	 *                   would not match what the client proposes.
	 *   traffic selectors are PORT-SPECIFIC: our 1701 against the client's
	 *                   ephemeral port. Selectors of 0.0.0.0/0 would capture
	 *                   traffic that has nothing to do with L2TP.
	 *   encap = yes     almost every client is behind NAT, and NAT rewrites the
	 *                   source port the selectors are negotiated against.
	 *                   Forcing UDP encapsulation is what makes that work.
	 *
	 * The secret is matched on %any: a client's identity is its current public
	 * address, which we cannot know in advance. Authentication of the USER is
	 * PPP's job inside the tunnel (mpd.secret or RADIUS), which is the standard
	 * two-layer L2TP/IPsec arrangement, not an omission.
	 * ------------------------------------------------------------------ */
	$l2tp = isset($config['l2tp']) && is_array($config['l2tp']) ? $config['l2tp'] : array();
	$l2tp_psk = $l2tp['ipsec']['psk'] ?? '';
	if (($l2tp['mode'] ?? '') == 'server' && $l2tp_psk !== '') {
		/* The address clients come to. A dynamic WAN has to be resolved at
		   generation time, because a traffic selector cannot say "whatever my
		   address is" -- rc.newwanip regenerates this when the lease changes. */
		$l2tp_local = get_current_wan_address();
		$l2tp_lts   = is_ipaddr($l2tp_local)
		              ? "{$l2tp_local}[udp/1701]" : "dynamic[udp/1701]";

		$conns .= "\tl2tp {\n";
		$conns .= "\t\tlocal_addrs  = " . (is_ipaddr($l2tp_local) ? $l2tp_local : '%any') . "\n";
		$conns .= "\t\tremote_addrs = %any\n";
		$conns .= "\t\tversion      = 1\n";
		$conns .= "\t\tencap        = yes\n";
		/* Deliberately broad: these have to interoperate with whatever the
		   client's built-in stack offers, and that varies by OS and version.
		   aes256/aes128 with sha256/sha1 and modp2048/modp1024 covers every
		   current client without accepting DES or MD5. */
		$conns .= "\t\tproposals    = aes256-sha256-modp2048,aes256-sha1-modp1024," .
		          "aes128-sha1-modp1024\n";
		$conns .= "\t\tlocal {\n";
		$conns .= "\t\t\tauth = psk\n";
		$conns .= "\t\t}\n";
		$conns .= "\t\tremote {\n";
		$conns .= "\t\t\tauth = psk\n";
		$conns .= "\t\t}\n";
		$conns .= "\t\tchildren {\n";
		$conns .= "\t\t\tl2tp {\n";
		$conns .= "\t\t\t\tlocal_ts      = {$l2tp_lts}\n";
		/* 'dynamic[udp]', not 'dynamic[udp/%any]' -- swanctl rejects a %any
		   PORT outright ("invalid value for: remote_ts, config discarded"),
		   which would have discarded the whole connection and left the L2TP
		   listener unprotected again. Omitting the port is how strongSwan
		   spells "any port", which is what is needed: NAT rewrites the
		   client's source port. Verified against strongSwan 6.1.0. */
		$conns .= "\t\t\t\tremote_ts     = dynamic[udp]\n";
		$conns .= "\t\t\t\tmode          = transport\n";
		$conns .= "\t\t\t\tesp_proposals = aes256-sha256,aes256-sha1,aes128-sha1\n";
		/* We can never initiate to a roaming client, and a trap policy here
		   would black-hole our own outbound UDP/1701. */
		$conns .= "\t\t\t\tstart_action  = none\n";
		$conns .= "\t\t\t\tdpd_action    = clear\n";
		$conns .= "\t\t\t}\n";
		$conns .= "\t\t}\n";
		$conns .= "\t}\n";
		$n++;

		$secrets .= "\tike-l2tp {\n";
		$secrets .= "\t\tid     = %any\n";
		$secrets .= "\t\tsecret = \"" . $l2tp_psk . "\"\n";
		$secrets .= "\t}\n";
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
	if (!empty($ls['address'])) {
		/* The GUI writes an explicit local subnet as "10.0.0.0/24" in
		   ['address'] -- there is no 'netbits' key -- so appending one
		   produced "10.0.0.0/24/32" and swanctl refused the connection. */
		if (strpos($ls['address'], '/') !== false)
			return $ls['address'];
		return $ls['address'] . (!empty($ls['netbits']) ? "/{$ls['netbits']}" : "/32");
	}

	return null;
}

/* Write the X.509 material charon needs onto disk.
 *
 * The webGUI stores certificates and private keys base64-encoded inside
 * config.xml. strongSwan does not read them from there: swanctl loads
 * credentials from files under its own directory, and the generator above
 * names those files. Until this existed the generator emitted
 * "certs = con0-local.crt" and nothing ever created con0-local.crt, so
 * certificate authentication could not work at all -- every RSA-signature
 * tunnel failed to load, with a message about a missing certificate.
 *
 * Everything is rewritten from config.xml on each call, so a tunnel that has
 * been deleted or switched to a pre-shared key does not leave its key behind
 * on a running firewall.
 */
function ipsec_ss_write_credentials() {
	global $config;

	$dirs = array('x509', 'private', 'x509ca');
	foreach ($dirs as $d) {
		@mkdir(SWANCTL_DIR . "/{$d}", 0700, true);
		/* clear what we wrote last time -- nothing else owns these */
		foreach ((array)@glob(SWANCTL_DIR . "/{$d}/*") as $old)
			@unlink($old);
	}

	$put = function ($rel, $b64, $mode) {
		if (empty($b64))
			return;
		$pem = base64_decode($b64);
		if ($pem === false || trim($pem) === '')
			return;
		$path = SWANCTL_DIR . "/" . $rel;
		$um = umask(0077);
		@file_put_contents($path, $pem);
		umask($um);
		@chmod($path, $mode);
	};

	$ipseccfg = isset($config['ipsec']) && is_array($config['ipsec']) ? $config['ipsec'] : array();

	/* CA and CRL certificates, shared by every tunnel. */
	$cacerts = (isset($ipseccfg['cacert']) && is_array($ipseccfg['cacert']))
	           ? $ipseccfg['cacert'] : array();
	foreach ($cacerts as $i => $ca) {
		if (empty($ca['cert']))
			continue;
		$put("x509ca/ca{$i}.crt", $ca['cert'], 0644);
	}

	/* Per-tunnel material. The names must match the generator exactly. */
	$tunnels = (isset($ipseccfg['tunnel']) && is_array($ipseccfg['tunnel']))
	           ? $ipseccfg['tunnel'] : array();
	foreach ($tunnels as $i => $tunnel) {
		if (isset($tunnel['disabled']) || empty($tunnel['remote-gateway']))
			continue;
		$p1 = isset($tunnel['p1']) ? $tunnel['p1'] : array();
		if (!empty($p1['pre-shared-key']))
			continue;                       /* psk tunnel: no files needed */
		$name = ipsec_ss_conn_name($i, $tunnel);
		$put("x509/{$name}-local.crt", isset($p1['cert']) ? $p1['cert'] : '', 0644);
		$put("x509/{$name}-peer.crt",  isset($p1['peercert']) ? $p1['peercert'] : '', 0644);
		$put("private/{$name}.key",    isset($p1['private-key']) ? $p1['private-key'] : '', 0600);
	}

	/* Road-warrior connection, if it authenticates with a certificate. */
	$mob = isset($ipseccfg['mobileclients']) && is_array($ipseccfg['mobileclients'])
	       ? $ipseccfg['mobileclients'] : array();
	if (isset($mob['enable']) && isset($mob['p1'])) {
		$put("x509/mobile-local.crt", isset($mob['p1']['cert']) ? $mob['p1']['cert'] : '', 0644);
		$put("private/mobile.key",    isset($mob['p1']['private-key']) ? $mob['p1']['private-key'] : '', 0600);
	}

	return 0;
}

/* ---------------------------------------------------------------------------
 * Starting it
 * ------------------------------------------------------------------------ */

function vpn_ipsec_configure($ipchg = false) {
	global $config, $g;

	$conf = "{$g['varetc_path']}/swanctl.conf";

	/* L2TP/IPsec needs charon too, and it is enabled independently of the
	   IPsec tunnel feature -- VPN > IPsec > L2TP is its own page. Testing only
	   $config['ipsec']['enable'] meant that turning on L2TP/IPsec without also
	   turning on IPsec tunnels tore charon DOWN, leaving the bare L2TP
	   listener this function is supposed to be protecting. */
	$l2tp_on = (($config['l2tp']['mode'] ?? '') == 'server')
	           && !empty($config['l2tp']['ipsec']['psk']);

	if (!isset($config['ipsec']['enable']) && !$l2tp_on) {
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
	@mkdir(SWANCTL_DIR, 0700, true);
	@copy($conf, SWANCTL_DIR . "/swanctl.conf");

	/* ... and its certificates and keys from files beside it. */
	ipsec_ss_write_credentials();

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

/* pgrep is not in the image, so the old exec() always failed and charon was
   relaunched (plus a 2 s sleep) on every call -- and a charon that had died
   looked exactly like one that was running. killall -0 signals nothing and
   just reports whether a process of that name exists. */
function is_process_running($name) {
	return mwexec("/usr/bin/killall -0 " . escapeshellarg($name) . " 2>/dev/null") == 0;
}
