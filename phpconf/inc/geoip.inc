<?php
/*
	geoip.inc
	part of m0n0wall (http://m0n0.ch/wall)

	Blocking and passing by country, enforced with pf tables.

	Copyright (C) 2026 m0n0wall contributors.
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the conditions of the two-clause
	BSD licence carried by the rest of m0n0wall are met.
*/

/* ===========================================================================
 * Why it is built this way
 *
 * ENFORCEMENT IS pf TABLES. One table per country, referenced from ordinary
 * filter rules, so "Country" becomes just another kind of source or
 * destination and composes with direction, protocol, ports and logging
 * exactly as an address or an alias does. No new daemon, no new binary, and
 * `pfctl -t geo_CN -T show` tells you precisely what is loaded.
 *
 * DATA COMES FROM THE FIVE RIRs. ARIN, RIPE, APNIC, LACNIC and AFRINIC each
 * publish a "delegated-extended" file: plain text, no account, no key, no
 * licence terms to redistribute. MaxMind's GeoLite2 needs a signed-up licence
 * key and has redistribution conditions; ipdeny.com is a convenient mirror of
 * this same RIR data but puts a single third party in the path. The registries
 * are the authority for which organisation holds a range, which is the
 * question being asked.
 *
 * THE FILES ARE NEVER STORED. All five together are around 40 MB, and /var/db
 * lives on the root RAM disk -- 98 MB total with single-digit megabytes free.
 * So geoip_update() streams each file over HTTPS and keeps only the lines for
 * the countries actually in use, which is a handful. One country is roughly
 * 100-200 KB of CIDRs.
 *
 * ONLY COUNTRIES IN USE ARE FETCHED. geoip_countries_in_use() reads the rule
 * set; nothing is downloaded for a country no rule mentions.
 *
 * IT FAILS OPEN, AND THAT IS VISIBLE. /var/db is a RAM disk, so after a reboot
 * the tables are empty until the first refresh succeeds -- and a box whose WAN
 * is not up yet cannot refresh. An empty pf table matches nothing, so a
 * country block rule is a no-op until the data arrives. That is the safe
 * direction for reachability and the unsafe one for filtering, so it is not
 * hidden: the table is still declared (the rule set always loads), the status
 * page shows each country's prefix count and age, and a count of zero is
 * called out there. Do not infer protection from the presence of a rule --
 * check the count.
 * ===========================================================================
 */

define('GEOIP_DIR', '/var/db/geoip');

/* The registries, in the order they are tried. */
function geoip_rirs() {
	return array(
		'arin'    => 'https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest',
		'ripencc' => 'https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest',
		'apnic'   => 'https://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest',
		'lacnic'  => 'https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest',
		'afrinic' => 'https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest',
	);
}

/* pf table name for a country. Lower case would collide with nothing, but
   upper case matches how the registries and the GUI spell it. */
function geoip_table_name($cc) {
	return "geo_" . strtoupper(preg_replace('/[^A-Za-z]/', '', $cc));
}

function geoip_file($cc) {
	return GEOIP_DIR . "/" . strtoupper(preg_replace('/[^A-Za-z]/', '', $cc)) . ".txt";
}

/* A two-letter ISO country code, and nothing else -- these end up in a
   filename and in a pf table name. */
function is_country_code($cc) {
	return is_string($cc) && preg_match('/^[A-Za-z]{2}$/', $cc) === 1;
}

/* Split a start address and an address COUNT into aligned CIDR blocks.
 *
 * The registries publish ranges as "first address plus how many addresses",
 * and that count is not required to be a power of two -- 8.8.8.0 with 512 is
 * one /23, but 1.2.3.0 with 768 is a /24 plus a /23. Each emitted block has
 * to be no larger than the alignment of its own start address, or it would
 * cover addresses below it.
 */
function geoip_v4_range_to_cidrs($start_ip, $count) {
	$out = array();
	$start = ip2long($start_ip);
	if ($start === false || $count < 1)
		return $out;
	$start = $start & 0xFFFFFFFF;
	$count = (int)$count;

	while ($count > 0) {
		/* how big a block may start here: the lowest set bit of the address */
		$align = ($start == 0) ? 0x80000000 : ($start & -$start);
		/* the largest power of two not exceeding what is left */
		$size = 1;
		while (($size << 1) <= $count && ($size << 1) > 0)
			$size <<= 1;
		if ($size > $align)
			$size = $align;

		$bits = 32 - (int)round(log($size, 2));
		$out[] = long2ip($start) . "/" . $bits;

		$start += $size;
		$count -= $size;
	}
	return $out;
}

/* Parse one delegated-extended line.
 *
 * registry|cc|type|start|value|date|status[|opaque-id|...]
 *   ipv4: value is a COUNT of addresses
 *   ipv6: value is a prefix LENGTH
 * Summary lines ("...|*|ipv4|*|12345|summary") and comments are skipped, as
 * are records with no country or a status that is not an actual allocation.
 */
function geoip_parse_line($line, $want = null) {
	$line = trim($line);
	if ($line === '' || $line[0] == '#')
		return null;

	$f = explode('|', $line);
	if (count($f) < 7)
		return null;
	list($registry, $cc, $type, $start, $value, $date, $status) = $f;

	if ($cc === '' || $cc === '*' || !is_country_code($cc))
		return null;
	if ($status !== 'allocated' && $status !== 'assigned')
		return null;
	if ($want !== null && !in_array(strtoupper($cc), $want, true))
		return null;

	if ($type === 'ipv4')
		return array(strtoupper($cc), geoip_v4_range_to_cidrs($start, (int)$value));
	if ($type === 'ipv6') {
		$len = (int)$value;
		if ($len < 1 || $len > 128 || strpos($start, ':') === false)
			return null;
		return array(strtoupper($cc), array($start . "/" . $len));
	}
	return null;
}

/* Country codes any enabled filter rule refers to, plus any the GeoIP page
   has been told to keep up to date even though no rule uses them yet. */
function geoip_countries_in_use() {
	global $config;

	$ccs = array();

	$rules = (isset($config['filter']['rule']) && is_array($config['filter']['rule']))
	         ? $config['filter']['rule'] : array();
	foreach ($rules as $rule) {
		if (!is_array($rule) || isset($rule['disabled']))
			continue;
		foreach (array('source', 'destination') as $side) {
			if (!isset($rule[$side]) || !is_array($rule[$side]))
				continue;
			if (!empty($rule[$side]['country'])) {
				foreach (explode(',', $rule[$side]['country']) as $cc)
					if (is_country_code(trim($cc)))
						$ccs[strtoupper(trim($cc))] = true;
			}
		}
	}

	if (isset($config['geoip']['country']) && is_array($config['geoip']['country'])) {
		foreach ($config['geoip']['country'] as $cc)
			if (is_country_code($cc))
				$ccs[strtoupper($cc)] = true;
	}

	$out = array_keys($ccs);
	sort($out);
	return $out;
}

/* Refresh the tables for the countries in use.
 *
 * Streams each registry file line by line and keeps only what is wanted, so
 * peak memory is the prefixes for the requested countries and never the ~40 MB
 * of source data. Writes each country's file atomically, and leaves the
 * previous file in place if a registry cannot be reached -- stale data blocks
 * more accurately than no data.
 *
 * Returns array(array $written, array $errors).
 */
function geoip_update($ccs = null) {
	global $config;

	if ($ccs === null)
		$ccs = geoip_countries_in_use();
	$ccs = array_values(array_filter(array_map('strtoupper', (array)$ccs), 'is_country_code'));
	if (empty($ccs))
		return array(array(), array());

	@mkdir(GEOIP_DIR, 0755, true);

	$prefixes = array();
	foreach ($ccs as $cc)
		$prefixes[$cc] = array();

	$errors = array();
	$ctx = stream_context_create(array(
		'http' => array('timeout' => 60,
		                'header'  => "User-Agent: m0n0wall/" . trim(@file_get_contents("/etc/version"))),
		'ssl'  => array('verify_peer' => true, 'verify_peer_name' => true,
		                'cafile' => '/usr/local/etc/ssl/cert.pem'),
	));

	$got_any = false;
	foreach (geoip_rirs() as $name => $url) {
		$fh = @fopen($url, 'r', false, $ctx);
		if (!$fh) {
			$errors[] = "{$name}: could not be fetched";
			continue;
		}
		$got_any = true;
		while (($line = fgets($fh)) !== false) {
			$p = geoip_parse_line($line, $ccs);
			if ($p === null)
				continue;
			foreach ($p[1] as $cidr)
				$prefixes[$p[0]][] = $cidr;
		}
		fclose($fh);
	}

	if (!$got_any) {
		$errors[] = "no registry could be reached; the existing tables are unchanged";
		return array(array(), $errors);
	}

	$written = array();
	foreach ($ccs as $cc) {
		if (empty($prefixes[$cc])) {
			$errors[] = "{$cc}: no ranges found (leaving any existing table alone)";
			continue;
		}
		$path = geoip_file($cc);
		$tmp  = $path . ".new";
		if (@file_put_contents($tmp, implode("\n", $prefixes[$cc]) . "\n") === false) {
			$errors[] = "{$cc}: could not be written (is /var full?)";
			@unlink($tmp);
			continue;
		}
		@rename($tmp, $path);
		$written[$cc] = count($prefixes[$cc]);
	}

	return array($written, $errors);
}

/* Load the on-disk tables into a running pf without rebuilding the rule set.
   -T replace is atomic from the rule set's point of view. */
function geoip_tables_reload() {
	$n = 0;
	foreach (geoip_countries_in_use() as $cc) {
		$f = geoip_file($cc);
		if (!file_exists($f))
			continue;
		mwexec("/sbin/pfctl -t " . escapeshellarg(geoip_table_name($cc)) .
		       " -T replace -f " . escapeshellarg($f) . " 2>/dev/null");
		$n++;
	}
	return $n;
}

/* Per-country age and size, for the status page. */
function geoip_status() {
	$out = array();
	foreach (geoip_countries_in_use() as $cc) {
		$f = geoip_file($cc);
		$out[$cc] = array(
			'file'     => $f,
			'exists'   => file_exists($f),
			'prefixes' => file_exists($f) ? max(0, count(file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES))) : 0,
			'updated'  => file_exists($f) ? filemtime($f) : 0,
		);
	}
	return $out;
}

/* Periodic refresh.
 *
 * minicron, the same three-line daemon the captive portal uses for its prune
 * job, rather than croen: croen's jobsets are the user's scheduled actions and
 * this is housekeeping. Default weekly -- the registries publish daily, but a
 * country's ranges move slowly and every refresh costs a full pass over ~40 MB
 * of source data.
 */
function services_geoip_configure() {
	global $config, $g;

	killbypid("{$g['varrun_path']}/geoipcron.pid");

	$ccs = geoip_countries_in_use();
	if (empty($ccs))
		return 0;                       /* nothing refers to a country */

	if ($g['booting'])
		echo "Starting GeoIP updater... ";

	/* hours in the config, seconds for minicron; 0 disables the timer and
	   leaves manual updates only */
	$hours = isset($config['geoip']['interval']) ? (int)$config['geoip']['interval'] : 168;
	if ($hours > 0)
		mwexec("/usr/local/bin/minicron " . ($hours * 3600) . " " .
		       "{$g['varrun_path']}/geoipcron.pid /etc/rc.geoipupdate");

	if ($g['booting'])
		echo "done\n";

	return 0;
}
