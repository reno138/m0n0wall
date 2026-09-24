<?php
/*
 * geoip.inc -- the range arithmetic and the registry line parser.
 *
 * These two are worth testing hard: a wrong CIDR split silently blocks or
 * admits addresses that were never in the registry's range, and the country
 * code from a registry line ends up in both a filename and a pf table name.
 */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/geoip.inc';

/* --- start+count to aligned CIDRs -------------------------------------- */
is_same('exact /24',           geoip_v4_range_to_cidrs("8.8.8.0", 256), array("8.8.8.0/24"));
is_same('aligned /23',         geoip_v4_range_to_cidrs("8.8.8.0", 512), array("8.8.8.0/23"));
is_same('misaligned 512 splits', geoip_v4_range_to_cidrs("8.8.9.0", 512),
        array("8.8.9.0/24", "8.8.10.0/24"));
is_same('count not a power of two', geoip_v4_range_to_cidrs("1.2.3.0", 768),
        array("1.2.3.0/24", "1.2.4.0/23"));
is_same('single address',      geoip_v4_range_to_cidrs("10.0.0.1", 1), array("10.0.0.1/32"));
is_same('zero count',          geoip_v4_range_to_cidrs("0.0.0.0", 0), array());
is_same('unparseable start',   geoip_v4_range_to_cidrs("nonsense", 256), array());

/* Checked arithmetically rather than by eye: every block must start where the
   previous one ended, be aligned to its own size, and the set must cover
   exactly the requested number of addresses. */
$why = '';
foreach (array(array("1.2.3.0",768), array("8.8.9.0",512), array("192.168.0.0",1024),
               array("172.16.5.128",384), array("203.0.113.7",9)) as $c) {
	$blocks = geoip_v4_range_to_cidrs($c[0], $c[1]);
	$total = 0; $expect = ip2long($c[0]);
	foreach ($blocks as $b) {
		list($ip, $bits) = explode("/", $b);
		$size = 1 << (32 - (int)$bits);
		if (ip2long($ip) != $expect)      { $why = "$b not contiguous in {$c[0]}+{$c[1]}"; break; }
		if (ip2long($ip) % $size != 0)    { $why = "$b not aligned to its own size"; break; }
		$total += $size; $expect += $size;
	}
	if ($why === '' && $total != $c[1])   $why = "{$c[0]}+{$c[1]} covered $total addresses";
	if ($why !== '') break;
}
is_same('blocks contiguous, self-aligned, exact coverage', $why, '');

/* --- registry line parsing --------------------------------------------- */
is_same('ipv4 allocated', geoip_parse_line("arin|US|ipv4|8.0.0.0|256|19921201|allocated"),
        array("US", array("8.0.0.0/24")));
is_same('ipv6 uses prefix length', geoip_parse_line("apnic|CN|ipv6|2001:db8::|32|20110101|assigned"),
        array("CN", array("2001:db8::/32")));
is_same('summary line',   geoip_parse_line("arin|*|ipv4|*|12345|summary"), null);
is_same('comment',        geoip_parse_line("# comment"), null);
is_same('blank',          geoip_parse_line(""), null);
is_same('reserved is not an allocation',
        geoip_parse_line("arin|US|ipv4|8.0.0.0|256|19921201|reserved"), null);
is_same('non-ISO country code rejected',
        geoip_parse_line("arin|ZZZ|ipv4|8.0.0.0|256|1992|allocated"), null);
is_same('asn records ignored', geoip_parse_line("arin|US|asn|1234|1|1992|allocated"), null);
is_same('filtered when another country is wanted',
        geoip_parse_line("arin|US|ipv4|8.0.0.0|256|19921201|allocated", array("CN")), null);
is_same('kept when wanted',
        geoip_parse_line("arin|US|ipv4|8.0.0.0|256|19921201|allocated", array("US")),
        array("US", array("8.0.0.0/24")));

/* --- names that become filenames and pf table names -------------------- */
is_same('table name upper case',        geoip_table_name("cn"), "geo_CN");
is_same('table name strips non-letters', geoip_table_name("c/../n"), "geo_CN");
is_true('filename cannot traverse',     strpos(geoip_file("../../etc/passwd"), "..") === false);
is_true('country code accepts US',      is_country_code("US"));
is_false('rejects three letters',       is_country_code("USA"));
is_false('rejects a digit',             is_country_code("U1"));
is_false('rejects empty',               is_country_code(""));
is_false('rejects null',                is_country_code(null));

/* --- config round trip ------------------------------------------------- */
/* The settings this feature writes must survive dump_xml_config() and come
   back through parse_xml_config(). A numerically-indexed array whose key is
   not in $listtags serialises as <0>AD</0>, which is not a legal XML element
   name -- the file then fails to parse and every page dies with "XML error:
   XML_ERR_NAME_REQUIRED". That happened; this is the guard. */
require MW_ROOT . '/phpconf/inc/xmlparse.inc';

$cfg = array(
	'system' => array('hostname' => 'm0n0wall'),
	'geoip'  => array('interval' => 168, 'country' => 'AD,US'),
	'filter' => array('rule' => array(
		array('type' => 'block', 'interface' => 'wan',
		      'source' => array('country' => 'CN,RU'),
		      'destination' => array('any' => true)),
	)),
);
$xml = dump_xml_config($cfg, 'm0n0wall');
is_true('serialised config has no numeric element name',
        preg_match('/<\/?\d+[\s>]/', $xml) === 0);

$tmp = tempnam(sys_get_temp_dir(), 'geoipcfg');
file_put_contents($tmp, $xml);
$back = parse_xml_config($tmp, 'm0n0wall');
unlink($tmp);
is_true('config survives the round trip', is_array($back));
is_same('geoip country preserved',        $back['geoip']['country'] ?? null, 'AD,US');
is_same('geoip interval preserved',       $back['geoip']['interval'] ?? null, '168');
is_same('rule country preserved',         $back['filter']['rule'][0]['source']['country'] ?? null, 'CN,RU');

exit(mw_report('geoip.inc'));
