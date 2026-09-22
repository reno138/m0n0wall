<?php
/* xmlparse.inc -- the single-XML config model that the whole product rests on.
   The round trip is the important one: it is what happens on every save. */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/xmlparse.inc';

$cfg = parse_xml_config(MW_ROOT . '/phpconf/config.xml', 'm0n0wall');

is_true ('parses to array',  is_array($cfg));
is_same('schema version',    $cfg['version'] ?? null, '2.0');
is_same('default hostname',  $cfg['system']['hostname'] ?? null, 'm0n0wall');
is_same('default LAN ip',    $cfg['interfaces']['lan']['ipaddr'] ?? null, '192.168.1.1');
is_same('default LAN mask',  $cfg['interfaces']['lan']['subnet'] ?? null, '24');
is_true ('has filter stanza',isset($cfg['filter']));
is_true ('has nat stanza',   isset($cfg['nat']));
is_true ('has system stanza',isset($cfg['system']));

/* dump -> reparse must reproduce the structure exactly, or saving settings
   silently mutates the configuration. */
$tmp = mw_sandbox() . '/roundtrip.xml';
file_put_contents($tmp, dump_xml_config($cfg, 'm0n0wall'));
$again = parse_xml_config($tmp, 'm0n0wall');
is_same('round trip identical', $again, $cfg);

/* ---- empty sections normalise to arrays -------------------------------
 * <nat></nat> parses to an empty STRING. Indexing that with a string key is
 * a fatal TypeError in PHP 8, and is_array() does not protect it because the
 * inner read happens first. With the shipped config that fatal fires inside
 * filter.inc before a single rule is generated, so the firewall never comes
 * up. parse_xml_config() now normalises empty top-level sections to arrays.
 */
foreach (array('staticroutes','nat','shaper','ipsec','aliases','proxyarp',
               'wol','bridge','diag','dnsupdate','syslog') as $sec) {
    is_true("section '$sec' is an array, not a string", is_array($cfg[$sec]));
}

/* The two genuine top-level scalars must be left alone. */
is_true('version stays a string',    is_string($cfg['version']));
is_true('lastchange stays a string', is_string($cfg['lastchange']));

/* The exact call that used to be fatal. */
$threw = false;
try { $x = is_array(@$cfg['staticroutes']['route']); }
catch (Throwable $e) { $threw = true; }
is_false('indexing an empty section no longer throws', $threw);

exit(mw_report('xmlparse.inc'));
