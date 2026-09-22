<?php
/*
 * Dynamic DNS.
 *
 * URL construction and response interpretation are tested; the HTTPS request
 * itself is not, since that would need a network and a real account. The
 * value here is that a malformed URL or a misread response is silent -- the
 * update simply never lands, and the first sign is a stale DNS record.
 */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/xmlparse.inc';
require MW_ROOT . '/phpconf/inc/util.inc';
require MW_ROOT . '/phpconf/inc/dyndns.inc';

$p = dyndns_providers();

/* --- registry ----------------------------------------------------------- */
is_true ('registry is populated',     count($p) >= 10);
is_true ('has Cloudflare',            isset($p['cloudflare']));
is_true ('has Duck DNS',              isset($p['duckdns']));
is_true ('has deSEC',                 isset($p['desec']));
is_true ('has No-IP',                 isset($p['noip']));
/* the dead 2003-era ones must be gone */
is_false('DHS removed',               isset($p['dhs']));
is_false('ODS removed',               isset($p['ods']));
is_false('TZO removed',               isset($p['tzo']));
is_false('EZ-IP removed',             isset($p['ezip']));

/* every entry must name an implemented protocol, or the GUI offers a
   provider that cannot work */
$impl = array('dyndns2', 'token', 'cloudflare');
$bad = array();
foreach ($p as $k => $v) {
    if (!isset($v['proto']) || !in_array($v['proto'], $impl)) $bad[] = $k;
    if (!isset($v['name']) || $v['name'] === '') $bad[] = "$k (no name)";
    if ($v['proto'] === 'token' && empty($v['url'])) $bad[] = "$k (token, no url)";
    if ($v['proto'] === 'dyndns2' && empty($v['host'])) $bad[] = "$k (dyndns2, no host)";
}
is_same('every provider is implemented and complete', $bad, array());

/* --- token URL construction -------------------------------------------- */
$u = dyndns_token_url($p['duckdns'], 'myhost', '', 'tok123', '203.0.113.5');
is_same('duckdns url', $u,
        'https://www.duckdns.org/update?domains=myhost&token=tok123&ip=203.0.113.5');

$u = dyndns_token_url($p['dynv6'], 'a.dynv6.net', '', 'tk', '198.51.100.7');
is_true ('dynv6 carries hostname',  strpos($u, 'hostname=a.dynv6.net') !== false);
is_true ('dynv6 carries ipv4',      strpos($u, 'ipv4=198.51.100.7') !== false);

/* values must be URL-encoded: an unencoded '&' or '+' in a token silently
   truncates the request and the update fails with no error */
$u = dyndns_token_url($p['duckdns'], 'h', '', 'a&b c+d', '1.2.3.4');
is_true ('token is url-encoded',    strpos($u, 'a%26b%20c%2Bd') !== false);
is_false('raw ampersand not passed',strpos($u, 'token=a&b') !== false);

/* --- unknown provider --------------------------------------------------- */
list($ok, $msg) = dyndns_update('nosuchprovider', 'h', 'u', 'p', '1.2.3.4');
is_false('unknown provider fails',  $ok);
is_true ('and says so',             strpos($msg, 'nosuchprovider') !== false);

/* --- Cloudflare needs a zone id ----------------------------------------- */
list($ok, $msg) = dyndns_update('cloudflare', 'h.example.com', '', 'token', '1.2.3.4');
is_false('cloudflare without zone id fails', $ok);
is_true ('and explains why',        stripos($msg, 'zone id') !== false);

exit(mw_report('dyndns'));
