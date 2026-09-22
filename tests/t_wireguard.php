<?php
/*
 * WireGuard peer manager: IPAM, validation and config generation.
 *
 * AllowedIPs is the entire security model of a WireGuard server -- cryptokey
 * routing means a peer may only send from the addresses listed against its
 * key. Getting a /32 wrong there lets one peer impersonate every other, so
 * that has dedicated tests.
 */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/xmlparse.inc';
require MW_ROOT . '/phpconf/inc/util.inc';
require MW_ROOT . '/phpconf/inc/wireguard.inc';

/* --- key validation ----------------------------------------------------- */
$good = base64_encode(str_repeat("\x01", 32));          /* 32 bytes -> 44 chars */
is_true ('valid 32-byte key',   wg_is_valid_key($good));
is_false('too short',           wg_is_valid_key(base64_encode(str_repeat("\x01", 16))));
is_false('too long',            wg_is_valid_key(base64_encode(str_repeat("\x01", 64))));
is_false('not base64',          wg_is_valid_key(str_repeat('!', 44)));
is_false('empty',               wg_is_valid_key(''));
is_false('non-string',          wg_is_valid_key(null));

/* --- peer names --------------------------------------------------------- */
is_true ('simple name',   wg_is_valid_peername('laptop'));
is_true ('dots + dashes', wg_is_valid_peername('my-phone.home'));
is_false('leading dash',  wg_is_valid_peername('-bad'));
is_false('spaces',        wg_is_valid_peername('my laptop'));
is_false('slash',         wg_is_valid_peername('a/b'));
is_false('empty',         wg_is_valid_peername(''));

/* --- endpoints ---------------------------------------------------------- */
is_true ('host:port',     wg_is_valid_endpoint('vpn.example.com:51820'));
is_true ('ip:port',       wg_is_valid_endpoint('203.0.113.5:51820'));
is_true ('empty is ok',   wg_is_valid_endpoint(''));
is_false('no port',       wg_is_valid_endpoint('vpn.example.com'));
is_false('port too high', wg_is_valid_endpoint('vpn.example.com:99999'));

/* --- IPAM: allocation, not DHCP ----------------------------------------- */
$tunnel = array(
    'if' => 'wg0', 'address' => '10.77.0.1', 'subnet' => '24',
    'privatekey' => $good, 'publickey' => $good, 'listenport' => '51820',
    'peer' => array(),
);
is_same('first allocation skips .0 and the server .1',
        wg_allocate_address($tunnel), '10.77.0.2');

$tunnel['peer'][] = array('name'=>'a','publickey'=>$good,'address'=>'10.77.0.2');
is_same('second allocation', wg_allocate_address($tunnel), '10.77.0.3');

/* a gap left by a deleted peer is reused rather than skipped */
$tunnel['peer'][] = array('name'=>'b','publickey'=>$good,'address'=>'10.77.0.4');
is_same('fills the gap', wg_allocate_address($tunnel), '10.77.0.3');

is_same('free count', wg_pool_free_count($tunnel), 254 - 3);

/* a /30 has exactly two host addresses; the server takes one */
$tiny = array('address'=>'10.0.0.1','subnet'=>'30','peer'=>array());
is_same('/30 first',  wg_allocate_address($tiny), '10.0.0.2');
$tiny['peer'][] = array('address'=>'10.0.0.2');
is_same('/30 exhausted', wg_allocate_address($tiny), null);
is_same('/31 rejected',  wg_allocate_address(array('address'=>'10.0.0.1','subnet'=>'31')), null);

/* --- server config ------------------------------------------------------ */
$k2 = base64_encode(str_repeat("\x02", 32));
$k3 = base64_encode(str_repeat("\x03", 32));
$t = array(
  'if'=>'wg0','address'=>'10.77.0.1','subnet'=>'24','listenport'=>'51820',
  'privatekey'=>$good,'publickey'=>$k2,
  'peer'=>array(
    array('name'=>'laptop','publickey'=>$k2,'address'=>'10.77.0.2'),
    array('name'=>'branch','publickey'=>$k3,'address'=>'10.77.0.3',
          'routes'=>'192.168.50.0/24','endpoint'=>'branch.example.com:51820','keepalive'=>'25'),
    array('name'=>'off','publickey'=>$k3,'address'=>'10.77.0.9','disabled'=>true),
  ),
);
$srv = wg_tunnel_config_generate($t);

is_true('has Interface section', strpos($srv, "[Interface]\nPrivateKey = $good") === 0);
is_true('listen port',           strpos($srv, 'ListenPort = 51820') !== false);
/* THE security property: each peer gets its own /32, never the subnet */
is_true('peer gets a /32',       strpos($srv, 'AllowedIPs = 10.77.0.2/32') !== false);
is_false('never the whole subnet', strpos($srv, 'AllowedIPs = 10.77.0.0/24') !== false);
is_true('site-to-site route appended',
        strpos($srv, 'AllowedIPs = 10.77.0.3/32, 192.168.50.0/24') !== false);
is_true('endpoint emitted',      strpos($srv, 'Endpoint = branch.example.com:51820') !== false);
is_true('keepalive emitted',     strpos($srv, 'PersistentKeepalive = 25') !== false);
is_false('disabled peer omitted',strpos($srv, '10.77.0.9') !== false);

/* --- client config ------------------------------------------------------ */
$peer = array('name'=>'laptop','publickey'=>$k2,'address'=>'10.77.0.2');
$cli  = wg_peer_config_generate($t, $peer, '', '203.0.113.5:51820');

is_true('client address is a /32', strpos($cli, 'Address = 10.77.0.2/32') !== false);
is_true('points at the server key', strpos($cli, "PublicKey = $k2") !== false);
is_true('server endpoint',          strpos($cli, 'Endpoint = 203.0.113.5:51820') !== false);
/* When the client supplied its own public key the firewall never held the
   private half, and the config must say so rather than invent one. */
is_true('private key left to the client',
        strpos($cli, "<insert this device's private key>") !== false);
is_true('routes the tunnel subnet by default',
        strpos($cli, 'AllowedIPs = 10.77.0.0/24') !== false);

$cli2 = wg_peer_config_generate($t, array_merge($peer, array('clientallowed'=>'0.0.0.0/0')), $k3, '203.0.113.5:51820');
is_true('full-tunnel honoured',  strpos($cli2, 'AllowedIPs = 0.0.0.0/0') !== false);
is_true('generated key embedded',strpos($cli2, "PrivateKey = $k3") !== false);

exit(mw_report('wireguard.inc'));
