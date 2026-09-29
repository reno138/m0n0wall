<?php
/*
 * IPsec configuration for strongSwan.
 *
 * racoon and strongSwan spell algorithms differently and a wrong name does
 * not fail loudly -- the tunnel simply negotiates nothing, reporting that no
 * proposal was chosen, which looks like a remote-end problem. So the mapping
 * gets the most attention here.
 */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/xmlparse.inc';
require MW_ROOT . '/phpconf/inc/util.inc';
/* The L2TP connection needs the WAN address, because a traffic selector cannot
   say "whatever my address is". Stubbed here; rc.newwanip regenerates the real
   file when a dynamic lease changes. */
function get_current_wan_address($ipv6 = false) { return '203.0.113.5'; }

require MW_ROOT . '/phpconf/inc/ipsec_strongswan.inc';

/* --- algorithm names ---------------------------------------------------- */
is_same('3des',            ipsec_ss_enc('3des'),            '3des');
is_same('rijndael -> aes', ipsec_ss_enc('rijndael', '256'), 'aes256');
is_same('aes keylen',      ipsec_ss_enc('aes', '128'),      'aes128');
is_same('aes default 128', ipsec_ss_enc('aes'),             'aes128');
is_same('unknown -> aes256', ipsec_ss_enc('nonsense'),      'aes256');
is_same('sha1',            ipsec_ss_hash('sha1'),           'sha1');
is_same('sha256',          ipsec_ss_hash('sha256'),         'sha256');
is_same('unknown hash -> sha256', ipsec_ss_hash('zzz'),     'sha256');

/* DH group numbers to names. Getting these wrong is the classic cause of a
   tunnel that never comes up. */
is_same('DH 1',  ipsec_ss_dh(1),  'modp768');
is_same('DH 2',  ipsec_ss_dh(2),  'modp1024');
is_same('DH 5',  ipsec_ss_dh(5),  'modp1536');
is_same('DH 14', ipsec_ss_dh(14), 'modp2048');
is_same('DH 19', ipsec_ss_dh(19), 'ecp256');
is_same('DH unknown -> modp2048', ipsec_ss_dh(999), 'modp2048');

/* --- proposals ---------------------------------------------------------- */
is_same('phase 1 proposal',
        ipsec_ss_p1_proposal(array('encryption-algorithm'=>'aes','encryption-algorithm-keylen'=>'256',
                                   'hash-algorithm'=>'sha256','dhgroup'=>'14')),
        'aes256-sha256-modp2048');

/* m0n0wall lets phase 2 offer SEVERAL algorithms; strongSwan wants a
   comma-separated list of complete proposals, so this is a cross product. */
is_same('phase 2 cross product',
        ipsec_ss_p2_proposals(array(
            'encryption-algorithm-option' => array('aes256','3des'),
            'hash-algorithm-option'       => array('sha256','sha1'),
            'pfsgroup'                    => '14')),
        'aes256-sha256-modp2048,aes256-sha1-modp2048,3des-sha256-modp2048,3des-sha1-modp2048');

is_same('phase 2 without PFS omits the DH group',
        ipsec_ss_p2_proposals(array('encryption-algorithm-option'=>'aes256',
                                    'hash-algorithm-option'=>'sha256','pfsgroup'=>'0')),
        'aes256-sha256');

/* --- a whole configuration ---------------------------------------------- */
$config = array(
  'interfaces' => array('lan' => array('if'=>'em1','ipaddr'=>'192.168.1.1','subnet'=>'24')),
  'ipsec' => array('enable' => true, 'tunnel' => array(
    array('descr'=>'branch','interface'=>'wan','remote-gateway'=>'203.0.113.9',
          'auto'=>true,'dpddelay'=>'30',
          'local-subnet'=>array('network'=>'lan'),
          'remote-subnet'=>'10.50.0.0/24',
          'p1'=>array('mode'=>'main','encryption-algorithm'=>'aes',
                      'encryption-algorithm-keylen'=>'256','hash-algorithm'=>'sha256',
                      'dhgroup'=>'14','lifetime'=>'28800','pre-shared-key'=>'sekrit'),
          'p2'=>array('encryption-algorithm-option'=>array('aes256'),
                      'hash-algorithm-option'=>array('sha256'),
                      'pfsgroup'=>'14','lifetime'=>'3600')),
    array('descr'=>'off','remote-gateway'=>'198.51.100.1','disabled'=>true,
          'p1'=>array(),'p2'=>array()),
  )),
);
$out = ipsec_ss_config_generate();

is_true ('has a connections block', strpos($out, 'connections {') !== false);
is_true ('names the connection',    strpos($out, 'con0_branch {') !== false);
is_true ('remote gateway',          strpos($out, 'remote_addrs = 203.0.113.9') !== false);
/* p1 mode 'main' is an IKEv1 concept */
is_true ('main mode selects IKEv1', strpos($out, 'version      = 1') !== false);
is_true ('p1 proposal',             strpos($out, 'proposals    = aes256-sha256-modp2048') !== false);
is_true ('rekey from p1 lifetime',  strpos($out, 'rekey_time   = 28800s') !== false);
is_true ('dpd delay',               strpos($out, 'dpd_delay    = 30s') !== false);
/* local-subnet 'lan' must resolve to the interface's network */
is_true ('local_ts resolved from lan', strpos($out, 'local_ts      = 192.168.1.0/24') !== false);
is_true ('remote_ts',               strpos($out, 'remote_ts     = 10.50.0.0/24') !== false);
is_true ('esp proposals',           strpos($out, 'esp_proposals = aes256-sha256-modp2048') !== false);
is_true ('auto means start at boot',strpos($out, 'start_action  = start') !== false);
is_true ('psk auth',                strpos($out, 'auth = psk') !== false);
/* the PSK belongs in secrets{}, not in the connection */
is_true ('secret in secrets block', strpos($out, 'secret = "sekrit"') !== false);
is_true ('secret keyed by peer id', strpos($out, 'ike-con0_branch {') !== false);
is_false('disabled tunnel omitted', strpos($out, '198.51.100.1') !== false);

/* IKEv2 is the default for anything not explicitly IKEv1 */
$config['ipsec']['tunnel'][0]['p1']['mode'] = '';
$v2 = ipsec_ss_config_generate();
is_true ('no mode means IKEv2',     strpos($v2, 'version      = 2') !== false);

/* The webGUI's new-tunnel and mobile defaults (2026-09-29), exactly as the
   pages store them -- 'ikev2' as the mode, 'rijndael 256' as the lists spell
   AES-256, and hmac_-prefixed phase-2 hashes. They must come out as IKEv2
   with aes256-sha256-modp2048 in BOTH phases, PFS included. */
$config['ipsec']['tunnel'][0]['p1'] = array('mode'=>'ikev2','encryption-algorithm'=>'rijndael 256',
    'hash-algorithm'=>'sha256','dhgroup'=>'14','pre-shared-key'=>'sekrit');
$config['ipsec']['tunnel'][0]['p2'] = array('encryption-algorithm-option'=>array('rijndael 256'),
    'hash-algorithm-option'=>array('hmac_sha256'),'pfsgroup'=>'14');
$d = ipsec_ss_config_generate();
is_true ('default mode "ikev2" negotiates IKEv2', strpos($d, 'version      = 2') !== false);
is_false('and is not aggressive',                 strpos($d, 'aggressive') !== false);
is_true ('default IKE proposal',  strpos($d, 'proposals    = aes256-sha256-modp2048') !== false);
is_true ('default ESP proposal, with PFS',
         strpos($d, 'esp_proposals = aes256-sha256-modp2048') !== false);
is_false('no 3des/md5/sha1/modp1024 anywhere in a default tunnel',
         preg_match('/3des|md5|sha1|modp1024/', $d) === 1);
/* the ECP groups the lists now offer are real */
is_same ('group 19 is ecp256', ipsec_ss_dh('19'), 'ecp256');
is_same ('group 20 is ecp384', ipsec_ss_dh('20'), 'ecp384');

/* nothing enabled */
$config['ipsec'] = array();
$empty = ipsec_ss_config_generate();
is_true ('empty config is still valid', strpos($empty, 'no enabled tunnels') !== false);

/* --- REGRESSION: L2TP/IPsec generated NOTHING ----------------------------
 *
 * vpn.inc started mpd5 listening on UDP/1701 and the page collected a
 * pre-shared key, but no IPsec half was ever generated -- racoon used to do it
 * and strongSwan had no L2TP awareness at all. So enabling "L2TP/IPsec" gave a
 * bare, unencrypted L2TP listener: no standard client would connect, and the
 * PSK configured nothing.
 *
 * Every assertion below was checked against a real strongSwan 6.1.0 by loading
 * the generated file with 'swanctl --load-all'. Two of them exist because that
 * run REJECTED the first attempt. */
$config = array(
  'interfaces' => array(
    'lan' => array('if'=>'em1','ipaddr'=>'10.0.0.1','subnet'=>'24'),
    'wan' => array('if'=>'em0','ipaddr'=>'dhcp'),
  ),
  'l2tp' => array(
    'mode'     => 'server',
    'localip'  => '10.9.9.1',
    'remoteip' => '10.9.9.128',
    'nunits'   => '16',
    'ipsec'    => array('psk' => 's3cr3t-psk'),
  ),
);
$l = ipsec_ss_config_generate();

is_true ('an L2TP connection is generated',  strpos($l, "\tl2tp {") !== false);
is_true ('the PSK reaches the secrets',      strpos($l, 'secret = "s3cr3t-psk"') !== false);
is_true ('any client identity may use it',   strpos($l, 'id     = %any') !== false);
is_true ('it accepts from anywhere',         strpos($l, 'remote_addrs = %any') !== false);

/* IKEv1 is not a style choice here: every L2TP/IPsec client implementation
   (Windows, macOS, iOS, Android) speaks IKEv1 only. */
is_true ('it is IKEv1',                      strpos($l, "version      = 1") !== false);

/* TRANSPORT, not tunnel. L2TP carries its own PPP session, so IPsec protects
   the UDP/1701 datagrams in place; a tunnel-mode SA would not match what the
   client proposes. Tunnel mode is the default, so this must be explicit. */
is_true ('the child SA is transport mode',   strpos($l, 'mode          = transport') !== false);

/* Port-specific selectors. 0.0.0.0/0 would capture traffic unrelated to L2TP. */
is_true ('our selector is UDP 1701',         strpos($l, 'local_ts      = 203.0.113.5[udp/1701]') !== false);

/* swanctl REJECTS a %any port with "invalid value for: remote_ts, config
   discarded" -- which would have discarded the whole connection and left the
   listener unprotected again. Omitting the port is how strongSwan says "any",
   and NAT rewrites the client's source port so it has to be any. */
is_true ('the client selector is any UDP port', strpos($l, 'remote_ts     = dynamic[udp]') !== false);
is_false('and never a %any port',               strpos($l, 'udp/%any') !== false);

/* Almost every client is behind NAT, and NAT rewrites the port the selectors
   are negotiated against, so UDP encapsulation has to be forced. */
is_true ('UDP encapsulation is forced',      strpos($l, 'encap        = yes') !== false);

/* We can never initiate to a roaming client, and a trap policy would
   black-hole our own outbound UDP/1701. */
is_true ('it never initiates',               strpos($l, 'start_action  = none') !== false);

/* Weak algorithms must not creep in for the sake of interoperability. */
is_false('no DES',                           strpos($l, '3des') !== false);
is_false('no MD5',                           strpos($l, 'md5') !== false);

/* Turning the server off must remove it, not leave a listener configured. */
$config['l2tp']['mode'] = 'off';
is_false('L2TP off generates no connection', strpos(ipsec_ss_config_generate(), "\tl2tp {") !== false);

/* A server with no PSK cannot be protected, so it must not be half-configured:
   the page makes the key mandatory, and this is the backstop. */
$config['l2tp']['mode'] = 'server';
$config['l2tp']['ipsec']['psk'] = '';
is_false('no PSK generates no connection',   strpos(ipsec_ss_config_generate(), "\tl2tp {") !== false);

exit(mw_report('ipsec (strongSwan)'));
