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

/* nothing enabled */
$config['ipsec'] = array();
$empty = ipsec_ss_config_generate();
is_true ('empty config is still valid', strpos($empty, 'no enabled tunnels') !== false);

exit(mw_report('ipsec (strongSwan)'));
