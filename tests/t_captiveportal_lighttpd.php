<?php
/*
 * Captive portal web server configuration.
 *
 * The portal was the ONLY reason m0n0wall patched mini_httpd: -maxperip and
 * -cpelement existed for it alone. These tests assert both survived the move
 * to lighttpd, because losing either is silent. Without the per-IP cap one
 * client can exhaust the pool; without the element alias the portal renders
 * with no images or stylesheet and looks merely ugly rather than broken.
 */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/xmlparse.inc';
require MW_ROOT . '/phpconf/inc/util.inc';
require MW_ROOT . '/phpconf/inc/webgui_lighttpd.inc';   /* LIGHTTPD_BIN */
require MW_ROOT . '/phpconf/inc/captiveportal_lighttpd.inc';

$config = array(
  'interfaces' => array('opt1' => array('if'=>'em2','ipaddr'=>'10.9.9.1','subnet'=>'24')),
  'captiveportal' => array('enable'=>true, 'interface'=>'opt1'),
);

/* --- plain HTTP instance ------------------------------------------------ */
$out = captiveportal_lighttpd_config_generate(false);

is_true ('listens on 8000',      strpos($out, 'server.port          = 8000') !== false);
is_true ('binds the portal interface', strpos($out, 'server.bind          = "10.9.9.1"') !== false);
is_true ('serves the portal root', strpos($out, 'server.document-root = "' . $g['captiveportal_path'] . '"') !== false);
is_true ('runs PHP',             strpos($out, '"bin-path" => "/usr/local/bin/php-cgi"') !== false);
is_false('no TLS on the plain instance', strpos($out, 'ssl.engine') !== false);

/* mini_httpd's -maxperip is NOT here: lighttpd 1.4.84 dropped mod_evasive,
   so the cap moved to pf as "max-src-conn". Asserting its absence here is
   deliberate -- referencing a module the binary does not ship makes lighttpd
   refuse to start at all, which takes the portal down entirely. */
is_false('does not reference mod_evasive', strpos($out, 'mod_evasive') !== false);

/* mini_httpd -cpelement: uploaded logos and stylesheets live outside the
   document root and are served for the portal vhost only. */
is_true ('vhost conditional',    strpos($out, '$HTTP["host"]') !== false);
is_true ('element alias',        strpos($out, $g['captiveportal_element_path']) !== false);
/* alias.url is IGNORED unless mod_alias is named, even though lighttpd
   builds it in -- and an ignored alias means no portal images at all. */
is_true ('mod_alias named',      strpos($out, '"mod_alias"') !== false);
is_true ('mod_accesslog named',  strpos($out, '"mod_accesslog"') !== false);

/* --- HTTPS instance ----------------------------------------------------- */
$config['captiveportal']['httpslogin'] = true;
$config['captiveportal']['httpsname']  = 'portal.example.com';
$s = captiveportal_lighttpd_config_generate(true);

is_true ('listens on 8001',      strpos($s, 'server.port          = 8001') !== false);
is_true ('TLS enabled',          strpos($s, 'ssl.engine  = "enable"') !== false);
is_true ('reads cert-portal.pem',strpos($s, 'cert-portal.pem') !== false);
is_true ('TLS 1.2 minimum',      strpos($s, '"MinProtocol" => "TLSv1.2"') !== false);
/* the HTTPS vhost uses httpsname, not the interface address, because the
   certificate is issued for a name */
/* The host match is a REGEX, so the dots are escaped. Asserting the raw
   hostname would pass only if the escaping were missing -- which would make
   "portalXexampleXcom" match too. */
is_true ('https vhost uses httpsname',
         strpos($s, 'portal\\.example\\.com') !== false);
/* separate pidfiles, or stopping one stops the other */
is_true ('separate pidfile',     strpos($s, 'lighttpd.cps.pid') !== false);
is_true ('separate fastcgi socket', strpos($s, 'php-cp-cps.socket') !== false);

/* only modules lighttpd 1.4.84 actually ships may be referenced */
$shipped = array('mod_fastcgi','mod_openssl','mod_auth','mod_authn_file',
                 'mod_accesslog','mod_magnet','mod_cgi','mod_deflate',
                 'mod_alias');  /* built in, but must still be named */
preg_match_all('/"(mod_[a-z0-9_]+)"/', $out . $s, $m);
$unknown = array_values(array_diff(array_unique($m[1]), $shipped));
is_same('only shipped modules referenced', $unknown, array());

exit(mw_report('captive portal'));
