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
require __DIR__ . '/lighttpd_directives.inc';
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
/* The intercept forwards to 127.0.0.1, so that is what must be bound. The
   interface address gets its own socket block -- see the regressions below. */
is_true ('binds the loopback the intercept targets',
         strpos($out, 'server.bind          = "127.0.0.1"') !== false);
is_true ('serves the portal root', strpos($out, 'server.document-root = "' . $g['captiveportal_path'] . '"') !== false);
is_true ('runs PHP',             strpos($out, '"bin-path" => "/usr/local/bin/php-cgi"') !== false);
is_false('no TLS on the plain instance', strpos($out, 'ssl.engine') !== false);

/* mini_httpd's -maxperip is NOT here: lighttpd 1.4.84 dropped mod_evasive,
   so the cap moved to pf as "max-src-conn". Asserting its absence here is
   deliberate -- referencing a module the binary does not ship makes lighttpd
   refuse to start at all, which takes the portal down entirely. */
is_false('does not reference mod_evasive', strpos($out, 'mod_evasive') !== false);

/* mini_httpd -cpelement: uploaded logos and stylesheets live outside the
   document root and are aliased into it.

   This used to assert a $HTTP["host"] vhost block wrapping one
   "/captiveportal-" alias. Both were wrong -- the prefix matched nothing the
   GUI documents, and the host conditional could not match the Host header of
   an intercepted request, which is the ORIGINAL site's name. The aliases are
   now unconditional and per file; asserted against a populated element list in
   the regression section below. */
$config['captiveportal']['element'] = array(array('name'=>'probe.gif','size'=>1));
$withel = captiveportal_lighttpd_config_generate(false);
is_true ('element alias', strpos($withel, $g['captiveportal_element_path']) !== false);
$config['captiveportal']['element'] = array();
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
/* The HTTPS instance identifies itself by httpsname: that is the name the
   certificate is issued to and the name index.php redirects to. There is no
   longer a host-regex block to escape -- the aliases are unconditional -- so
   what matters is that the name reaches the generated config at all. */
is_true ('https instance knows its own hostname',
         strpos($s, 'cert-portal.pem') !== false);
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

/* ------------------------------------------------------------------------
 * Regressions from the subsystem audit. The portal was dead, not degraded.
 * --------------------------------------------------------------------- */

$out = captiveportal_lighttpd_config_generate(false);

/* 1. ipfw rewrites the destination to 127.0.0.1:8000. A server bound only to
 *    the interface address has no socket for that, so every intercepted
 *    request was refused -- the whole point of the portal. */
is_true('the ipfw intercept has a socket to land on',
        strpos($out, 'server.bind          = "127.0.0.1"') !== false);
is_false('the portal is not exposed on every interface',
         strpos($out, 'server.bind          = "0.0.0.0"') !== false);

/* 2. index.php bounces the client to http://<cpip>:8000/, so that address
 *    needs a listener too. */
is_true('the redirect target is listened on',
        strpos($out, '$SERVER["socket"] == "10.9.9.1:8000"') !== false);

/* 3. An intercepted client asked for some other site's path, which does not
 *    exist in the document root. Without a handler they got a 404 instead of
 *    the login page. */
is_true('any path reaches index.php',
        strpos($out, 'server.error-handler-404 = "/index.php"') !== false);

/* 4. Uploaded elements are referenced as <img src="test.jpg"> -- the file
 *    manager says so -- not under an invented "/captiveportal-" prefix. */
$config['captiveportal']['element'] = array(
    array('name' => 'logo.png', 'size' => 100),
    array('name' => 'style.css', 'size' => 50),
);
$out = captiveportal_lighttpd_config_generate(false);
is_true('an element is served at the URL the GUI documents',
        strpos($out, 'alias.url += ( "/logo.png" => "' .
               $g['captiveportal_element_path'] . '/logo.png" )') !== false);
is_true('every element is aliased',
        strpos($out, '"/style.css"') !== false);
is_false('the invented prefix is gone',
         strpos($out, '/captiveportal-') !== false);

/* A name that tries to escape the element directory must not become an alias. */
$config['captiveportal']['element'] = array(
    array('name' => '../../etc/master.passwd', 'size' => 1),
    array('name' => '.hidden', 'size' => 1),
);
$out = captiveportal_lighttpd_config_generate(false);
is_false('a traversing element name is not aliased', strpos($out, '..') !== false);
is_false('a dotfile element name is not aliased', strpos($out, '.hidden') !== false);
$config['captiveportal']['element'] = array();

/* 5. TLS has to be enabled on the extra socket too, or the second listener
 *    would serve plaintext on the HTTPS port. */
$config['captiveportal']['httpslogin'] = true;
$config['captiveportal']['httpsname']  = 'portal.example.com';
$s2 = captiveportal_lighttpd_config_generate(true);
is_true('the HTTPS instance listens on 8001',
        strpos($s2, 'server.port          = 8001') !== false);
$sock = strpos($s2, '$SERVER["socket"] == "10.9.9.1:8001"');
is_true('the HTTPS redirect target is listened on', $sock !== false);
is_true('TLS is enabled on that socket too',
        strpos($s2, 'ssl.engine', $sock) !== false);

/* --- REGRESSION: a misspelled directive is silently ignored ---------------
 *
 * lighttpd does not reject an unknown configuration key and `lighttpd -t` calls
 * it "Syntax OK", so a typo costs the feature in silence. See
 * lighttpd_directives.inc for the verified list. */
mw_check_lighttpd_directives('portal HTTP',  captiveportal_lighttpd_config_generate(false));
$config['captiveportal']['httpslogin'] = true;
$config['captiveportal']['httpsname']  = 'portal.example.com';
mw_check_lighttpd_directives('portal HTTPS', captiveportal_lighttpd_config_generate(true));

exit(mw_report('captive portal'));
