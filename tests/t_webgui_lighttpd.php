<?php
/*
 * webGUI server configuration for lighttpd.
 *
 * The critical assertion here is REMOTE_USER. mini_httpd enforced HTTP Basic
 * and PHP read $_SERVER['REMOTE_USER']; auth.inc uses it in 12 places to
 * apply per-group page permissions. If it stops arriving, every page either
 * denies everyone or admits everyone, depending on the code path -- and it
 * would not be obvious which.
 */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/xmlparse.inc';
require MW_ROOT . '/phpconf/inc/webgui_lighttpd.inc';

/* --- plain HTTP --------------------------------------------------------- */
$config = array('system' => array('webgui' => array('protocol' => 'http')));
$out = webgui_lighttpd_config_generate();

is_true('document root points at the GUI',
        strpos($out, 'server.document-root = "' . $g['www_path'] . '"') !== false);
is_true('defaults to port 80',      strpos($out, 'server.port          = 80') !== false);
/* lighttpd REFUSES "server.username = root" and exits. Omitting it makes it
   keep the uid it was started with -- root, via rc.bootup. Asserting the
   ABSENCE of the directive is the test, because setting it is what breaks. */
is_false('no server.username (lighttpd refuses uid 0)',
         strpos($out, 'server.username') !== false);
is_false('no TLS on plain http',    strpos($out, 'ssl.engine') !== false);

/* --- PHP backend -------------------------------------------------------- */
is_true('php-cgi over FastCGI',     strpos($out, '"bin-path"    => "/usr/local/bin/php-cgi"') !== false);
/* Without PHP_FCGI_CHILDREN, php-cgi exits after one request and lighttpd
   respawns it constantly -- it works, slowly, which is the worst failure. */
is_true('FastCGI children set',     strpos($out, 'PHP_FCGI_CHILDREN') !== false);
is_true('index.php is the index',   strpos($out, 'server.indexfiles    = ( "index.php" )') !== false);

/* --- authentication: the part auth.inc depends on ----------------------- */
is_true('htpasswd backend',         strpos($out, 'auth.backend                 = "htpasswd"') !== false);
is_true('reads the generated htpasswd',
        strpos($out, 'auth.backend.htpasswd.userfile = "' . $g['varrun_path'] . '/htpasswd"') !== false);
is_true('basic auth, valid-user',   strpos($out, '"method"  => "basic"') !== false
                                 && strpos($out, '"require" => "valid-user"') !== false);
is_true('protects the whole tree',  strpos($out, 'auth.require = ( "/" =>') !== false);
is_true('mod_authn_file loaded',    strpos($out, '"mod_authn_file"') !== false);

/* auth can be turned off deliberately */
$config['system']['webgui']['nopassword'] = true;
$noauth = webgui_lighttpd_config_generate();
is_false('nopassword disables auth', strpos($noauth, 'auth.require') !== false);
unset($config['system']['webgui']['nopassword']);

/* --- HTTPS -------------------------------------------------------------- */
$config['system']['webgui']['protocol'] = 'https';
$s = webgui_lighttpd_config_generate();
is_true('TLS enabled',              strpos($s, 'ssl.engine  = "enable"') !== false);
is_true('reads cert.pem',           strpos($s, 'ssl.pemfile = "' . $g['varetc_path'] . '/cert.pem"') !== false);
is_true('mod_openssl loaded',       strpos($s, '"mod_openssl"') !== false);
is_true('defaults to port 443',     strpos($s, 'server.port          = 443') !== false);
/* The patched mini_httpd disabled SSLv3 by hand after POODLE. A modern
   server should not be offering TLS 1.0 or 1.1 either. */
is_true('TLS 1.2 minimum',          strpos($s, '"MinProtocol" => "TLSv1.2"') !== false);

/* --- non-standard port -------------------------------------------------- */
$config['system']['webgui'] = array('protocol' => 'http', 'port' => '8080');
$p = webgui_lighttpd_config_generate();
is_true('custom port honoured',     strpos($p, 'server.port          = 8080') !== false);

exit(mw_report('webgui (lighttpd)'));
