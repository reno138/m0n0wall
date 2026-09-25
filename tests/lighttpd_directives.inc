<?php
/*
 * The lighttpd directives these generators are allowed to emit.
 *
 * Why an allowlist exists at all: lighttpd SILENTLY IGNORES a configuration key
 * it does not recognise. It does not warn, and `lighttpd -t` reports "Syntax OK"
 * for a misspelled directive -- verified against lighttpd 1.4.84 by feeding it
 * "server.max-connections-typo", which it accepted without comment. So a typo
 * costs you the feature and nothing tells you, which is precisely how the
 * captive portal's element alias came to 404 for every uploaded logo.
 *
 * Every name below was checked against the real lighttpd 1.4.84 shipped in this
 * image, searching the binary AND /usr/local/lib/lighttpd/*.so -- the module
 * directives (accesslog, openssl, auth) live in their own objects, so searching
 * only the binary wrongly reports five of these as missing.
 *
 * Adding a directive here is the point: it forces you to confirm the spelling
 * against the binary rather than trusting that a config which loads is a config
 * that works.
 */
$GLOBALS['MW_LIGHTTPD_DIRECTIVES'] = array(
    /* core, in the lighttpd binary */
    'server.modules',
    'server.document-root',
    'server.port',
    'server.bind',
    'server.pid-file',
    'server.errorlog',
    'server.indexfiles',
    'server.error-handler-404',
    'server.max-connections',
    'server.max-request-size',
    'server.upload-dirs',
    'mimetype.assign',
    'fastcgi.server',
    'alias.url',
    /* mod_accesslog */
    'accesslog.filename',
    /* mod_openssl */
    'ssl.engine',
    'ssl.pemfile',
    'ssl.openssl.ssl-conf-cmd',
    /* mod_auth */
    'auth.backend',
    'auth.backend.htpasswd.userfile',
    'auth.require',
);

/* Assert that $conf emits nothing outside the allowlist.
 *
 * Matches "word.word" at the start of a line, which is how every directive is
 * written, and ignores the contents of the lists they are assigned. */
function mw_check_lighttpd_directives($label, $conf) {
    preg_match_all('/^[ \t]*([a-z][a-z0-9_]*\.[a-z0-9_.-]+)[ \t]*(\+?=)/m', $conf, $m);
    $used    = array_unique($m[1]);
    $unknown = array_values(array_diff($used, $GLOBALS['MW_LIGHTTPD_DIRECTIVES']));
    sort($unknown);
    is_same($label . ': every directive is one lighttpd knows', $unknown, array());
}
