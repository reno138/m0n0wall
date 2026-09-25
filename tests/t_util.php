<?php
/* util.inc -- IP maths and input validation. Everything else leans on these. */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/xmlparse.inc';
require MW_ROOT . '/phpconf/inc/util.inc';

/* subnet maths */
is_same('gen_subnet /24',        gen_subnet('192.168.1.55', 24),    '192.168.1.0');
is_same('gen_subnet /8',         gen_subnet('192.0.2.77', 8),       '192.0.0.0');
is_same('gen_subnet /30',        gen_subnet('10.0.0.6', 30),        '10.0.0.4');
is_same('gen_subnet /32',        gen_subnet('10.0.0.6', 32),        '10.0.0.6');
is_same('gen_subnet_max /24',    gen_subnet_max('192.168.1.1', 24), '192.168.1.255');
is_same('gen_subnet_max /30',    gen_subnet_max('10.0.0.4', 30),    '10.0.0.7');
is_same('gen_subnet_mask /24',   gen_subnet_mask(24),               '255.255.255.0');
is_same('gen_subnet_mask /30',   gen_subnet_mask(30),               '255.255.255.252');
is_same('gen_subnet_mask /0',    gen_subnet_mask(0),                '0.0.0.0');
is_same('gen_subnet_mask /32',   gen_subnet_mask(32),               '255.255.255.255');

/* IPv4 validation */
is_true ('is_ipaddr valid',      is_ipaddr('192.0.2.1'));
is_true ('is_ipaddr 0.0.0.0',    is_ipaddr('0.0.0.0'));
is_false('is_ipaddr octet>255',  is_ipaddr('999.1.1.1'));
is_false('is_ipaddr garbage',    is_ipaddr('garbage'));
is_false('is_ipaddr empty',      is_ipaddr(''));
is_false('is_ipaddr 3 octets',   is_ipaddr('10.1.10'));

/* IPv6 validation */
is_true ('is_ipaddr6 valid',     is_ipaddr6('2001:db8::1'));
is_true ('is_ipaddr6 loopback',  is_ipaddr6('::1'));
is_false('is_ipaddr6 garbage',   is_ipaddr6('zzzz::1'));

/* subnets */
is_true ('is_subnet /24',        is_subnet('192.0.2.0/24'));
is_false('is_subnet /33',        is_subnet('192.0.2.0/33'));
is_false('is_subnet no prefix',  is_subnet('192.0.2.0'));
is_true ('is_subnet6',           is_subnet6('2001:db8::/64'));

/* other validators */
is_true ('is_macaddr valid',     is_macaddr('00:11:22:33:44:55'));
is_false('is_macaddr bad hex',   is_macaddr('zz:11:22:33:44:55'));
is_true ('is_port 443',          is_port('443'));
is_true ('is_port 1',            is_port('1'));
is_false('is_port 70000',        is_port('70000'));
is_false('is_port 0',            is_port('0'));
is_true ('is_hostname',          is_hostname('m0n0wall'));
is_false('is_hostname w/ dot',   is_hostname('a.b'));
is_true ('is_domain',            is_domain('example.org'));
is_true ('is_numericint',        is_numericint('42'));
is_false('is_numericint float',  is_numericint('4.2'));
is_true ('is_validaliasname',    is_validaliasname('myalias'));

/* duration formatting (WireGuard last-handshake column) */
is_same('duration seconds',  format_duration(1),      '1 second');
is_same('duration plural',   format_duration(45),     '45 seconds');
is_same('duration minutes',  format_duration(60),     '1 minute');
is_same('duration minutes+', format_duration(3599),   '59 minutes');
is_same('duration hours',    format_duration(3600),   '1 hour');
is_same('duration days',     format_duration(86400),  '1 day');
is_same('duration days+',    format_duration(259200), '3 days');
is_same('duration negative', format_duration(-5),     'in the future');

/* --- REGRESSION: PEM key validation accepted only PKCS#1 ------------------
 *
 * Five separate pages tested for the literal string "BEGIN RSA PRIVATE KEY" --
 * the webGUI's own HTTPS certificate, the captive portal's HTTPS login, both
 * IPsec certificate pages, and generate_self_signed_cert()'s own sanity check.
 * That is PKCS#1, and every current openssl writes PKCS#8 ("BEGIN PRIVATE KEY")
 * by default, so a key generated today was rejected even though the OpenSSL 3
 * that lighttpd and charon link against reads it happily.
 *
 * Worst of all, generate_self_signed_cert() checked its OWN output that way, so
 * it always returned false and the caller reported "your system's clock is not
 * set" while falling back to the insecure certificate shared by every install.
 *
 * These use fixed PEM headers rather than shelling out to openssl, so the suite
 * still runs on a machine without it. */
$pkcs8 = "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkq\n-----END PRIVATE KEY-----\n";
$pkcs1 = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAL\n-----END RSA PRIVATE KEY-----\n";
$ec    = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIAxq\n-----END EC PRIVATE KEY-----\n";
$dsa   = "-----BEGIN DSA PRIVATE KEY-----\nMIIBuwIBAAKB\n-----END DSA PRIVATE KEY-----\n";
$enc8  = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFDjA=\n-----END ENCRYPTED PRIVATE KEY-----\n";
$enc1  = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,AB\n\nxyz\n-----END RSA PRIVATE KEY-----\n";

is_true ('PKCS#8 is accepted (openssl default)', is_pem_private_key($pkcs8));
is_true ('PKCS#1 is still accepted',             is_pem_private_key($pkcs1));
is_true ('an EC key is accepted',                is_pem_private_key($ec));
is_true ('a DSA key is accepted',                is_pem_private_key($dsa));

/* Rejected on purpose: lighttpd, charon and mpd5 start with no console, so
   nothing can prompt for the passphrase and the daemon just fails to start.
   The pages report this specifically rather than "not valid". */
is_false('an encrypted PKCS#8 key is refused',   is_pem_private_key($enc8));
is_true ('and is identified as encrypted',       is_pem_encrypted_private_key($enc8));
is_false('an encrypted PKCS#1 key is refused',   is_pem_private_key($enc1));
is_true ('and is identified as encrypted',       is_pem_encrypted_private_key($enc1));

is_false('garbage is refused',                   is_pem_private_key('hello'));
is_false('an empty string is refused',           is_pem_private_key(''));
is_false('a certificate is not a private key',   is_pem_private_key(
         "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n"));
/* a header with no matching footer is a truncated paste, which must not pass */
is_false('a truncated key is refused',           is_pem_private_key(
         "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkq\n"));

is_true ('a certificate is recognised',          is_pem_certificate(
         "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n"));
is_false('a private key is not a certificate',   is_pem_certificate($pkcs8));
is_false('garbage is not a certificate',         is_pem_certificate('hello'));

/* --- REGRESSION: the firewall could not make its own HTTPS certificate ---
 *
 * Only run where openssl is compiled into PHP; the image has it. */
if (function_exists('openssl_pkey_new')) {
    $ck = generate_self_signed_cert('m0n0wall', 'fw.example.com');
    is_true ('a self-signed certificate is generated', is_array($ck));
    if (is_array($ck)) {
        is_true ('its certificate is valid PEM',   is_pem_certificate($ck['cert']));
        is_true ('its key passes our own check',   is_pem_private_key($ck['key']));
        $parsed = openssl_x509_parse($ck['cert']);
        /* SHA-1 signatures are rejected by every current browser, so a
           certificate signed that way was useless even when it was produced. */
        is_true ('it is signed with SHA-256',
                 isset($parsed['signatureTypeSN']) && stripos($parsed['signatureTypeSN'], 'sha256') !== false);
        is_same('the common name is the one asked for', $parsed['subject']['CN'] ?? null, 'fw.example.com');
    }
}

exit(mw_report('util.inc'));
