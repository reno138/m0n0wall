<?php
/* voucher.inc + build/tools/voucher.c -- captive portal prepaid access codes.
 *
 * The feature was dead on this platform: the printed code was a 64-bit RSA
 * ciphertext, and OpenSSL 3 refuses to generate a modulus below 512 bits, so
 * "voucher -g 64" produced nothing and no voucher could be created or checked.
 * Raising the key is not an option either -- a 512-bit modulus renders as ~89
 * characters instead of ~11. The primitive is now a keyed 64-bit permutation
 * (10-round balanced Feistel, HMAC-SHA256 truncated to 32 bits per round) under
 * a single 256-bit secret, which keeps the 64-bit-in/64-bit-out shape and so
 * keeps the printed length, the charset rendering and the voucher.cfg format.
 *
 * This suite locks down four separate things:
 *   1. the permutation itself, against the published KAT -- via an independent
 *      PHP implementation written from the spec, so the C and the spec cannot
 *      drift apart silently;
 *   2. the PACKING of roll/ticket/checksum/magic into the word, end to end
 *      through the real binary. The KAT does not cover packing, and the single
 *      most likely regression in the rewrite lives there (see below);
 *   3. that the secret survives the config.xml round trip, and that the
 *      element name is not one the XML parser turns into an array;
 *   4. that printing a roll does not destroy the key needed to validate it.
 */
require __DIR__ . '/bootstrap.php';

/* Build the real tool and point the code under test at it.
 *
 * voucher.inc reads VOUCHER_BIN if it is already defined, so this makes the
 * suite exercise the ACTUAL binary -- the encode/decode round trip, the canonical
 * form check, the charset refusal -- rather than only asserting that a missing
 * one is handled politely. Skipped silently if there is no compiler or no
 * libcrypto, so the suite still runs anywhere. */
$mw_voucher_bin = mw_sandbox() . '/voucher';
$mw_cc = trim((string) @shell_exec('command -v cc 2>/dev/null || command -v gcc 2>/dev/null'));
if ($mw_cc !== '') {
    @exec(escapeshellarg($mw_cc) . ' -O1 -o ' . escapeshellarg($mw_voucher_bin) . ' ' .
          escapeshellarg(MW_ROOT . '/build/tools/voucher.c') . ' -lcrypto 2>/dev/null',
          $mw_ccout, $mw_ccrc);
    if ($mw_ccrc === 0 && is_executable($mw_voucher_bin))
        define('VOUCHER_BIN', $mw_voucher_bin);
}
require MW_ROOT . '/phpconf/inc/xmlparse.inc';

/* voucher.inc calls these; the real ones live in the boot-time include chain. */
function killbypid($pidfile) { return 0; }
function mwexec($cmd) { return 0; }
$GLOBALS['mw_write_config_calls'] = 0;
function write_config($desc = "") { $GLOBALS['mw_write_config_calls']++; return 0; }

require MW_ROOT . '/phpconf/inc/voucher.inc';

$CHARSET = '2345678abcdefhijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';

/* ======================================================================
 * 1. The permutation, reimplemented in PHP from the spec in voucher.c.
 *
 * PHP has no unsigned 64-bit integer, so the block is carried as a 16-digit
 * hex string and split into two 32-bit halves, which is what the Feistel
 * wants anyway.
 * ====================================================================== */

define('MW_FPE_ROUNDS',  10);
define('MW_FPE_VERSION', 0x01);

/* F(i, X) = first 4 bytes, big-endian, of HMAC-SHA256(K, 0x01 || i || BE32(X)) */
function mw_fpe_f(string $key, int $round, int $x): int {
    $msg = chr(MW_FPE_VERSION) . chr($round) . pack('N', $x);
    $mac = hash_hmac('sha256', $msg, $key, true);
    return unpack('N', substr($mac, 0, 4))[1];
}

function mw_fpe_encrypt_hex(string $key, string $pthex): string {
    $l = hexdec(substr($pthex, 0, 8));
    $r = hexdec(substr($pthex, 8, 8));
    for ($i = 1; $i <= MW_FPE_ROUNDS; $i++) {
        $t = ($l ^ mw_fpe_f($key, $i, $r)) & 0xffffffff;
        $l = $r; $r = $t;
    }
    return sprintf('%08x%08x', $l, $r);
}

/* Identical loop backwards with the halves swapped -- F is applied to a value
   the decryptor already has, which is why every round inverts unconditionally
   and F need not be invertible. */
function mw_fpe_decrypt_hex(string $key, string $cthex): string {
    $l = hexdec(substr($cthex, 0, 8));
    $r = hexdec(substr($cthex, 8, 8));
    for ($i = MW_FPE_ROUNDS; $i >= 1; $i--) {
        $t = ($r ^ mw_fpe_f($key, $i, $l)) & 0xffffffff;
        $r = $l; $l = $t;
    }
    return sprintf('%08x%08x', $l, $r);
}

/* base-N rendering of a 64-bit value, least significant digit first, exactly
   as the tool prints it. Done as byte-wise long division over the 8-byte
   string because the value does not fit in a PHP int. */
function mw_code_render(string $hex16, string $charset): string {
    $base  = strlen($charset);
    $bytes = array_values(unpack('C*', hex2bin($hex16)));
    $out   = '';
    while (true) {
        $rem = 0; $q = array(); $allzero = true;
        foreach ($bytes as $b) {
            $cur = ($rem << 8) | $b;
            $d   = intdiv($cur, $base);
            $rem = $cur % $base;
            $q[] = $d;
            if ($d !== 0) $allzero = false;
        }
        $out  .= $charset[$rem];
        $bytes = $q;
        if ($allzero) break;      /* v==0 therefore renders as charset[0] */
    }
    return $out;
}

/* pack the voucher word as magic|checksum|ticket|roll, as bits, so no step
   ever needs a 64-bit integer */
function mw_pack_word(int $magic, int $mb, int $cksum, int $cb,
                      int $ticket, int $tb, int $roll, int $rb): string {
    $bits = '';
    foreach (array(array($magic,$mb), array($cksum,$cb),
                   array($ticket,$tb), array($roll,$rb)) as $fld) {
        list($v, $n) = $fld;
        for ($i = $n - 1; $i >= 0; $i--) $bits .= (($v >> $i) & 1) ? '1' : '0';
    }
    $hex = '';
    for ($i = 0; $i < 64; $i += 4) $hex .= dechex(bindec(substr($bits, $i, 4)));
    return $hex;
}

/* --- the published KAT. Key 000102..1f, 10 rounds, version tag 0x01.
   These four vectors are what build/tools/voucher.c self-tests against on
   every invocation; reproducing them here from the prose spec alone is the
   evidence that the spec is implementable without reading the C. */
$kat_key = '';
for ($i = 0; $i < 32; $i++) $kat_key .= chr($i);

$kat = array(
    '0000000000000000' => '057a9ff680d00feb',
    '0000000000000001' => '9a4d227a727a0296',
    '0123456789abcdef' => 'aeffa80658fe0280',
    'ffffffffffffffff' => '97250f5ad1c932da',
);
foreach ($kat as $pt => $ct) {
    is_same("KAT encrypt $pt", mw_fpe_encrypt_hex($kat_key, $pt), $ct);
    is_same("KAT decrypt $ct", mw_fpe_decrypt_hex($kat_key, $ct), $pt);
}

/* the permutation must invert for every block, including the edges */
foreach (array('0000000000000000', '8000000000000000', 'ffffffff00000000',
               '00000000ffffffff', 'ffffffffffffffff', 'deadbeefcafebabe') as $v) {
    is_same("round trip $v", mw_fpe_decrypt_hex($kat_key, mw_fpe_encrypt_hex($kat_key, $v)), $v);
}
$rk = random_bytes(32);
$ok = true;
for ($i = 0; $i < 200; $i++) {
    $v = bin2hex(random_bytes(8));
    if (mw_fpe_decrypt_hex($rk, mw_fpe_encrypt_hex($rk, $v)) !== $v) $ok = false;
}
is_true('200 random blocks round trip under a random key', $ok);

/* F must differ per round, or the Feistel collapses */
is_false('F(1,x) != F(2,x)', mw_fpe_f($kat_key, 1, 0x1234) === mw_fpe_f($kat_key, 2, 0x1234));

/* ---- the documented worked example: roll 0, tickets 1..8, 16/10/5 -------
 * magic_bits is 64 - (16+10+5) = 33, NOT 32. The old code reserved one extra
 * bit to keep the plaintext below the RSA modulus; a permutation has no
 * modulus, so that bit is reclaimed. This is also why the CSV header now
 * reports "33 Bits used". */
$mb = 64 - (16 + 10 + 5);
is_same('magic is 33 bits wide at the defaults', $mb, 33);
$magic = 1174491274 & ((1 << $mb) - 1);
$expected = array(1 => ' G8DEa7DeNaN', 2 => ' NRTj3BraAAW', 3 => ' ztVZcVhJZdP',
                  4 => ' s38KKwZiiAD', 5 => ' E4uw8YFbyzv3', 6 => ' YZqGeNBMtA73',
                  7 => ' 8hRtMxtb72c', 8 => ' TD4RYPh5ZDh3');
foreach ($expected as $t => $want) {
    $word = mw_pack_word($magic, $mb, ($t + 0) % 32, 5, $t, 10, 0, 16);
    $code = mw_code_render(mw_fpe_encrypt_hex($kat_key, $word), $CHARSET);
    is_same("worked example ticket $t", " $code", $want);
}

/* ======================================================================
 * 2. The stored secret must survive config.xml.
 * ====================================================================== */

/* REGRESSION GUARD, do not delete.
 * $listtags (phpconf/inc/xmlparse.inc) names the elements the parser always
 * turns into a LIST. 'key' is one of them. If the voucher secret were stored
 * as $config['voucher']['key'], parse_xml_config() would hand back a
 * one-element ARRAY rather than a string, and base64_decode() on it is a
 * TypeError in PHP 8 -- so voucher_configure() would fatal in rc.bootup on
 * every boot after the first save. 'fpekey' is safe today; someone editing
 * $listtags must not make it unsafe. */
is_false("the secret's element name is not in \$listtags", in_array('fpekey', $listtags, true));
is_true ("...and 'key' really is, which is why it was not used", in_array('key', $listtags, true));

/* base64 of 32 bytes is 44 characters of [A-Za-z0-9+/=]: never empty (which
   dump_xml_config_sub writes as <ent/>), never a bool (which it drops or
   writes as <ent/>), and containing nothing htmlspecialchars() rewrites. */
$secret = random_bytes(32);
$b64 = base64_encode($secret);
is_same('base64 of the secret is 44 characters', strlen($b64), 44);
is_same('...and untouched by htmlspecialchars()', htmlspecialchars($b64), $b64);

$cfg = parse_xml_config(MW_ROOT . '/phpconf/config.xml', 'm0n0wall');
$cfg['voucher'] = array(
    'enable' => true, 'charset' => $CHARSET, 'rollbits' => '16',
    'ticketbits' => '10', 'checksumbits' => '5', 'magic' => '1174491274',
    'saveinterval' => '300', 'fpekey' => $b64,
    'msgnoaccess' => 'Voucher invalid', 'msgexpired' => 'Voucher expired',
    'roll' => array(array('number' => '0', 'minutes' => '60', 'count' => '20',
                          'comment' => 'test roll',
                          'used' => base64_encode(str_repeat("\000", 4)),
                          'active' => array())),
);
$tmp = mw_sandbox() . '/voucher-roundtrip.xml';
file_put_contents($tmp, dump_xml_config($cfg, 'm0n0wall'));
$again = parse_xml_config($tmp, 'm0n0wall');
is_true ('the secret comes back as a string, not an array',
         is_string($again['voucher']['fpekey'] ?? null));
is_same('...byte-identical', $again['voucher']['fpekey'] ?? null, $b64);
is_same('...and decodes to the same 32 bytes',
        base64_decode($again['voucher']['fpekey'], true), $secret);
/* The scalars all survive verbatim. Two fields deliberately do NOT compare
   equal, and both are long-standing properties of the XML model rather than
   anything to do with the secret -- asserted here so a reader is not tempted
   to "fix" them:
     - boolean true is written as <enable/> and parses back as "", which is
       still isset(), which is all voucher_configure() tests for;
     - an empty list element ('active' => array()) is dropped by the dumper. */
foreach (array('charset','rollbits','ticketbits','checksumbits','magic',
               'saveinterval','msgnoaccess','msgexpired') as $k) {
    is_same("voucher/$k survives the round trip",
            $again['voucher'][$k] ?? null, $cfg['voucher'][$k]);
}
is_true ('voucher/enable is still isset() after the round trip',
         isset($again['voucher']['enable']));
is_same('the roll survives as a list',
        $again['voucher']['roll'][0]['count'] ?? null, '20');

/* ======================================================================
 * 3. voucher_configure() -- the two files the binary reads.
 * ====================================================================== */

$config = $cfg;
is_same('voucher_configure() succeeds', voucher_configure(), 0);

$keyfile = "{$g['varetc_path']}/voucher.key";
$cfgfile = "{$g['varetc_path']}/voucher.cfg";

is_true ('voucher.key is written', file_exists($keyfile));
is_same('...as 64 hex digits plus a newline', file_get_contents($keyfile), bin2hex($secret) . "\n");
is_same('...mode 0600', substr(sprintf('%o', fileperms($keyfile)), -4), '0600');
/* The old code fopen()ed then chmod()ed, leaving the key world-readable with
   its content already in it; voucher_write_keyfile() creates, chmods, writes. */

is_true ('voucher.cfg is written', file_exists($cfgfile));
is_same('...still the same five comma-separated fields', file_get_contents($cfgfile),
        "16,10,5,1174491274,$CHARSET\n");

/* an upgraded config has the old RSA keys and no fpekey: it must complain
   loudly, not fail mutely, because nothing else tells the admin why every
   voucher check is failing */
$config = $cfg;
unset($config['voucher']['fpekey']);
$config['voucher']['publickey'] = base64_encode("-----BEGIN PUBLIC KEY-----\nMEw=\n-----END PUBLIC KEY-----\n");
@unlink($keyfile);
ob_start(); $rc = voucher_configure(); $msg = ob_get_clean();
is_same('a config with no secret makes voucher_configure() fail', $rc, 1);
is_true ('...and say so on stdout', strpos($msg, 'no voucher secret configured') !== false);
is_false('...and writes no key file', file_exists($keyfile));
is_true ('...but still writes voucher.cfg so the rest of the boot proceeds', file_exists($cfgfile));

/* a malformed secret must be refused rather than written out truncated */
$config = $cfg;
$config['voucher']['fpekey'] = base64_encode('too short');
ob_start(); $rc = voucher_configure(); $msg = ob_get_clean();
is_same('a short secret makes voucher_configure() fail', $rc, 1);
is_true ('...and says the secret is malformed', strpos($msg, 'malformed') !== false);
is_false('...and writes no key file', file_exists($keyfile));

$config = $cfg;   /* leave a good state behind */
voucher_configure();

/* ======================================================================
 * 4. voucher_auth() caps how many codes one request may carry.
 *
 * Every code in a request is an independent attempt at the tool's 2^-38
 * forgery test, and nothing else rate-limits the captive portal, so an
 * unbounded POST was an unbounded number of guesses (and, before the
 * single-exec change, an unbounded fork storm).
 * ====================================================================== */

$lockfile_path = "{$g['varrun_path']}/voucher.lock";

@unlink($lockfile_path);
$many = implode(' ', array_fill(0, 5, 'aaaaaaaaaaa'));
is_same('5 codes from the portal are refused', voucher_auth($many, 0), 0);
is_false('...and the lock is released, not left behind', file_exists($lockfile_path));

$res = voucher_auth(implode(' ', array_fill(0, 65, 'aaaaaaaaaaa')), 1);
is_true ('65 codes on the test page are refused', is_array($res) &&
         strpos($res[0] ?? '', 'Too many vouchers') !== false);

/* The admin test page gets the wider limit: 5 codes must NOT be refused
   outright. When the tool could not be built, voucher_auth() execs the shipped
   absolute path instead and this also covers the graceful handling of a missing
   binary -- stderr is closed for those two calls so the suite output stays
   readable either way. */
if (VOUCHER_BIN === '/usr/local/bin/voucher' && !is_executable(VOUCHER_BIN))
    echo "  (voucher could not be built here; exercising the missing-binary path)\n";
$res = voucher_auth($many, 1);
is_true ('5 codes on the test page pass the cap', is_array($res) &&
         strpos($res[0] ?? '', 'Too many vouchers') === false);

/* PREG_SPLIT_NO_EMPTY: leading/trailing/repeated whitespace must not count
   towards the cap, or a guest's stray newline would look like a 5th code */
$res = voucher_auth("  aaaaaaaaaaa \n\n bbbbbbbbbbb \t ccccccccccc  ddddddddddd \n", 1);
is_true ('padded whitespace does not inflate the code count', is_array($res) &&
         strpos($res[0] ?? '', 'Too many vouchers') === false);

/* ======================================================================
 * 5. End to end through the real binary, if we can build it.
 *
 * This is the part the KAT cannot do. The single most dangerous line in the
 * rewrite is the one that is NOT there any more:
 *
 *     clearcode &= 0xffffffffffffffffLL >> (65 - 8*crypt_len);
 *
 * which cleared bit 63 to keep the plaintext below the RSA modulus. Bit 63 is
 * now a magic bit, so keeping that line would make every printed voucher fail
 * its own magic check -- and it would look like a broken Feistel, not like a
 * masking bug. Only a print-then-check round trip catches it.
 * ====================================================================== */

$src = MW_ROOT . '/build/tools/voucher.c';
$bin = mw_sandbox() . '/voucher';
$cc  = getenv('CC') ?: 'cc';
$built = false;
if (is_readable($src) && trim((string)shell_exec("command -v " . escapeshellarg($cc) . " 2>/dev/null")) !== '') {
    $out = array(); $rc = 1;
    exec(escapeshellarg($cc) . " -O2 -o " . escapeshellarg($bin) . " " .
         escapeshellarg($src) . " -lcrypto 2>&1", $out, $rc);
    $built = ($rc === 0 && is_executable($bin));
}

if (!$built) {
    echo "  (skipping the end-to-end cases: no working C compiler with -lcrypto here)\n";
} else {
    /* -g emits one 256-bit secret as 64 hex digits */
    $hex = trim((string)shell_exec(escapeshellarg($bin) . " -g"));
    is_same('voucher -g emits 64 hex digits', preg_match('/^[0-9a-f]{64}$/', $hex), 1);
    is_false('...and two invocations differ',
             $hex === trim((string)shell_exec(escapeshellarg($bin) . " -g")));

    /* Drive it exactly the way the GUI does: voucher_write_keyfile() +
       voucher_write_cfgfile(), then print, then check. */
    $config = $cfg;
    $config['voucher']['fpekey'] = base64_encode(hex2bin($hex));
    is_same('voucher_write_keyfile()', voucher_write_keyfile(), 0);
    is_same('voucher_write_cfgfile()', voucher_write_cfgfile(), 0);

    $pfx = escapeshellarg($bin) . " -c " . escapeshellarg($cfgfile) .
           " -K " . escapeshellarg($keyfile);

    $printed = array();
    exec("$pfx -p 0 20", $printed, $rc);
    is_same('printing roll 0 succeeds', $rc, 0);

    $codes = array();
    foreach ($printed as $line)
        if (preg_match('/^" (\S+)"$/', $line, $m)) $codes[] = $m[1];
    is_same('20 codes were printed', count($codes), 20);

    /* the CSV header still carries the six "# ..." lines the format promises,
       with the magic width now reading 33 rather than 32 */
    is_true ('the CSV header reports 33 magic bits',
             in_array('# magic initializer   1174491274 (33 Bits used)', $printed, true));
    is_true ('the CSV header still names the roll',
             in_array('# Voucher Tickets 1..20 for Roll 0', $printed, true));

    /* printed codes stay short enough to type: 10-12 characters in base 54 */
    $lens = array_map('strlen', $codes);
    is_true ('every code is 9..12 characters long (was ~11 under RSA)',
             min($lens) >= 9 && max($lens) <= 12);

    /* THE case this whole block exists for: every printed code must validate
       back to its own roll and ticket, in order. */
    $checked = array(); $rc = 1;
    exec("$pfx -k -- " . implode(' ', array_map('escapeshellarg', $codes)), $checked, $rc);
    is_same('checking all 20 in one invocation succeeds', $rc, 0);
    is_same('...one result line per code', count($checked), 20);
    $want = array();
    for ($t = 1; $t <= 20; $t++) $want[] = "OK 0 $t";
    is_same('every printed voucher validates to its own roll and ticket', $checked, $want);

    /* a single character changed must be refused */
    $bad = $codes[0];
    $bad[0] = ($bad[0] === $CHARSET[0]) ? $CHARSET[1] : $CHARSET[0];
    $out = array(); exec("$pfx -k -- " . escapeshellarg($bad), $out, $rc);
    is_same('a mutated code is refused', $rc, 1);
    is_true ('...with a TYPO line', strpos($out[0] ?? '', 'TYPO') === 0);

    /* a character the charset excludes on purpose (O and l are not in it) */
    $out = array(); exec("$pfx -k -- " . escapeshellarg(substr($codes[0], 0, -1) . 'O'), $out, $rc);
    is_same('a code with an out-of-charset character is refused', $rc, 1);

    /* an over-long string used to wrap mod 2^64 and could alias onto a real
       code; code_parse() now refuses it */
    $out = array(); exec("$pfx -k -- " . escapeshellarg(str_repeat($codes[0], 2)), $out, $rc);
    is_same('an over-long code is refused', $rc, 1);

    /* a whitespace-only argument consumed zero digits and "succeeded" with
       value 0, leaning on the magic test instead of being rejected outright */
    $out = array(); exec("$pfx -k -- " . escapeshellarg('   '), $out, $rc);
    is_same('a whitespace-only code is refused', $rc, 1);

    /* the CSV form is '" <code>"', so a leading space must still parse */
    $out = array(); exec("$pfx -k -- " . escapeshellarg(' ' . $codes[0]), $out, $rc);
    is_same('a code with the CSV leading space still validates', $out[0] ?? '', 'OK 0 1');

    /* a good code, a bad code and a good code: one line each, in order, and
       the run does not stop at the bad one -- that is what lets voucher_auth()
       check a whole request in a single fork */
    $out = array();
    exec("$pfx -k -- " . escapeshellarg($codes[0]) . " " . escapeshellarg($bad) .
         " " . escapeshellarg($codes[2]), $out, $rc);
    is_same('a mixed batch yields one line per code, in order',
            array(count($out), $out[0], strpos($out[1], 'TYPO'), $out[2]),
            array(3, 'OK 0 1', 0, 'OK 0 3'));

    /* a code minted under a different secret must not validate */
    $other = mw_sandbox() . '/other.key';
    file_put_contents($other, trim((string)shell_exec(escapeshellarg($bin) . " -g")) . "\n");
    $out = array();
    exec(escapeshellarg($bin) . " -c " . escapeshellarg($cfgfile) . " -K " .
         escapeshellarg($other) . " -k -- " . escapeshellarg($codes[0]), $out, $rc);
    is_same('a code from another secret is refused', $rc, 1);

    /* ---- REGRESSION: printing must not destroy the validation key --------
     * The RSA version wrote voucher.private, printed, and unlinked it
     * (services_captiveportal_vouchers.php), because a gateway that only
     * validated needed nothing but the public key. One secret now does both
     * jobs, so a mechanical rename of that unlink() would delete the key the
     * captive portal needs -- failing only for guests, and only after an admin
     * printed a roll. Do not let this get "tidied" back in. */
    $out = array();
    exec("$pfx -p 5 3", $out, $rc);
    is_true ('the key file still exists after a print', file_exists($keyfile));
    $out2 = array();
    exec("$pfx -k -- " . escapeshellarg($codes[0]), $out2, $rc);
    is_same('a voucher still validates AFTER a roll was printed', $out2[0] ?? '', 'OK 0 1');

    $page = (string)file_get_contents(MW_ROOT . '/webgui/services_captiveportal_vouchers.php');
    is_same('the Vouchers page never unlinks voucher.key', 0,
            preg_match('/unlink\s*\(\s*["\'][^"\']*voucher\.key/', $page));

    /* the bit-width floor is refused by the TOOL, not just by the GUI:
       voucher.cfg is hand-editable and is also rewritten from a restored
       config.xml that never passed through the validation page */
    $badcfg = mw_sandbox() . '/bad.cfg';
    file_put_contents($badcfg, "31,16,16,1174491274,$CHARSET\n");
    $out = array();
    exec(escapeshellarg($bin) . " -c " . escapeshellarg($badcfg) . " -K " .
         escapeshellarg($keyfile) . " -p 0 3", $out, $rc);
    is_same('the tool refuses rollbits+ticketbits > 32', $rc, 1);
    is_true ('...with a CFG error naming the rule',
             strpos($out[0] ?? '', 'CFG') === 0 &&
             strpos($out[0] ?? '', 'must not exceed 32') !== false);

    /* 16+16 = 32 is the boundary and must be allowed */
    file_put_contents($badcfg, "16,16,5,1174491274,$CHARSET\n");
    $out = array();
    exec(escapeshellarg($bin) . " -c " . escapeshellarg($badcfg) . " -K " .
         escapeshellarg($keyfile) . " -p 0 2", $out, $rc);
    is_same('rollbits+ticketbits == 32 is allowed', $rc, 0);

    /* a malformed key file must be refused, not silently truncated */
    $shortkey = mw_sandbox() . '/short.key';
    file_put_contents($shortkey, "deadbeef\n");
    $out = array();
    exec(escapeshellarg($bin) . " -c " . escapeshellarg($cfgfile) . " -K " .
         escapeshellarg($shortkey) . " -k -- " . escapeshellarg($codes[0]), $out, $rc);
    is_same('a short key file is refused', $rc, 1);
    is_true ('...with a CRYPT error', strpos($out[0] ?? '', 'CRYPT') === 0);

    /* checksumbits 0 is legal (the magic absorbs the bits) */
    $cs0 = mw_sandbox() . '/cs0.cfg';
    file_put_contents($cs0, "16,10,0,1174491274,$CHARSET\n");
    $out = array();
    exec(escapeshellarg($bin) . " -c " . escapeshellarg($cs0) . " -K " .
         escapeshellarg($keyfile) . " -p 1 3", $out, $rc);
    $c0 = array();
    foreach ($out as $line) if (preg_match('/^" (\S+)"$/', $line, $m)) $c0[] = $m[1];
    $out = array();
    exec(escapeshellarg($bin) . " -c " . escapeshellarg($cs0) . " -K " .
         escapeshellarg($keyfile) . " -k -- " . implode(' ', array_map('escapeshellarg', $c0)),
         $out, $rc);
    is_same('checksumbits 0 round trips', $out, array('OK 1 1', 'OK 1 2', 'OK 1 3'));

    /* the C tool and the PHP reference above must agree byte for byte */
    file_put_contents($keyfile, bin2hex($kat_key) . "\n");
    $out = array();
    exec("$pfx -p 0 8", $out, $rc);
    $katcodes = array();
    foreach ($out as $line) if (preg_match('/^(" \S+")$/', $line, $m)) $katcodes[] = $m[1];
    is_same('the binary reproduces the PHP reference exactly',
            $katcodes, array_map(fn($v) => '"' . $v . '"', array_values($expected)));
}

/* --- against the REAL binary -----------------------------------------------
 *
 * Everything above tests the PHP. These exercise the tool itself, which is the
 * only way to prove the encoding is a bijection and that the refusals fire.
 * Skipped when it could not be built. */
if (VOUCHER_BIN !== '/usr/local/bin/voucher' && is_executable(VOUCHER_BIN)) {
    $cs  = '2345678abcdefhijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
    $dir = mw_sandbox();
    $kf  = "$dir/rt.key";
    $cf  = "$dir/rt.cfg";

    exec(escapeshellarg(VOUCHER_BIN) . ' -g', $kout, $krc);
    is_same('the tool generates a secret', $krc, 0);
    is_true ('and it is 64 hex digits', preg_match('/^[0-9a-f]{64}$/', trim($kout[0] ?? '')) === 1);
    file_put_contents($kf, trim($kout[0]) . "\n");
    file_put_contents($cf, "16,10,5,1174491274,$cs\n");

    $base = escapeshellarg(VOUCHER_BIN) . ' -c ' . escapeshellarg($cf) . ' -K ' . escapeshellarg($kf);

    /* print a roll, then redeem every ticket in it */
    exec("$base -p 3 200", $pout, $prc);
    is_same('printing a roll succeeds', $prc, 0);
    $codes = array();
    foreach ($pout as $ln)
        if (preg_match('/^"\s*(\S+)"$/', $ln, $m))
            $codes[] = $m[1];
    is_same('200 codes were printed', count($codes), 200);

    $args = '';
    foreach ($codes as $c) $args .= ' ' . escapeshellarg($c);
    exec("$base -k --$args", $cout, $crc);
    is_same('every printed code validates', $crc, 0);
    $okcount = 0;
    foreach ($cout as $ln) if (strpos($ln, 'OK 3 ') === 0) $okcount++;
    is_same('and each reports its own roll and ticket', $okcount, 200);

    /* the canonical-form rule: padding a code with charset[0] must NOT validate.
       Without it, appending charset[0] gives an unlimited family of alternate
       spellings for every voucher -- and the active-voucher database is keyed on
       the code STRING while the used-ticket bitmask is keyed on (roll, ticket). */
    $pad = $cs[0];
    exec("$base -k -- " . escapeshellarg($codes[0] . $pad), $p1);
    is_true ('a padded code is refused', strpos($p1[0] ?? '', 'OK') !== 0);
    exec("$base -k -- " . escapeshellarg($codes[0] . $pad . $pad), $p2);
    is_true ('and so is a doubly padded one', strpos($p2[0] ?? '', 'OK') !== 0);

    /* mutations */
    $mut = $codes[0];
    $mut[0] = ($mut[0] === $cs[1]) ? $cs[2] : $cs[1];
    exec("$base -k -- " . escapeshellarg($mut), $m1);
    is_true ('a mutated code is refused', strpos($m1[0] ?? '', 'OK') !== 0);

    /* a different secret must not validate another secret's codes */
    exec(escapeshellarg(VOUCHER_BIN) . ' -g', $k2out);
    file_put_contents("$dir/rt2.key", trim($k2out[0]) . "\n");
    exec(escapeshellarg(VOUCHER_BIN) . ' -c ' . escapeshellarg($cf) .
         ' -K ' . escapeshellarg("$dir/rt2.key") . ' -k -- ' . escapeshellarg($codes[0]), $x1);
    is_true ('another secret does not validate them', strpos($x1[0] ?? '', 'OK') !== 0);

    /* a charset with a repeated character makes render/parse stop being
       inverses, so the tool must refuse it outright rather than print a roll
       whose tickets cannot be redeemed */
    file_put_contents("$dir/dup.cfg", "16,10,5,1,2345678900ABCDEFGHJKLMNPQRSTUVWXYZ\n");
    exec(escapeshellarg(VOUCHER_BIN) . ' -c ' . escapeshellarg("$dir/dup.cfg") .
         ' -K ' . escapeshellarg($kf) . ' -p 0 3', $dout, $drc);
    is_true ('a repeated charset character is refused',
             strpos(implode(' ', $dout), 'repeats the character') !== false);
    is_false('and no codes are printed for it', (bool) preg_grep('/^"/', $dout));

    /* the anti-forgery floor is enforced by the tool, not only by the page */
    file_put_contents("$dir/weak.cfg", "31,16,16,1,$cs\n");
    exec(escapeshellarg(VOUCHER_BIN) . ' -c ' . escapeshellarg("$dir/weak.cfg") .
         ' -K ' . escapeshellarg($kf) . ' -p 0 1', $wout);
    is_true ('roll+ticket bits over 32 are refused',
             strpos(implode(' ', $wout), 'CFG') !== false);
}

exit(mw_report('voucher.inc'));
