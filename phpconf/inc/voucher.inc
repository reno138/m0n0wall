<?php
/*
    $Id$
    
    Copyright (C) 2007 Marcel Wiget <mwiget@mac.com>.
    All rights reserved.
    
    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:
    
    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
    
    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.

*/
    
/* include all configuration functions */
require_once("functions.inc");

/* The voucher tool, as a constant like SWANCTL_BIN and WG_BIN elsewhere.
 *
 * Not only for tidiness: the path was written out at three call sites, so a
 * unit test could not point the code at a locally built copy and had to settle
 * for asserting around the tool's absence. With this, tests/t_voucher.php can
 * exercise the real binary. checkbins.php still finds the literal path here, so
 * the build gate that requires it to be in the image keeps working.
 *
 * Overridable for that reason, and for that reason only. */
if (!defined('VOUCHER_BIN'))
    define('VOUCHER_BIN', '/usr/local/bin/voucher');

$lockfile = "{$g['varrun_path']}/voucher.lock";
$dirtyfile = "{$g['varrun_path']}/voucher.dirty";

/* 
 *Authenticate a voucher and return the remaining time credit in minutes
 * if $test is set, don't mark the voucher as used nor add it to the list
 * of active vouchers
 */
function voucher_auth($voucher_received, $test = 0) {

    global $g, $config, $dirtyfile;

    // if $test is set, simply test the voucher. Don't change anything
    // but return a more verbose error and result message back

    if (! $test)
        voucher_lock();

    // read rolls into assoc array with rollid as key and minutes as value
    $a_roll = &$config['voucher']['roll'];
    $tickets_per_roll = array();
    $minutes_per_roll = array();
    foreach ($a_roll as $rollent) {
        $tickets_per_roll[$rollent['number']] = $rollent['count'];
        $minutes_per_roll[$rollent['number']] = $rollent['minutes'];
    }

    // split into an array. Useful for multiple vouchers given
    /* PREG_SPLIT_NO_EMPTY, and a hard cap on how many codes one request may
       carry. Every code in the request is an independent attempt at the
       voucher tool's forgery test (2^-38 at the shipped bit widths), and
       nothing else rate-limits the captive portal, so an unbounded POST was an
       unbounded number of guesses -- and, before the single-exec change below,
       an unbounded fork storm as well. A guest has no reason to hand in more
       than a few codes at once; the admin's test page gets a wider limit. */
    $a_vouchers_received = preg_split("/[\t\n\r ]+/", trim($voucher_received),
                                      -1, PREG_SPLIT_NO_EMPTY);
    $maxcodes = $test ? 64 : 4;
    if (count($a_vouchers_received) > $maxcodes) {
        voucher_log(LOG_WARNING, "refused a request carrying " .
                    count($a_vouchers_received) . " codes (max $maxcodes)");
        if ($test)
            return array("Too many vouchers in one request (max $maxcodes).");
        voucher_unlock();   /* voucher_lock() above is ours: do not leave it */
        return 0;
    }

    $error = 0;
    $test_result = array();     // used to display for voucher test option in GUI
    $total_minutes = 0;
    $first_voucher = "";
    $first_voucher_roll = 0;

    // go through all received vouchers, check their valid and extract
    // Roll# and Ticket# using the external voucher binary

    /* One invocation for all of them, not one per code. The tool prints one
       result line per argument, in order, and no longer stops at the first bad
       code -- exec() hands back only the LAST line of output unless a second
       argument is given, which is why this used to fork per voucher.
       -K names the single secret that both prints and validates vouchers; the
       RSA public/private pair it replaces could not be generated at all under
       OpenSSL 3. See build/tools/voucher.c. */
    $checkme = array();
    foreach ($a_vouchers_received as $voucher) {
        if (strlen($voucher) < 3)       // else it seems too short to be a voucher
            continue;
        /* Reject anything that is not printable ASCII before it reaches
           escapeshellarg().
        
           A voucher is by definition a string of characters from the configured
           charset, so this cannot turn away a real one. It has to be checked
           because escapeshellarg() THROWS a ValueError on a NUL byte in PHP 8,
           and nothing above here removes one: trim() strips NUL only from the
           ends, and the preg_split does not split on it. So POSTing
           auth_voucher=aaa%00bbb to the captive portal was an uncaught fatal --
           remote, pre-authentication, from any guest on the portal network, and
           repeatable. Worse, voucher_lock() has already been taken by the time
           it fires, so every poisoned request left a stale lock and the next
           genuine voucher login waited out its timeout. */
        if (preg_match('/[^\x21-\x7e]/', $voucher)) {
            voucher_log(LOG_WARNING, "ignoring a submitted voucher containing " .
                        "characters that cannot appear in one");
            continue;
        }
        if (strlen($voucher) > 64) {    // no charset makes a code this long
            voucher_log(LOG_WARNING, "ignoring an over-long submitted voucher (" .
                        strlen($voucher) . " characters)");
            continue;
        }
        $checkme[] = $voucher;
    }

    $results = array();
    if (!empty($checkme)) {
        $args = "";
        foreach ($checkme as $voucher)
            $args .= " " . escapeshellarg($voucher);
        $lines = array();
        exec(VOUCHER_BIN . " -c {$g['varetc_path']}/voucher.cfg " .
             "-K {$g['varetc_path']}/voucher.key -k --{$args}", $lines);
        if (count($lines) == count($checkme)) {
            $results = $lines;
        } else {
            /* The tool gave up before reaching the codes: missing or malformed
               key file, unreadable voucher.cfg, or a failed crypto self-test.
               Attribute its message to every code rather than pairing output
               with the wrong voucher. */
            $why = !empty($lines) ? trim($lines[0]) : "no output from voucher tool";
            voucher_log(LOG_ERR, "voucher tool failed: $why");
            foreach ($checkme as $voucher)
                $results[] = $why;
        }
    }

    foreach ($checkme as $i => $voucher) {

        $result = $results[$i];
        /* array_pad: an error line is not three words, and list() on a short
           array is an "Undefined array key" warning in PHP 8 */
        list($status, $roll, $nr) = array_pad(explode(" ", $result), 3, null);
        if ($status == "OK") {
            if (!$first_voucher) 
            {
                $first_voucher = $voucher;  // store first voucher. Thats the one we give the timecredit
                $first_voucher_roll = $roll;
            }
            // check if we have this ticket on a registered roll for this ticket 
            /* ?? 0: an unregistered roll has no key here, which is an
               "Undefined array key" warning in PHP 8 -- and this runs inside
               the captive portal's own output. */
            if (($tickets_per_roll[$roll] ?? 0) && ($nr <= $tickets_per_roll[$roll])) {
                // voucher is from a registered roll. 
                if (!isset($active_vouchers[$roll]))
                    $active_vouchers[$roll] = voucher_read_active_db($roll);
                // valid voucher. Store roll# and ticket#
                if ($line = ($active_vouchers[$roll][$voucher] ?? null)) {
                    list($timestamp,$minutes) = explode(",", $line);
                    // we have an already active voucher here.
                    $remaining = intval((($timestamp + 60*$minutes) - time())/60);
                    $test_result[] = "$voucher ($roll/$nr) active and good for $remaining Minutes";
                    $total_minutes += $remaining;
                } else {
                    // voucher not used. Check if ticket Id is on the roll (not too high)
                    // and if the ticket is marked used.
                    // check if voucher already marked as used
                    if (!isset($bitstring[$roll]))
                        $bitstring[$roll] = voucher_read_used_db($roll);
                    $pos = $nr >> 3; // divide by 8 -> octet
                    $mask = 1 << ($nr % 8);
                    /* The bitmask lives on the /var ramdisk and is (count/8)+1
                       octets long, so $pos is in range for any $nr that passed
                       the test above -- unless the DB file is missing or was
                       truncated, where reading past the end is an
                       "Uninitialized string offset" error in PHP 8. Treat a
                       missing octet as "not yet used". */
                    $octet = isset($bitstring[$roll][$pos]) ? ord($bitstring[$roll][$pos]) : 0;
                    if ($octet & $mask) {
                        $test_result[] = "$voucher ($roll/$nr) already used and expired";
                        $total_minutes = -1;    // voucher expired
                        $error++;
                    } else {
                        // mark bit for this voucher as used
                        if (strlen($bitstring[$roll]) <= $pos)
                            $bitstring[$roll] = str_pad($bitstring[$roll], $pos + 1, "\000");
                        $bitstring[$roll][$pos] = chr($octet | $mask);
                        $test_result[] = "$voucher ($roll/$nr) good for {$minutes_per_roll[$roll]} Minutes";
                        $total_minutes += $minutes_per_roll[$roll];
                    }
                }
            } else {
                $test_result[] = "$voucher ($roll/$nr): not found on any registererd Roll";
            }
        } else {
            // hmm, thats weired ... not what I expected
            $test_result[] = "$voucher invalid: $result !!";
            $error++;
        }
    }

    // if this was a test call, we're done. Return the result.
    if ($test) {
        if ($error) {
            $test_result[] = "Access denied!";
        } else {
            $test_result[] = "Access granted for $total_minutes Minutes in total.";
        }
        return $test_result;
    }

    // if we had an error (one of the vouchers is invalid), return 0.
    // Discussion: we could return the time remaining for good vouchers, but then
    // the user wouldn't know that he used at least one invalid voucher.

    if ($error) {
        voucher_unlock();
        if ($total_minutes > 0)     // probably not needed, but want to make sure
            $total_minutes = 0;     // we only report -1 (expired) or 0 (no access)
        return $total_minutes;       // well, at least one voucher had errors. Say NO ACCESS
    }

    /* Nothing was recognised as a voucher at all -- e.g. every token was
       shorter than 3 characters and got skipped above. Stop here: falling
       through would write an active-DB entry keyed on the empty string with a
       0 minute credit, and voucher_save_db_to_config() would then persist that
       into config.xml. */
    if ($first_voucher === "") {
        voucher_unlock();
        return 0;
    }

    // All given vouchers were valid and this isn't simply a test.
    // Write back the used DB's

    if (isset($bitstring) && is_array($bitstring))
        foreach ($bitstring as $roll => $used)
            voucher_write_used_db($roll, base64_encode($used));

    // Active DB: we only add the first voucher if multiple given
    // and give that one all the time credit. This allows the user to logout and
    // log in later using just the first voucher. It also keeps username limited
    // to one voucher and that voucher shows the correct time credit in 'active vouchers'

    if ($line = ($active_vouchers[$first_voucher_roll][$first_voucher] ?? null)) {
        list($timestamp, $minutes) = explode(",", $line);
    } else {
        $timestamp = time();    // new voucher
        $minutes = $total_minutes;
    }

    if (!isset($active_vouchers[$first_voucher_roll]) || !is_array($active_vouchers[$first_voucher_roll]))
        $active_vouchers[$first_voucher_roll] = array();
    $active_vouchers[$first_voucher_roll][$first_voucher] = "$timestamp,$minutes";
    /* $first_voucher_roll, not $roll: $roll is left over from the parse loop
       above and holds the LAST voucher's roll, so credit for a login using
       vouchers from several rolls was written to the wrong roll's file. */
    voucher_write_active_db($first_voucher_roll, $active_vouchers[$first_voucher_roll]);

    // mark the DB's as dirty.
    if ($fd = fopen($dirtyfile, "w"))
        fclose($fd);

    voucher_unlock();

    return $total_minutes;
}

function voucher_configure() {
    global $config, $g;
    
    /* kill any running minicron */
    killbypid("{$g['varrun_path']}/vouchercron.pid");

    /* 'isset() && !== false' rather than plain isset().
    
       A webGUI page writes a cleared checkbox as boolean FALSE, and isset() is
       true for false. Both live callers -- rc.bootup and the Vouchers page --
       happen to run this only after write_config(), which re-reads config.xml
       and drops false values, so plain isset() is not wrong today. This makes
       the function correct for any caller, rather than correct by virtue of
       where it is called from. */
    if (isset($config['voucher']['enable']) && $config['voucher']['enable'] !== false) {

        if ($g['booting']) {
            echo "Enabling voucher support... ";
        }

        // start cron if we're asked to save runtime DB periodically
        // to XML config if it changed
        /* (int) before the multiply. A config restored or upgraded with
           <saveinterval></saveinterval> gives "" here, and "" * 60 is a
           TypeError in PHP 8 -- not 0 as it was in PHP 5. This runs from
           rc.bootup, so that killed the BOOT, on a value the Vouchers page only
           validates while vouchers are being enabled. */
        $croninterval = ((int) ($config['voucher']['saveinterval'] ?? 0)) * 60; // need seconds. Config has minutes
        if ($croninterval) {
            /* start pruning process (interval defaults to 60 seconds) */
            mwexec("/usr/local/bin/minicron $croninterval {$g['varrun_path']}/vouchercron.pid " .
                    "/etc/rc.savevoucher");
        }

        /* Write the secret used BOTH to print and to verify vouchers. There is
           one key now, not an RSA pair -- see build/tools/voucher.c for why.
           Keep going if it fails: the roll bookkeeping below is restored from
           the config at boot and losing it would strand already-used tickets,
           so report the problem in the return value rather than bailing here. */
        $error = voucher_write_keyfile();

        /* write config file used by voucher binary to decode vouchers */
        if (voucher_write_cfgfile() != 0)
            $error = 1;

        if ($g['booting']) {

            // create active and used DB per roll on ramdisk from config
            $a_roll = &$config['voucher']['roll'];
            voucher_lock();

            foreach ($a_roll as $rollent) {

                $roll = $rollent['number'];
                voucher_write_used_db($roll, $rollent['used']);
                $minutes = $rollent['minutes'];
                $active_vouchers = array();
                $a_active = &$rollent['active'];
                if (is_array($a_active)) {
                    foreach ($a_active as $activent) {
                        $voucher = $activent['voucher'];
                        $timestamp = $activent['timestamp'];
                        $minutes = $activent['minutes'];
                        // its tempting to check for expired timestamps, but during
                        // bootup, we most likely don't have the correct time time.
                        $active_vouchers[$voucher] = "$timestamp,$minutes";
                    }
                }
                voucher_write_active_db($roll, $active_vouchers);
            }

            voucher_unlock();
            echo "done\n";
        }

        if ($error)
            return 1;
    }
    return 0;
}

/* Write the voucher secret where the voucher binary can read it.
 *
 * The secret is stored base64 in $config['voucher']['fpekey'] and handed to the
 * tool as 64 lowercase hex digits (the tool wants hex so it can reject a
 * malformed key with one exact length test instead of reasoning about
 * EVP_DecodeBlock's padded return length -- see build/tools/voucher.c).
 *
 * ONE FILE FOR BOTH OPERATIONS. The RSA version wrote voucher.public here and
 * voucher.private only for the duration of a CSV download. Printing and
 * checking now use the same voucher.key, so nothing may unlink it -- see the
 * comment at the CSV handler in services_captiveportal_vouchers.php.
 *
 * varetc is on the /var ramdisk, so the only copy that reaches the CF card is
 * the base64 one inside config.xml, which is where every other m0n0wall secret
 * already lives.
 */
function voucher_write_keyfile() {

    global $config, $g;

    $keyfile = "{$g['varetc_path']}/voucher.key";

    /* Remove any previous key FIRST, before either of the early returns below.
    
       They used to return with the old file still in place, so a firewall whose
       secret had gone missing or become malformed carried on validating vouchers
       minted under the PREVIOUS secret -- the exact opposite of what the log
       message says ("Until then no voucher can be printed or validated"). Since
       /var/etc is a ramdisk the file only survives within a boot, but that is
       precisely the window in which an admin clears or replaces the secret and
       expects the old tickets to stop working. */
    @unlink($keyfile);

    if (empty($config['voucher']['fpekey'])) {
        /* A config upgraded from an older image carries the old RSA
           publickey/privatekey and no fpekey, and the secret is only created
           when an admin opens Services: Captive portal: Vouchers. Until then
           the tool has no key and every voucher check fails -- so say it out
           loud rather than letting the exec fail mutely. */
        voucher_log(LOG_ERR, "no voucher secret configured: open " .
            "Services: Captive portal: Vouchers and press Save to generate one. " .
            "Until then no voucher can be printed or validated.");
        printf("Error: no voucher secret configured\n");
        return 1;
    }

    $raw = base64_decode($config['voucher']['fpekey'], true);
    if ($raw === false || strlen($raw) != 32) {
        voucher_log(LOG_ERR, "voucher secret in the configuration is not 32 bytes of base64");
        printf("Error: voucher secret in the configuration is malformed\n");
        return 1;
    }

    /* Create empty, chmod, THEN write. The old fopen("w")-then-chmod() order
       left the key world-readable with its content already in it. (The unlink
       that used to be here has moved to the top of the function, so that the
       early returns above cannot leave a stale key behind.) */
    if (@touch($keyfile) === false) {
        printf("Error: cannot write voucher.key\n");
        return 1;
    }
    @chmod($keyfile, 0600);
    if (@file_put_contents($keyfile, bin2hex($raw) . "\n") === false) {
        printf("Error: cannot write voucher.key\n");
        return 1;
    }

    /* leftovers from the RSA era: nothing reads these any more */
    @unlink("{$g['varetc_path']}/voucher.public");
    @unlink("{$g['varetc_path']}/voucher.private");

    return 0;
}

/* Write the parameter line the voucher binary parses:
 *     rollbits,ticketbits,checksumbits,magic,charset
 * Unchanged from the RSA version -- five fields, same order. The only visible
 * difference is in the CSV header the tool prints, where the magic width now
 * reads 33 rather than 32 because the bit the RSA modulus used to need is
 * reclaimed (build/tools/voucher.c explains it).
 */
function voucher_write_cfgfile() {

    global $config, $g;

    $fd = fopen("{$g['varetc_path']}/voucher.cfg", "w");
    if (!$fd) {
        printf("Error: cannot write voucher.cfg\n");
        return 1;
    }
    chmod("{$g['varetc_path']}/voucher.cfg", 0600);

    /* Refuse to write a line the tool cannot parse.
    
       The five fields are read by the tool with "%d,%d,%d,%llu,%255s", and a
       blank or non-numeric one makes that fscanf consume the wrong field and
       mis-parse the rest of the line -- printing and validating then both fail,
       silently, for every voucher. The page validates these, but only while
       vouchers are being ENABLED: saving with the box unchecked skips validation
       entirely, and a restored or upgraded config never passed through the page
       at all. Better to leave the previous cfg in place and say why. */
    $v = $config['voucher'];
    $fields = array('rollbits' => '/^\d+$/', 'ticketbits' => '/^\d+$/',
                    'checksumbits' => '/^\d+$/', 'magic' => '/^\d+$/',
                    'charset' => '/^\S{2,255}$/');
    foreach ($fields as $f => $re) {
        if (!isset($v[$f]) || !preg_match($re, (string) $v[$f])) {
            voucher_log(LOG_ERR, "not writing voucher.cfg: '$f' is missing or not " .
                        "usable (" . var_export($v[$f] ?? null, true) . "). Open " .
                        "Services: Captive portal: Vouchers and save valid settings.");
            printf("Error: voucher setting '%s' is missing or invalid\n", $f);
            fclose($fd);
            return 1;
        }
    }
    /* A repeated character makes code_render() and code_parse() stop being
       inverses, so most of a printed roll would be rejected. The tool refuses
       this too; catching it here keeps a bad cfg from being written at all. */
    if (strlen(count_chars($v['charset'], 3)) != strlen($v['charset'])) {
        voucher_log(LOG_ERR, "not writing voucher.cfg: the character set repeats a " .
                    "character, which makes vouchers impossible to read back.");
        printf("Error: the voucher character set repeats a character\n");
        fclose($fd);
        return 1;
    }

    fwrite($fd, "{$v['rollbits']},{$v['ticketbits']},{$v['checksumbits']},{$v['magic']},{$v['charset']}\n");
    fclose($fd);
    return 0;
}

/* Ask the voucher binary for a fresh 256-bit secret and store it base64 in the
 * config. base64 because dump_xml_config_sub() writes any value through
 * htmlspecialchars() and turns "" (and boolean false/true) into something that
 * is not a string when parsed back -- base64 of 32 bytes is always exactly 44
 * characters of [A-Za-z0-9+/=], none of which htmlspecialchars() touches.
 * 'fpekey' is deliberately NOT called 'key': 'key' is in $listtags
 * (phpconf/inc/xmlparse.inc), so it would parse back as a one-element ARRAY
 * and base64_decode() would be a TypeError on any config loaded from disk.
 * tests/t_voucher.php asserts that.
 *
 * Returns false and leaves the config alone if the tool is missing or its
 * output is not 64 hex digits: a truncated secret must not silently replace a
 * working one.
 */
function voucher_new_key() {

    global $config;

    $hex = "";
    $fd = popen(VOUCHER_BIN . " -g", "r");
    if ($fd !== false) {
        $hex = trim(fread($fd, 256));
        pclose($fd);
    }
    if (!preg_match('/^[0-9a-f]{64}$/', $hex)) {
        voucher_log(LOG_ERR, "could not generate a voucher secret ('voucher -g' failed)");
        return false;
    }
    $config['voucher']['fpekey'] = base64_encode(hex2bin($hex));
    return true;
}

/* lock captive portal information, decide that the lock file is stale after
   10 seconds */
function voucher_lock() {

    global $lockfile;

    $n = 0;
    while ($n < 10) {
        /* open the lock file in append mode to avoid race condition */
        if ($fd = fopen($lockfile, "x")) {
            /* succeeded */
            fclose($fd);
            return;
        } else {
            /* file locked, wait and try again */
            sleep(1);
            $n++;
        }
    }
}
/* unlock captive portal information file */
function voucher_unlock() {

    global $lockfile;

    if (file_exists($lockfile))
        unlink($lockfile);
}

/* write bitstring of used vouchers to ramdisk. 
 * Bitstring must already be base64_encoded!
 */
function voucher_write_used_db($roll, $vdb) {

    global $g;

    $fd = fopen("{$g['vardb_path']}/voucher_used_$roll.db", "w");
    if ($fd) {
        fwrite($fd, $vdb . "\n");
        fclose($fd);
    } else {
        voucher_log(LOG_ERR, "cant write {$g['vardb_path']}/voucher_used_$roll.db");
    }
}

/* return assoc array of active vouchers with activation timestamp
 * voucher is index. 
 */
function voucher_read_active_db($roll) {

    global $g;

    $active = array();
    $dirty = 0;
    $file = "{$g['vardb_path']}/voucher_active_$roll.db";
    if (file_exists($file)) {
        $fd = fopen($file, "r");
        if ($fd) {
            while (!feof($fd)) {
                $line = trim(fgets($fd));
                if ($line) {
                    list($voucher,$timestamp,$minutes) = explode(",", $line); // voucher,timestamp
                    if ((($timestamp + 60*$minutes) - time()) > 0) {
                        $active[$voucher] = "$timestamp,$minutes";
                    } else {
                        $dirty=1;
                    }
                }
            }
            fclose($fd);
            if ($dirty) // if we found expired entries, lets save our snapshot
                voucher_write_active_db($roll, $active);
        }
    }
    return $active;
}

/* store array of active vouchers back to DB */
function voucher_write_active_db($roll, $active) {

    global $g;

    $fd = fopen("{$g['vardb_path']}/voucher_active_$roll.db", "w");
    if ($fd) {
        foreach($active as $voucher => $value)
            fwrite($fd, "$voucher,$value\n");
        fclose($fd);
    }
}

/* return how many vouchers are marked used on a roll */
function voucher_used_count($roll) {

    global $g;

    $bitstring = voucher_read_used_db($roll);
    $max = strlen($bitstring) * 8;
    $used = 0;
    /* Ticket n lives in bit (n % 8) of octet (n >> 3) -- the same layout
       voucher_auth() uses. The old loop ran 1..max with "1 << (($i % 8) - 1)",
       which is a shift by -1 on every eighth ticket: an ArithmeticError in
       PHP 7+, so this page was fatal for any roll that had a bitmask. It also
       read one octet past the end of the string on the last iteration. */
    for ($i = 0; $i < $max; $i++) {
        $pos = $i >> 3;             // divide by 8 -> octet
        $mask = 1 << ($i % 8);      // mask to test bit in octet
        if (ord($bitstring[$pos]) & $mask)
            $used++;
    }   
    return $used;
}

function voucher_read_used_db($roll) {

    global $g;

    $vdb = "";
    $file = "{$g['vardb_path']}/voucher_used_$roll.db";
    if (file_exists($file)) {
        $fd = fopen($file, "r");
        if ($fd) {
            $vdb = trim(fgets($fd));
            fclose($fd);
        } else {
            voucher_log(LOG_ERR, "cant read {$g['vardb_path']}/voucher_used_$roll.db");
        }
    }
    return base64_decode($vdb);
}

function voucher_unlink_db($roll) {

    global $g;
    unlink("{$g['vardb_path']}/voucher_used_$roll.db");
    unlink("{$g['vardb_path']}/voucher_active_$roll.db");
}

/* we share the log with captiveportal for now */
function voucher_log($priority, $message) {

    $message = trim($message);
    openlog("logportalauth", LOG_PID, LOG_LOCAL4);
    syslog($priority, "Voucher: " . $message);
    closelog();
}

/* Save active and used voucher DB into XML config and write it to flash
 * Called during reboot -> system_reboot_cleanup() and minicron
 */
function voucher_save_db_to_config() {

    global $config, $g, $dirtyfile;
    
    if (!isset($config['voucher']['enable']) || $config['voucher']['saveinterval'] == 0) 
        return;   // no vouchers or don't want to save DB's

    if (!file_exists($dirtyfile))
        return;     // nothing changed.

    voucher_lock(); 

    // walk all active rolls and save runtime DB's to flash
    $a_roll = &$config['voucher']['roll'];
//    foreach ($a_roll as $rollent) {
    foreach ($a_roll as $key => $value) {
        $rollent = &$a_roll[$key];
        $roll = $rollent['number'];
        $bitmask = voucher_read_used_db($roll);
        $rollent['used'] = base64_encode($bitmask);
        $active_vouchers = voucher_read_active_db($roll);
        $db = array();
        foreach($active_vouchers as $voucher => $line) {
            list($timestamp,$minutes) = explode(",", $line);
            $activent['voucher'] = $voucher;
            $activent['timestamp'] = $timestamp;
            $activent['minutes'] = $minutes;
            $db[] = $activent;
        }
        $rollent['active'] = $db;
    }
    unlink($dirtyfile);
    write_config();
    voucher_unlock(); 
    return;
}

?>
