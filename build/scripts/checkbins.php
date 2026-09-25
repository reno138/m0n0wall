<?php
/*
 * Every external program the shipped PHP tries to run must be in the image.
 *
 * A missing binary is silent: mwexec() gets 127, exec() fills nothing in, and
 * the feature simply does not happen. Nothing logs it, no page shows an error,
 * and it looks exactly like a configuration problem. Found this way:
 *
 *   /usr/local/sbin/setkey   diag_ipsec_sad.php and diag_ipsec_spd.php, two
 *                            pages ON THE DIAGNOSTICS MENU, listed nothing and
 *                            their delete buttons ran a missing binary. setkey
 *                            belonged to ipsec-tools, which went with racoon.
 *   /usr/local/bin/mbmon     the "Enable Motherboard Monitoring" option on
 *                            System: Advanced configured nothing.
 *   /usr/bin/nsupdate        RFC 2136 dynamic DNS could never update anything.
 *   /sbin/ipf /sbin/ipmon    left over from ipfilter, in dead code and in the
 *   /sbin/ipnat              two L2TP link scripts.
 *
 * Scans absolute paths only -- a bare command name resolves through $PATH at
 * runtime and is checked separately (see the note at the end).
 *
 * KNOWN-DEAD paths are listed in $allowed_missing below with a reason. That
 * list is the point of the gate: a path either resolves in the image or is
 * explicitly acknowledged as unreachable, and anything else fails the build.
 */
$root = rtrim($argv[1], '/');            /* the image root */
$src  = rtrim($argv[2], '/');            /* the source tree */

/* collect candidate command strings from the exec-ish calls */
$files = array_merge(
    glob("$src/phpconf/inc/*.inc"), glob("$src/phpconf/rc.*"),
    glob("$src/webgui/*.php"), glob("$src/webgui/*.inc"),
    glob("$src/captiveportal/*.php"), glob("$src/captiveportal/*.inc"),
    glob("$src/etc/croen_jobs/*.cjob"), glob("$src/etc/rc*"), glob("$src/build/tools/*")
);
$RE = '#(?<![\w.$/-])(/(?:s?bin|usr/s?bin|usr/local/s?bin|usr/local/bin|usr/bin)/[A-Za-z0-9_.-]+)#';

$found = array();
foreach ($files as $f) {
    if (!is_file($f)) continue;
    $t = @file_get_contents($f);
    if ($t === false) continue;

    /* Comments are skipped. A path named in a comment is documentation -- this
       gate's own explanation of why mbmon went away mentions /usr/local/bin/mbmon,
       and exec_raw.php's header shows a #!/usr/bin/perl example client. Flagging
       those taught the reader nothing and invited exceptions for non-problems.
       The tokenizer is used rather than a regex because stripping comments by
       pattern gets strings containing "//" wrong. */
    $strip = $t;
    if (strpos($t, '<?php') !== false) {
        $toks = @token_get_all($t);
        if ($toks) {
            $strip = '';
            foreach ($toks as $tk) {
                if (is_array($tk)) {
                    if ($tk[0] === T_COMMENT || $tk[0] === T_DOC_COMMENT) {
                        /* keep the newlines so reported line numbers stay sane */
                        $strip .= str_repeat("\n", substr_count($tk[1], "\n"));
                        continue;
                    }
                    $strip .= $tk[1];
                } else {
                    $strip .= $tk;
                }
            }
        }
    } else {
        /* a shell script: drop whole-line and trailing # comments */
        $strip = preg_replace('/(^|\s)#.*$/m', '$1', $t);
    }

    if (preg_match_all($RE, $strip, $m))
        foreach ($m[1] as $p) $found[$p][basename($f)] = 1;
}
/* Paths that are deliberately absent. Each one must be genuinely unreachable at
   runtime, and the reason is recorded so the next person does not have to work it
   out again. Adding an entry here is a claim that the code path is dead. */
$allowed_missing = array(
    '/sbin/ipf'    => 'ipfilter is gone; only in filter.inc functions renamed _ipf_superseded',
    '/sbin/ipmon'  => 'ipfilter is gone; pflogd replaced it',
    '/sbin/ipnat'  => 'ipfilter is gone; pf does NAT in the same ruleset',
    '/usr/local/sbin/racoon'  => 'replaced by strongSwan; only in vpn_ipsec_configure_racoon_superseded()',
    '/usr/local/sbin/setkey' => 'belonged to ipsec-tools with racoon; only in '
                              . 'vpn_ipsec_configure_racoon_superseded(). The two Diagnostics '
                              . 'IPsec pages that used it were rewritten for swanctl.',
    '/usr/bin/nsupdate' => 'RFC 2136 dynamic DNS is unavailable: bind-tools is 8.5MB plus seven '
                         . 'dependencies, which is not a reasonable cost for this one feature. '
                         . 'services_dnsupdate_process() is guarded and the page says so.',
);

$missing = array(); $ok = 0; $acknowledged = array();
foreach ($found as $p => $where) {
    if (file_exists($root . $p) || is_link($root . $p)) { $ok++; continue; }
    if (isset($allowed_missing[$p])) { $acknowledged[$p] = $allowed_missing[$p]; continue; }
    $missing[$p] = array_keys($where);
}
printf("absolute binary paths referenced: %d   present: %d   known-dead: %d   MISSING: %d\n",
       count($found), $ok, count($acknowledged), count($missing));
if ($acknowledged) {
    echo "\n  known-dead (acknowledged):\n";
    ksort($acknowledged);
    foreach ($acknowledged as $p => $why)
        printf("    %-32s %s\n", $p, $why);
}
if ($missing) {
    echo "\nERROR: referenced but not in the image, and not acknowledged:\n";
    ksort($missing);
    foreach ($missing as $p => $where)
        printf("    %-42s referenced by: %s\n", $p, implode(', ', array_slice($where, 0, 4)));
    echo "\nEither ship the binary, change the code, or add it to \$allowed_missing\n";
    echo "in build/scripts/checkbins.php WITH A REASON.\n";
    exit(1);
}
/* An entry in $allowed_missing that has become reachable again, or whose file is
   now shipped, is stale -- say so rather than letting the list rot. */
foreach ($allowed_missing as $p => $why) {
    if (file_exists($root . $p))
        printf("  note: %s is in the image now; drop it from \$allowed_missing\n", $p);
}
echo "  every referenced binary is present or acknowledged\n";
exit(0);
