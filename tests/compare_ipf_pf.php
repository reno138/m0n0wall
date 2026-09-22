<?php
/*
 * ipf vs pf rule-equivalence report.
 *
 * The pf rewrite cannot be trusted on a reading of the diff: the two
 * languages express the same intent with different keywords, and some
 * differences are deliberate (rule groups collapse, scrub replaces two rules).
 * So instead of diffing text, this generates BOTH rulesets from one config,
 * reduces each rule to a normalised tuple
 *
 *     action | direction | interface | proto | src | sport | dst | dport
 *
 * and reports which tuples match, which exist only in ipf, and which only in
 * pf. A reviewer then has a short list to justify rather than 200 lines to
 * eyeball.
 *
 * Usage:  php tests/compare_ipf_pf.php [config.xml]
 *
 * This is a REPORT, not a pass/fail test -- intentional differences show up
 * as ipf-only or pf-only entries and are expected. It is kept out of
 * run.sh for that reason.
 */

$cfgfile = isset($argv[1]) ? $argv[1] : __DIR__ . '/../phpconf/config.xml';

$noparseconfig = true;
require __DIR__ . '/../phpconf/inc/globals.inc';
$g['booting'] = false;
set_include_path(__DIR__ . '/../phpconf/inc' . PATH_SEPARATOR .
                 __DIR__ . '/../captiveportal' . PATH_SEPARATOR . get_include_path());
require __DIR__ . '/../phpconf/inc/functions.inc';
require __DIR__ . '/../phpconf/inc/filter_pf.inc';

$config = parse_xml_config($cfgfile, 'm0n0wall');
/* deterministic NIC names, so the report does not depend on the host */
$config['interfaces']['lan']['if'] = 'em1';
$config['interfaces']['wan']['if'] = 'em0';
$aliastable = array();
alias_make_table();

/* --- normalisers ------------------------------------------------------- */

function norm_addr($a) {
    $a = trim($a);
    if ($a === '' || $a === 'any' || $a === '0/0' || $a === '0.0.0.0/0') return 'any';
    return $a;
}

/* ipf: "port = 80", "port >= 1024", "port 999 >< 2001" (EXCLUSIVE ends) */
function norm_port_ipf($tok) {
    if (preg_match('/port\s*=\s*(\d+)/', $tok, $m))          return $m[1];
    if (preg_match('/port\s*>=\s*(\d+)/', $tok, $m))         return $m[1] . '-65535';
    if (preg_match('/port\s*<=\s*(\d+)/', $tok, $m))         return '1-' . $m[1];
    if (preg_match('/port\s+(\d+)\s*><\s*(\d+)/', $tok, $m)) {
        /* undo ipf's exclusive-range fudge so it compares against pf */
        return ($m[1] + 1) . '-' . ($m[2] - 1);
    }
    return '*';
}

/* pf: "port 80", "port 1000:2000", "port >= 1024" (INCLUSIVE) */
function norm_port_pf($tok) {
    if (preg_match('/port\s*>=\s*(\d+)/', $tok, $m))        return $m[1] . '-65535';
    if (preg_match('/port\s*<=\s*(\d+)/', $tok, $m))        return '1-' . $m[1];
    if (preg_match('/port\s+(\d+):(\d+)/', $tok, $m))       return $m[1] . '-' . $m[2];
    if (preg_match('/port\s+(\d+)\b/', $tok, $m))           return $m[1];
    return '*';
}

function norm_proto($p) {
    $p = trim($p);
    if ($p === '' || $p === 'any') return 'any';
    /* pf writes lists; normalise "{ tcp udp }" to ipf's "tcp/udp" */
    if (preg_match('/^\{\s*(.+?)\s*\}$/', $p, $m))
        return implode('/', preg_split('/[\s,]+/', trim($m[1])));
    return $p;
}

function parse_rules($text, $flavour) {
    $out = array();
    foreach (explode("\n", $text) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        /* skip constructs with no counterpart on the other side */
        if (preg_match('/^(set|scrub|table|anchor|skip|\w+_if\s*=)/', $line)) continue;

        if (!preg_match('/^(pass|block(?:\s+return-rst|\s+return-icmp\([^)]*\))?)\s+(in|out)\b/', $line, $m))
            continue;
        $action = strpos($m[1], 'return') !== false ? 'reject' : $m[1];
        $dir    = $m[2];

        preg_match('/\bon\s+(\S+)/', $line, $mi);
        $iface = isset($mi[1]) ? $mi[1] : '*';

        if (preg_match('/\bproto\s+(\{[^}]*\}|\S+)/', $line, $mp)) $proto = norm_proto($mp[1]);
        else $proto = 'any';

        /* split on from ... to ... so ports attach to the right side */
        $src = 'any'; $dst = 'any'; $sport = '*'; $dport = '*';
        if (preg_match('/\bfrom\s+(!\s*)?(\S+)(.*?)\bto\s+(!\s*)?(\S+)(.*)$/', $line, $ma)) {
            $src = ($ma[1] ? '!' : '') . norm_addr($ma[2]);
            $dst = ($ma[4] ? '!' : '') . norm_addr($ma[5]);
            $stail = $ma[3]; $dtail = $ma[6];
            if ($flavour === 'ipf') {
                $sport = norm_port_ipf($stail); $dport = norm_port_ipf($dtail);
            } else {
                $sport = norm_port_pf($stail);  $dport = norm_port_pf($dtail);
            }
        }

        $out[] = implode(' | ', array($action, $dir, $iface, $proto, $src, $sport, $dst, $dport));
    }
    return $out;
}

/* --- generate both ----------------------------------------------------- */

$ipf_rules = parse_rules(filter_rules_generate(), 'ipf');
$pf_rules  = parse_rules(pf_rules_generate(),     'pf');
$ipf_nat   = filter_nat_rules_generate();
$pf_nat    = pf_nat_rules_generate();

/* ---- pairing ----------------------------------------------------------
 * ipf scoped rules to an interface with 'group N' rather than 'on <if>', so
 * a group member emits if='*'. pf states the interface explicitly. Pair those
 * up before diffing, or every grouped rule shows as a difference on both
 * sides and buries the real ones.
 */
function pair_grouped(&$ipf, &$pf) {
    foreach ($ipf as $i => $ir) {
        $if = explode(' | ', $ir);
        if ($if[2] !== '*') continue;
        foreach ($pf as $j => $pr) {
            $pfp = explode(' | ', $pr);
            $pfp[2] = '*';
            if (implode(' | ', $pfp) === $ir) {
                unset($ipf[$i], $pf[$j]);
                break;
            }
        }
    }
}

/* ---- known, deliberate differences ------------------------------------
 * Each entry says why a rule exists on one side only. Anything NOT matched
 * here is an unexplained difference and fails the run -- that is the whole
 * point of the tool.
 */
$expected_ipf_only = array(
  '/^pass \| (in|out) \| lo0 \|/'
     => "loopback passes replaced by 'set skip on lo0'",
  '/^block \| in \| \S+ \| any \| (10\.0\.0\.0\/8|127\.0\.0\.0\/8|172\.16\.0\.0\/12|192\.168\.0\.0\/16) \|/'
     => "four private-network blocks collapsed into the <priv> table",
  '/^block \| in \| \* \| tcp \| any \| \* \| any \| \*$/'
     => "ipf's non-SYN TCP block; pf applies flags S/SA by default when creating TCP state",
  '/^block \| in \| \S+ \| any \| any \| \* \| any \| \*$/'
     => "ipf 'head' rule for a rule group; groups collapse into 'on <if>' plus the closing block",
);
$expected_pf_only = array(
  '/^block \| in \| \S+ \| any \| <priv> \|/'
     => "the <priv> table rule that replaces the four ipf private-network blocks",
);

function classify($rules, $expected) {
    $ok = array(); $unknown = array();
    foreach ($rules as $r) {
        $hit = null;
        foreach ($expected as $re => $why) { if (preg_match($re, $r)) { $hit = $why; break; } }
        if ($hit !== null) $ok[$r] = $hit; else $unknown[] = $r;
    }
    return array($ok, $unknown);
}

$common   = array_intersect($ipf_rules, $pf_rules);
$ipf_only = array_values(array_diff($ipf_rules, $pf_rules));
$pf_only  = array_values(array_diff($pf_rules,  $ipf_rules));
pair_grouped($ipf_only, $pf_only);
$ipf_only = array_values($ipf_only);
$pf_only  = array_values($pf_only);
list($ipf_ok, $ipf_unknown) = classify($ipf_only, $expected_ipf_only);
list($pf_ok,  $pf_unknown)  = classify($pf_only,  $expected_pf_only);

printf("config: %s\n\n", realpath($cfgfile));
printf("  ipf filter rules : %d\n", count($ipf_rules));
printf("  pf  filter rules : %d\n", count($pf_rules));
printf("  identical tuples : %d\n", count($common));
printf("  ipf only         : %d\n", count($ipf_only));
printf("  pf only          : %d\n\n", count($pf_only));

$hdr = sprintf("%-8s %-4s %-6s %-9s %-20s %-11s %-20s %s",
               'action','dir','if','proto','src','sport','dst','dport');

if ($ipf_ok || $pf_ok) {
    echo "--- differences, accounted for ---\n";
    foreach (array('ipf only' => $ipf_ok, 'pf only' => $pf_ok) as $side => $set) {
        foreach ($set as $r => $why)
            printf("  [%-7s] %s\n              %s\n", $side, str_replace(' | ', "\t", $r), $why);
    }
    echo "\n";
}

$unexplained = count($ipf_unknown) + count($pf_unknown);
if ($unexplained) {
    echo "--- UNEXPLAINED DIFFERENCES ---\n$hdr\n";
    foreach ($ipf_unknown as $r) echo "  [ipf only] " . str_replace(' | ', "\t", $r) . "\n";
    foreach ($pf_unknown  as $r) echo "  [pf  only] " . str_replace(' | ', "\t", $r) . "\n";
    echo "\n";
}

printf("translation rules: ipf/ipnat %d lines, pf %d lines\n",
       count(array_filter(explode("\n", $ipf_nat), fn($l) => trim($l) !== '' && $l[0] !== '#')),
       count(array_filter(explode("\n", $pf_nat),  fn($l) => trim($l) !== '' && $l[0] !== '#')));

printf("\n%s\n", $unexplained === 0
    ? "OK -- every difference is accounted for"
    : "$unexplained UNEXPLAINED difference(s): justify them or fix the generator");
exit($unexplained === 0 ? 0 : 1);
