<?php
/*
 * m0n0wall test bootstrap.
 *
 * Loads the core include chain with every filesystem path in $g redirected
 * into a throwaway sandbox, so the pure-logic layers can be exercised on any
 * machine with a PHP binary -- no FreeBSD, no root, no real /conf.
 *
 * Deliberately dependency-free (no PHPUnit, no Composer): it has to run on
 * the build host, on a developer laptop, and on the target image itself.
 */

define('MW_ROOT', dirname(__DIR__));

function mw_sandbox(): string {
    static $sb = null;
    if ($sb !== null) return $sb;
    $sb = sys_get_temp_dir() . '/mw-test-' . getmypid();
    foreach (['/var/run','/var/etc','/var/db','/var/log','/etc','/tmp','/conf',
              '/ftmp','/conf.default','/cf/conf','/usr/local/www'] as $d) {
        @mkdir($sb . $d, 0755, true);
    }
    copy(MW_ROOT . '/phpconf/config.xml', $sb . '/conf/config.xml');
    copy(MW_ROOT . '/phpconf/config.xml', $sb . '/conf.default/config.xml');
    register_shutdown_function(function () use ($sb) { mw_rmtree($sb); });
    return $sb;
}

function mw_rmtree(string $p): void {
    if (!is_dir($p)) { @unlink($p); return; }
    foreach (scandir($p) as $e) { if ($e !== '.' && $e !== '..') mw_rmtree("$p/$e"); }
    @rmdir($p);
}

/* Let a bare require_once("functions.inc") resolve to tests/stubs. PHP searches
   the include_path BEFORE the calling file's own directory, so this shadows the
   real aggregator without editing the files under test. See stubs/functions.inc. */
set_include_path(__DIR__ . '/stubs' . PATH_SEPARATOR . get_include_path());

/* Load globals.inc, then re-root every path it defines into the sandbox. */
require MW_ROOT . '/phpconf/inc/globals.inc';
$__sb = mw_sandbox();
foreach (['varrun_path','varetc_path','vardb_path','varlog_path','etc_path',
          'tmp_path','conf_path','ftmp_path','conf_default_path','cf_path',
          'cf_conf_path','www_path','captiveportal_path',
          'captiveportal_element_path'] as $__k) {
    if (isset($g[$__k])) $g[$__k] = $__sb . $g[$__k];
}
$g['booting'] = false;

/* ---- assertions ------------------------------------------------------- */

$GLOBALS['mw_pass'] = 0;
$GLOBALS['mw_fail'] = 0;
$GLOBALS['mw_failures'] = [];

function is_same(string $label, $got, $want): void {
    if ($got === $want) {
        $GLOBALS['mw_pass']++;
    } else {
        $GLOBALS['mw_fail']++;
        $GLOBALS['mw_failures'][] = sprintf(
            "%s\n      got:  %s\n      want: %s",
            $label, var_export($got, true), var_export($want, true));
    }
}

function is_true(string $label, $got): void  { is_same($label, $got, true); }
function is_false(string $label, $got): void { is_same($label, $got, false); }

function mw_report(string $suite): int {
    printf("%-22s %3d passed, %d failed\n", $suite, $GLOBALS['mw_pass'], $GLOBALS['mw_fail']);
    foreach ($GLOBALS['mw_failures'] as $f) echo "   FAIL  $f\n";
    return $GLOBALS['mw_fail'] === 0 ? 0 : 1;
}
