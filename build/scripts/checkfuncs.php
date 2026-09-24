<?php
/*
 * Every function the shipped PHP calls must exist in the shipped PHP.
 *
 * Run by stage 2 INSIDE a chroot of the image, so "what is available" is
 * exactly what the firewall will have at runtime -- not what the build host
 * happens to provide. That distinction is the whole point: the unit tests and
 * every php -l pass on a machine with ctype and bcmath compiled in, while the
 * image had neither, and the failure only appeared when a page or a boot
 * script actually reached the call.
 *
 * Found this way: ctype_digit (scheduler.inc, on the boot path), ctype_xdigit
 * (IPv6.php), bcdiv/bcmod/bcsub (captive portal RADIUS accounting).
 *
 * Scans the source as installed: /etc/inc, /usr/local/www,
 * /usr/local/captiveportal and the /etc/rc.* scripts.
 */

$have = array_flip(array_map('strtolower', get_defined_functions()['internal']));
$defined = array();
$calls   = array();

$files = array_merge(
	(array)glob("/etc/inc/*"),
	(array)glob("/etc/rc.*"),
	(array)glob("/usr/local/www/*"),
	(array)glob("/usr/local/captiveportal/*")
);

foreach ($files as $f) {
	if (!is_file($f))
		continue;
	if (!preg_match('/\.(php|inc)$|\/rc\./', $f))
		continue;
	$src = @file_get_contents($f);
	if ($src === false || strpos($src, '<?php') === false)
		continue;
	$t = @token_get_all($src);
	if (!$t)
		continue;

	$n = count($t);
	for ($i = 0; $i < $n; $i++) {
		if (is_array($t[$i]) && $t[$i][0] == T_FUNCTION) {
			for ($j = $i + 1; $j < $i + 4 && $j < $n; $j++)
				if (is_array($t[$j]) && $t[$j][0] == T_STRING) { $defined[strtolower($t[$j][1])] = 1; break; }
		}
		if (!is_array($t[$i]) || $t[$i][0] != T_STRING)
			continue;
		$k = $i + 1;
		while ($k < $n && is_array($t[$k]) && $t[$k][0] == T_WHITESPACE) $k++;
		if ($k >= $n || $t[$k] !== "(")
			continue;
		/* a method call or a declaration is not a function call */
		$p = $i - 1;
		while ($p >= 0 && is_array($t[$p]) && $t[$p][0] == T_WHITESPACE) $p--;
		$prev = ($p >= 0) ? (is_array($t[$p]) ? $t[$p][0] : $t[$p]) : null;
		if ($prev === T_OBJECT_OPERATOR || $prev === T_DOUBLE_COLON ||
		    $prev === T_FUNCTION || $prev === T_NEW)
			continue;
		$calls[strtolower($t[$i][1])][$f] = 1;
	}
}

/* language constructs the tokenizer reports as T_STRING */
$skip = array('array','list','isset','unset','empty','echo','print','exit','die',
              'include','require','include_once','require_once','eval','return',
              'new','clone','match','use','fn');

$missing = array();
foreach ($calls as $fn => $where) {
	if (isset($have[$fn]) || isset($defined[$fn]) || in_array($fn, $skip))
		continue;
	$missing[$fn] = array_keys($where);
}

if (empty($missing)) {
	printf("  %d functions called, all available\n", count($calls));
	exit(0);
}

ksort($missing);
echo "\nERROR: these functions are called but do not exist in the image's PHP:\n";
foreach ($missing as $fn => $w)
	printf("  %-20s %s\n", $fn . "()", implode(", ", array_slice($w, 0, 4)));
echo "\nAdd the extension that provides them to PKGS and php.ini in\n";
echo "build/scripts/2makebinaries.sh and build/files/php.ini.\n";
exit(1);
