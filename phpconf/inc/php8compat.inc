<?php
/*
	php8compat.inc
	part of m0n0wall (http://m0n0.ch/wall)

	PHP 8 reclassified reading an undefined array key or variable from an
	E_NOTICE -- which m0n0wall always ran with off -- to an E_WARNING. The
	code base was written against the PHP 4/5 rule that such a read simply
	yields null, and relies on it in hundreds of places, mostly form
	templates reading optional configuration keys:

	    <?=htmlspecialchars($pconfig['dstmask']);?>

	One sweep of the webGUI produced 1,771 of these from 793 sites, and boot
	prints a page of them to the console.

	They are not errors in this code base; they are the language changing
	underneath it. Until every site has been rewritten (the PHP 8 sweep in
	the plan), this handler restores the old semantics for exactly those
	messages and nothing else. Any other warning -- a failed fopen, "headers
	already sent", a bad argument -- goes on to whatever handler was there
	before, or to PHP's own, and is displayed or logged as php.ini says.

	To see them again -- for the sweep, or to hunt a real bug hiding among
	them -- set m0n0.strict_warnings = 1 in php.ini. get_cfg_var() reads
	custom directives, so that is the whole switch.
*/

$php8compat_previous_handler = null;

function php8compat_error_handler($errno, $errstr, $errfile, $errline) {
	global $php8compat_previous_handler;

	/* honour @ and error_reporting() exactly as PHP itself would */
	if (!(error_reporting() & $errno))
		return false;

	if ($errno == E_WARNING &&
	    preg_match('/^(Undefined (array key|variable|property|offset|index)\b|' .
	               'Trying to access array offset on (null|value of type))/', $errstr))
		return true;			/* swallowed: the pre-PHP-8 behaviour */

	if ($php8compat_previous_handler)
		return call_user_func($php8compat_previous_handler, $errno, $errstr, $errfile, $errline);

	return false;				/* PHP's normal handling */
}

if (!get_cfg_var("m0n0.strict_warnings"))
	$php8compat_previous_handler = set_error_handler("php8compat_error_handler");
