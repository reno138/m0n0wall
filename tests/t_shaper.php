<?php
/*
 * Traffic shaper (ipfw + dummynet).
 *
 * The shaper is the one subsystem that did NOT move to pf: ALTQ was rejected
 * because m0n0wall's shaper model is pipes-and-queues, which is dummynet's
 * model and not ALTQ's. So this code is the 2015 original, and it had never
 * been exercised by a test -- three of its defects are asserted below.
 */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/xmlparse.inc';
require MW_ROOT . '/phpconf/inc/util.inc';

function get_real_wan_interface($ipv6 = false) { return 'em0'; }

require MW_ROOT . '/phpconf/inc/shaper.inc';

$config = array(
  'interfaces' => array(
    'lan' => array('if'=>'em1','ipaddr'=>'10.0.0.1','subnet'=>'24'),
    'wan' => array('if'=>'em0','ipaddr'=>'dhcp'),
  ),
  'shaper' => array(
    'pipe' => array(
      array('bandwidth'=>'1000','delay'=>'', 'mask'=>''),
      array('bandwidth'=>'2000','delay'=>'', 'mask'=>''),
    ),
    'queue' => array(),
    'rule'  => array(),
  ),
);

/* --- pipes are numbered by array index + 1 ------------------------------ */
$out = shaper_rules_generate();
is_true('pipe 1 is the first configured pipe', strpos($out, 'pipe 1 config bw 1000Kbit/s') !== false);
is_true('pipe 2 is the second',                strpos($out, 'pipe 2 config bw 2000Kbit/s') !== false);

/* --- the anti-lockout rules are always present ------------------------- */
is_true('the admin cannot be shaped out of the webGUI',
        strpos($out, 'set 4 pass all from 10.0.0.1 to any') !== false);

/* --- REGRESSION: a skipped queue must not renumber the ones after it ----
 *
 * Queue index 0 points at pipe index 9, which does not exist, so it is
 * skipped. A running counter gave the NEXT queue the number 1, while the rule
 * emitter -- which derives the number from the config index -- called it 2. So
 * every rule above a skipped queue pointed at the wrong queue, or at one that
 * was never configured. */
$config['shaper']['queue'] = array(
    array('targetpipe'=>'9','weight'=>'10','mask'=>''),   /* unresolvable: skipped */
    array('targetpipe'=>'0','weight'=>'20','mask'=>''),
    array('targetpipe'=>'1','weight'=>'30','mask'=>''),
);
/* the generator legitimately complains about the unresolvable pipe; capture it
   so the suite's output stays readable */
ob_start(); $out = shaper_rules_generate(); $noise = ob_get_clean();
is_true ('the unresolvable pipe is reported', strpos($noise, 'not found') !== false);
is_false('the skipped queue is not emitted',   strpos($out, 'queue 1 config') !== false);
is_true ('the queue after it keeps its index', strpos($out, 'queue 2 config pipe 1') !== false);
is_true ('and so does the one after that',     strpos($out, 'queue 3 config pipe 2') !== false);

/* A rule naming queue index 1 must reach the queue the generator emitted as 2. */
$config['shaper']['rule'] = array(
    array('interface'=>'lan','direction'=>'out','targetqueue'=>'1',
          'source'=>array('any'=>true),'destination'=>array('any'=>true)),
);
ob_start(); $out = shaper_rules_generate(); ob_end_clean();
is_true('a rule and its queue agree on the number',
        preg_match('/add \d+ set 4 queue 2 /', $out) === 1);

/* --- REGRESSION: no pptpd section to read ------------------------------
 *
 * PPTP is removed. shaper.inc used to open with $pptpdcfg = $config['pptpd'],
 * then test $pptpdcfg['mode'] three times -- warnings on every rebuild for a
 * section that no longer exists. A restored config's pptp rules must be
 * skipped, not shaped. */
$config['shaper']['rule'] = array(
    array('interface'=>'pptp','direction'=>'out','targetpipe'=>'0',
          'source'=>array('any'=>true),'destination'=>array('any'=>true)),
    array('interface'=>'lan','direction'=>'out','targetpipe'=>'0',
          'source'=>array('network'=>'pptp'),'destination'=>array('any'=>true)),
);
$errors = array();
set_error_handler(function ($no, $str) use (&$errors) { $errors[] = $str; return true; });
ob_start(); $out = shaper_rules_generate(); ob_end_clean();
restore_error_handler();
is_same('no diagnostics for the removed pptpd section', $errors, array());
is_false('a pptp-interface rule is not shaped', strpos($out, 'via ng') !== false);

/* --- REGRESSION: a plain rule set must generate in silence --------------
 *
 * Ten optional fields (delay, plr, qsize, mask, weight, source/destination
 * network and address, port, iplen, iptos, tcpflags, direction) were read for
 * truth rather than with !empty(). All of them are blank in an ordinary config,
 * so every shaper rebuild printed a screenful of "Undefined array key" into the
 * Apply-changes page and onto the boot console. */
$config['shaper']['queue'] = array(array('targetpipe'=>'0','weight'=>'10'));
$config['shaper']['rule']  = array(
    /* the shape the GUI writes for "any -> any on LAN, out" */
    array('interface'=>'lan','direction'=>'out','targetpipe'=>'0',
          'source'=>array('any'=>true),'destination'=>array('any'=>true)),
    /* and one with ports and a protocol */
    array('interface'=>'wan','direction'=>'in','targetqueue'=>'0','protocol'=>'tcp',
          'source'=>array('any'=>true),
          'destination'=>array('network'=>'lan','port'=>'80-443')),
);
$errors = array();
set_error_handler(function ($no, $str) use (&$errors) { $errors[] = $str; return true; });
$out = shaper_rules_generate();
restore_error_handler();
is_same('an ordinary rule set generates with no diagnostics', $errors, array());
is_true('and it still produces rules', strpos($out, 'set 4') !== false);
is_true('the port range is emitted', strpos($out, '80-443') !== false);

/* --- REGRESSION: deleting pipes/queues must renumber every reference -------
 *
 * The three inline versions of this (pipes delete, queues delete, magic wizard)
 * were each wrong. The multi-entry case is the one that matters: the old code
 * looped once per victim and compared an already-decremented target against the
 * next raw index, so it under-counted the shift above the second victim. */
function mk_shaper() {
    return array(
      'pipe' => array(
        array('descr'=>'p0','bandwidth'=>'100'),
        array('descr'=>'p1','bandwidth'=>'200'),
        array('descr'=>'p2','bandwidth'=>'300'),
        array('descr'=>'p3','bandwidth'=>'400'),
        array('descr'=>'p4','bandwidth'=>'500'),
      ),
      'queue' => array(
        array('descr'=>'q0','targetpipe'=>'0','weight'=>'1'),
        array('descr'=>'q1','targetpipe'=>'4','weight'=>'2'),
      ),
      'rule' => array(
        array('descr'=>'r0','targetpipe'=>'0'),
        array('descr'=>'r1','targetpipe'=>'2'),
        array('descr'=>'r2','targetpipe'=>'4'),
        array('descr'=>'r3','targetqueue'=>'1'),
      ),
    );
}

/* delete pipes 1 and 3 in ONE action: 0 stays 0, 2 becomes 1, 4 becomes 2 */
$config['shaper'] = mk_shaper();
shaper_remove_entries('pipe', array(1, 3));
is_same('two pipes removed', count($config['shaper']['pipe']), 3);
is_same('the surviving pipes are the right ones',
        array_map(function ($p) { return $p['descr']; }, $config['shaper']['pipe']),
        array('p0','p2','p4'));
is_same('a reference below both victims is unchanged',  $config['shaper']['rule'][0]['targetpipe'], 0);
is_same('a reference between them shifts by one',       $config['shaper']['rule'][1]['targetpipe'], 1);
is_same('a reference above both shifts by TWO',         $config['shaper']['rule'][2]['targetpipe'], 2);
is_same('a queue reference is remapped as well',        $config['shaper']['queue'][1]['targetpipe'], 2);
is_same('and one below is left alone',                  $config['shaper']['queue'][0]['targetpipe'], 0);

/* the remapped indices must still resolve when the ruleset is generated */
$config['interfaces'] = array(
  'lan' => array('if'=>'em1','ipaddr'=>'10.0.0.1','subnet'=>'24'),
  'wan' => array('if'=>'em0','ipaddr'=>'dhcp'),
);
foreach ($config['shaper']['rule'] as $k => $unused) {
    $config['shaper']['rule'][$k]['interface'] = 'lan';
    $config['shaper']['rule'][$k]['direction'] = 'out';
    $config['shaper']['rule'][$k]['source'] = array('any'=>true);
    $config['shaper']['rule'][$k]['destination'] = array('any'=>true);
}
$errors = array();
set_error_handler(function ($no, $str) use (&$errors) { $errors[] = $str; return true; });
ob_start(); $out = shaper_rules_generate(); $noise = ob_get_clean();
restore_error_handler();
is_same('no diagnostics after a renumber', $errors, array());
is_false('and no unresolvable pipe', strpos($noise, 'not found') !== false);
is_true ('the highest surviving pipe is still referenced', strpos($out, 'pipe 3 ') !== false);

/* deleting a single entry must behave exactly as it always did */
$config['shaper'] = mk_shaper();
shaper_remove_entries('pipe', array(1));
is_same('single delete: below is unchanged', $config['shaper']['rule'][0]['targetpipe'], 0);
is_same('single delete: above shifts by one', $config['shaper']['rule'][1]['targetpipe'], 1);

/* queues renumber the rules that target them */
$config['shaper'] = mk_shaper();
shaper_remove_entries('queue', array(0));
is_same('a rule targeting queue 1 now targets queue 0',
        $config['shaper']['rule'][3]['targetqueue'], 0);

/* a reference to something that IS being deleted cannot work, so it is
 * disabled rather than left pointing at whatever lands on that index */
$config['shaper'] = mk_shaper();
$n = shaper_remove_entries('pipe', array(0));
is_same('the dangling reference is reported', $n, 2);   /* rule r0 and queue q0 */
is_true ('the rule that pointed at it is disabled',  isset($config['shaper']['rule'][0]['disabled']));
is_true ('the queue that pointed at it is disabled', isset($config['shaper']['queue'][0]['disabled']));
is_false('an unrelated rule is left enabled',        isset($config['shaper']['rule'][1]['disabled']));

/* deleting nothing must change nothing */
$config['shaper'] = mk_shaper();
$before = $config['shaper'];
shaper_remove_entries('pipe', array());
is_same('deleting nothing is a no-op', $config['shaper'], $before);

exit(mw_report('shaper'));
