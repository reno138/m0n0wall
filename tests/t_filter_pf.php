<?php
/*
 * pf rule generation.
 *
 * These exist because the ipf -> pf move is a semantic translation, not a
 * syntax port, and the failure mode of getting it wrong is a firewall that
 * looks configured and silently does not block.
 */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/xmlparse.inc';
require MW_ROOT . '/phpconf/inc/util.inc';
require MW_ROOT . '/phpconf/inc/filter_pf.inc';

$GLOBALS['aliastable'] = array('webservers' => '192.0.2.100');

/* --- port specifications ------------------------------------------------
 * THE trap. ipf's '><' excludes both endpoints, so filter.inc emitted
 * lo-1 >< hi+1. pf's 'lo:hi' includes both. Carrying the arithmetic over
 * would widen every range by one port at each end.
 */
is_same('port single',        pf_port_spec('80'),        'port 80');
is_same('port lo==hi',        pf_port_spec('80-80'),     'port 80');
is_same('port range',         pf_port_spec('1000-2000'), 'port 1000:2000');
is_same('port range narrow',  pf_port_spec('20-21'),     'port 20:21');
is_same('port all -> silent', pf_port_spec('1-65535'),   '');
is_same('port open upper',    pf_port_spec('1024-65535'),'port >= 1024');
is_same('port open lower',    pf_port_spec('1-1023'),    'port <= 1023');
is_same('port empty',         pf_port_spec(''),          '');
/* Regression: the ipf fudge must NOT appear. 999:2001 would be the bug. */
is_false('no off-by-one',     strpos(pf_port_spec('1000-2000'), '999') !== false);

/* --- protocol ----------------------------------------------------------- */
is_same('proto tcp',     pf_proto_spec('tcp'),     'proto tcp');
is_same('proto tcp/udp', pf_proto_spec('tcp/udp'), 'proto { tcp udp }');
is_same('proto empty',   pf_proto_spec(''),        '');
is_same('proto any',     pf_proto_spec('any'),     '');

/* --- context used by the rule tests ------------------------------------- */
$ctx = array(
    'lansa' => '192.168.1.0', 'lansn' => '24',
    'curwanip' => '203.0.113.5',
    'optcfg' => array('opt1' => array('sa' => '10.9.9.0', 'sn' => '24', 'if' => 'em2')),
    'pptpsa' => '10.5.0.0', 'pptpsn' => '28',
    'l2tpsa' => '10.6.0.0', 'l2tpsn' => '28',
);

/* --- symbolic network resolution ---------------------------------------- */
is_same('resolve lan',    pf_resolve_network('lan', $ctx),   '192.168.1.0/24');
is_same('resolve wanip',  pf_resolve_network('wanip', $ctx), '203.0.113.5');
is_same('resolve opt1',   pf_resolve_network('opt1', $ctx),  '10.9.9.0/24');
is_same('resolve l2tp',   pf_resolve_network('l2tp', $ctx),  '10.6.0.0/28');
is_same('resolve unknown',pf_resolve_network('opt9', $ctx),  null);

/* --- whole rules -------------------------------------------------------- */
$r = array('type'=>'pass','protocol'=>'tcp',
           'source'=>array('any'=>true),
           'destination'=>array('network'=>'lan','port'=>'80'));
is_same('pass tcp to lan:80', pf_user_rule_generate($r, $ctx, 'em0'),
        "pass in quick on em0 proto tcp from any to 192.168.1.0/24 port 80 keep state\n");

$r = array('type'=>'pass','protocol'=>'tcp/udp',
           'source'=>array('network'=>'lan'),
           'destination'=>array('any'=>true,'port'=>'1000-2000'));
is_same('tcp/udp + range', pf_user_rule_generate($r, $ctx, 'em0'),
        "pass in quick on em0 proto { tcp udp } from 192.168.1.0/24 to any port 1000:2000 keep state\n");

$r = array('type'=>'block','protocol'=>'tcp','log'=>true,
           'source'=>array('any'=>true),
           'destination'=>array('network'=>'lan'));
is_same('block + log', pf_user_rule_generate($r, $ctx, 'em1'),
        "block in log quick on em1 proto tcp from any to 192.168.1.0/24\n");

$r = array('type'=>'reject','protocol'=>'tcp',
           'source'=>array('any'=>true),
           'destination'=>array('network'=>'lan','port'=>'22'));
is_same('reject tcp -> return-rst', pf_user_rule_generate($r, $ctx, 'em1'),
        "block return-rst in quick on em1 proto tcp from any to 192.168.1.0/24 port 22 flags S/SA\n");

$r = array('type'=>'reject','protocol'=>'udp',
           'source'=>array('any'=>true),
           'destination'=>array('network'=>'lan'));
is_same('reject udp -> icmp unreach', pf_user_rule_generate($r, $ctx, 'em1'),
        "block return-icmp(port-unr) in quick on em1 proto udp from any to 192.168.1.0/24\n");

$r = array('type'=>'pass','protocol'=>'tcp',
           'source'=>array('network'=>'lan','not'=>true),
           'destination'=>array('any'=>true));
is_same('negated source', pf_user_rule_generate($r, $ctx, 'em0'),
        "pass in quick on em0 proto tcp from ! 192.168.1.0/24 to any keep state\n");

$r = array('type'=>'pass','protocol'=>'icmp','icmptype'=>'echoreq',
           'source'=>array('any'=>true), 'destination'=>array('any'=>true));
is_same('icmp type', pf_user_rule_generate($r, $ctx, 'em0'),
        "pass in quick on em0 proto icmp from any to any icmp-type echoreq keep state\n");

$r = array('type'=>'pass','protocol'=>'tcp','disabled'=>true,
           'source'=>array('any'=>true), 'destination'=>array('any'=>true));
is_same('disabled rule emits nothing', pf_user_rule_generate($r, $ctx, 'em0'), '');

$r = array('type'=>'pass','protocol'=>'tcp',
           'source'=>array('any'=>true), 'destination'=>array('network'=>'opt9'));
is_same('unresolvable iface emits nothing', pf_user_rule_generate($r, $ctx, 'em0'), '');

/* Regression for the upstream bug: a rule whose DESTINATION is the L2TP
 * network. filter.inc assigned $src there, leaving $dst empty, so the rule
 * was silently dropped. It must now emit, with l2tp as the destination. */
$r = array('type'=>'pass','protocol'=>'tcp',
           'source'=>array('any'=>true),
           'destination'=>array('network'=>'l2tp','port'=>'3389'));
is_same('l2tp as destination (upstream bug)', pf_user_rule_generate($r, $ctx, 'em0'),
        "pass in quick on em0 proto tcp from any to 10.6.0.0/28 port 3389 keep state\n");

/* alias expansion still works through the same path */
$r = array('type'=>'pass','protocol'=>'tcp',
           'source'=>array('any'=>true),
           'destination'=>array('address'=>'webservers','port'=>'443'));
is_same('alias expands', pf_user_rule_generate($r, $ctx, 'em1'),
        "pass in quick on em1 proto tcp from any to 192.0.2.100 port 443 keep state\n");

exit(mw_report('filter_pf.inc'));
