<?php
/*
 * ipv6_plan_apply(): what the console wizard's IPv6 answers do to config.xml.
 *
 * The keys must be the ones the webGUI's interface pages write, so that either
 * can edit what the other set up -- and switching mode must clear the previous
 * mode's keys, or a leftover tunnel6 makes a static WAN look like a tunnel.
 */
require __DIR__ . '/bootstrap.php';

function mwexec($command) { return 0; }
function mwexec_out($command, &$output) { $output = array(); return 0; }
function log_error($text) {}
function get_interface_list($ethernet = true, $wireless = true, $serial = true) { return array(); }
require MW_ROOT . '/phpconf/inc/interfaces.inc';

function base() {
	return array('system' => array(), 'interfaces' => array(
		'lan'  => array('if' => 'vtnet0', 'ipaddr' => '192.0.2.240', 'subnet' => '24'),
		'wan'  => array('if' => 'vtnet2', 'ipaddr' => 'dhcp'),
		'opt2' => array('if' => 'vlan0', 'descr' => 'BRAVO', 'enable' => true)));
}

/* --- static everywhere ---------------------------------------------------- */
$c = base();
ipv6_plan_apply($c, array(
	'wan' => array('ipaddr6' => 'fd00:172:16:55::240', 'subnet6' => '64', 'gateway6' => 'fd00:172:16:55::1'),
	'lan' => array('ipaddr6' => 'fd00:10:1:10::1', 'subnet6' => '64', 'ipv6ra' => true),
	'opt' => array('opt2' => array('ipaddr6' => 'fd00:202:1::1', 'subnet6' => '64'))));
is_true ('IPv6 is switched on', isset($c['system']['enableipv6']));
is_same ('WAN static address', $c['interfaces']['wan']['ipaddr6'], 'fd00:172:16:55::240');
is_same ('WAN gateway',        $c['interfaces']['wan']['gateway6'], 'fd00:172:16:55::1');
is_same ('LAN static address', $c['interfaces']['lan']['ipaddr6'], 'fd00:10:1:10::1');
is_true ('LAN RA on',          !empty($c['interfaces']['lan']['ipv6ra']));
is_same ('OPT address',        $c['interfaces']['opt2']['ipaddr6'], 'fd00:202:1::1');
is_same ('IPv4 left alone',    $c['interfaces']['lan']['ipaddr'], '192.0.2.240');
is_true ('OPT keeps its enable and name',
         isset($c['interfaces']['opt2']['enable']) && $c['interfaces']['opt2']['descr'] === 'BRAVO');

/* --- switching WAN from tunnel to DHCPv6 clears the tunnel's keys ------- */
$c['interfaces']['wan']['tunnel6'] = '192.0.2.1';
$c['interfaces']['wan']['aiccu'] = array('username' => 'x');
ipv6_plan_apply($c, array(
	'wan' => array('ipaddr6' => 'DHCP'),
	'lan' => array('ipaddr6' => 'DHCP-PD', 'slalen' => '8', 'slaid' => '1'),
	'opt' => array('opt2' => array())));
is_same ('WAN on DHCPv6', $c['interfaces']['wan']['ipaddr6'], 'DHCP');
is_false('the old gateway is gone',  isset($c['interfaces']['wan']['gateway6']));
is_false('the old subnet is gone',   isset($c['interfaces']['wan']['subnet6']));
is_false('a leftover tunnel6 is gone -- it would make WAN look tunnelled',
         isset($c['interfaces']['wan']['tunnel6']));
is_false('and so is a leftover AICCU block', isset($c['interfaces']['wan']['aiccu']));
is_same ('LAN takes the delegated prefix', $c['interfaces']['lan']['ipaddr6'], 'DHCP-PD');
is_same ('from a /56 (sla-len 8)',        $c['interfaces']['lan']['slalen'], '8');
is_false('LAN\'s old static prefix length is gone', isset($c['interfaces']['lan']['subnet6']));
is_false('RA off when not asked for again',        isset($c['interfaces']['lan']['ipv6ra']));
is_false('"none" for an OPT removes its IPv6',     isset($c['interfaces']['opt2']['ipaddr6']));

/* --- an OPT the plan names but config does not have is not created ------ */
$c = base();
ipv6_plan_apply($c, array('wan' => array(), 'lan' => array(),
	'opt' => array('opt7' => array('ipaddr6' => 'fd00::1', 'subnet6' => '64'))));
is_false('no interface is conjured from the plan', isset($c['interfaces']['opt7']));
is_false('"none" on WAN leaves no ipaddr6', isset($c['interfaces']['wan']['ipaddr6']));

/* --- router advertisements: the prefix length they announce ------------- */
is_same('RA on a static /64 announces 64', rtadvd_prefixlen(array('ipaddr6'=>'fd00::1','subnet6'=>'64')), '64');
is_same('RA on a delegated prefix announces the /64 LAN gets, not the ISP\'s /56',
        rtadvd_prefixlen(array('ipaddr6'=>'DHCP-PD','slalen'=>'8')), 64);
is_same('RA on 6to4 announces 64, not an empty prefixlen',
        rtadvd_prefixlen(array('ipaddr6'=>'6to4')), 64);

exit(mw_report('ipv6 plan'));
