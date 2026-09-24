<?php
/*
 * DHCP configuration generated for dnsmasq.
 *
 * The point of these is that the CONFIG MODEL did not change when the server
 * did. Every key here is one the webGUI has always written for ISC dhcpd, and
 * each test asserts the dnsmasq equivalent carries the same meaning.
 */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/xmlparse.inc';
require MW_ROOT . '/phpconf/inc/util.inc';
require MW_ROOT . '/phpconf/inc/dhcp_dnsmasq.inc';

$config = array(
  'system' => array('domain' => 'example.lan', 'dnsserver' => array('9.9.9.9')),
  'interfaces' => array(
     'lan'  => array('if' => 'em1', 'ipaddr' => '192.168.1.1', 'subnet' => '24'),
     'opt1' => array('if' => 'em2', 'ipaddr' => '10.9.9.1', 'subnet' => '24',
                     'enable' => true),
     'opt2' => array('if' => 'em3', 'ipaddr' => '10.8.8.1', 'subnet' => '24',
                     'enable' => true, 'bridge' => 'lan'),
  ),
  'dhcpd' => array(
     'lan' => array(
        'enable' => true,
        'range' => array('from' => '192.168.1.100', 'to' => '192.168.1.199'),
        'defaultleasetime' => '3600',
        'maxleasetime' => '86400',
        'domain' => 'lan.example.lan',
        'dnsserver' => array('192.168.1.1'),
        'winsserver' => array('192.168.1.5'),
        'staticmap' => array(
           array('mac' => '00:11:22:33:44:55', 'ipaddr' => '192.168.1.50',
                 'hostname' => 'printer'),
           array('mac' => '00:aa:bb:cc:dd:ee', 'ipaddr' => '192.168.1.51'),
           /* an IPv6 mapping must be skipped, not emitted */
           array('mac' => '00:de:ad:be:ef:00', 'ipaddr' => '2001:db8::5'),
        ),
     ),
     'opt1' => array(
        'enable' => true,
        'range' => array('from' => '10.9.9.100', 'to' => '10.9.9.199'),
        'gateway' => '10.9.9.254',
        'denyunknown' => true,
        'filename' => 'pxelinux.0',
        'next-server' => '10.9.9.10',
     ),
     /* bridged -- must be skipped */
     'opt2' => array('enable' => true,
        'range' => array('from' => '10.8.8.100', 'to' => '10.8.8.199')),
     /* disabled -- must be skipped */
     'opt3' => array('range' => array('from' => '10.7.7.1', 'to' => '10.7.7.9')),
  ),
);

$out = dhcp_dnsmasq_config_generate();

/* --- ranges ------------------------------------------------------------- */
is_true('lan range with netmask and lease',
        strpos($out, 'dhcp-range=set:lan,192.168.1.100,192.168.1.199,255.255.255.0,3600s') !== false);
is_true('opt1 range',
        strpos($out, 'dhcp-range=set:opt1,10.9.9.100,10.9.9.199,255.255.255.0,7200s') !== false);
is_false('bridged interface is skipped', strpos($out, '10.8.8.100') !== false);
is_false('disabled interface is skipped', strpos($out, '10.7.7.1') !== false);

/* --- options ------------------------------------------------------------ */
is_true('router defaults to the interface address',
        strpos($out, 'dhcp-option=tag:lan,3,192.168.1.1') !== false);
is_true('explicit gateway honoured',
        strpos($out, 'dhcp-option=tag:opt1,3,10.9.9.254') !== false);
is_true('per-interface DNS (option 6)',
        strpos($out, 'dhcp-option=tag:lan,6,192.168.1.1') !== false);
is_true('per-interface domain (option 15)',
        strpos($out, 'dhcp-option=tag:lan,15,lan.example.lan') !== false);
is_true('opt1 falls back to the system domain',
        strpos($out, 'dhcp-option=tag:opt1,15,example.lan') !== false);
is_true('WINS (option 44)',
        strpos($out, 'dhcp-option=tag:lan,44,192.168.1.5') !== false);
is_true('netbios node type (option 46)',
        strpos($out, 'dhcp-option=tag:lan,46,8') !== false);

/* --- PXE: ISC next-server + filename becomes dhcp-boot ------------------ */
is_true('PXE boot file and server',
        strpos($out, 'dhcp-boot=tag:opt1,pxelinux.0,,10.9.9.10') !== false);

/* --- deny unknown clients -----------------------------------------------
 *
 * It is set on opt1 only. An untagged 'dhcp-ignore=tag:!known' is GLOBAL to
 * dnsmasq, so the old form stopped dynamic DHCP on the LAN too -- which is
 * exactly the interface an admin would still be sitting on. */
is_true ('denyunknown becomes a per-interface dhcp-ignore',
         strpos($out, 'dhcp-ignore=tag:opt1,tag:!known') !== false);
is_false('and is not emitted globally',
         strpos($out, "dhcp-ignore=tag:!known") !== false);
is_false('so the LAN is unaffected',
         strpos($out, 'dhcp-ignore=tag:lan') !== false);

/* --- static mappings ---------------------------------------------------- */
is_true('static map with hostname',
        strpos($out, 'dhcp-host=00:11:22:33:44:55,192.168.1.50,printer') !== false);
is_true('static map without hostname',
        strpos($out, 'dhcp-host=00:aa:bb:cc:dd:ee,192.168.1.51') !== false);
is_false('IPv6 static map is not emitted', strpos($out, '2001:db8::5') !== false);

is_true('authoritative once DHCP is on',
        strpos($out, 'dhcp-authoritative') !== false);

/* --- REGRESSION: per-reservation PXE --------------------------------------
 *
 * services_dhcp_edit.php writes 'filename' and 'next-server' on an individual
 * reservation and its help text promises they override the pool's values.
 * Nothing read them, so a reserved client got the pool's boot file or none. */
$config['dhcpd']['lan']['staticmap'][0]['filename']    = 'thin-client.efi';
$config['dhcpd']['lan']['staticmap'][0]['next-server'] = '192.168.1.240';
$out = dhcp_dnsmasq_config_generate();
is_true('the reservation is tagged so options can attach to it',
        strpos($out, 'dhcp-host=00:11:22:33:44:55,192.168.1.50,printer,set:res-lan-1') !== false);
is_true('its own boot file and server are emitted',
        strpos($out, 'dhcp-boot=tag:res-lan-1,thin-client.efi,,192.168.1.240') !== false);
/* the tag has to be set before it is used, or dnsmasq never matches it */
is_true('the dhcp-host precedes the dhcp-boot that references it',
        strpos($out, 'set:res-lan-1') < strpos($out, 'dhcp-boot=tag:res-lan-1'));
/* a reservation with only a filename inherits the pool's next-server */
$config['dhcpd']['opt1']['staticmap'] = array(
    array('mac'=>'00:11:22:33:44:66','ipaddr'=>'10.9.9.60','filename'=>'other.efi'),
);
$out = dhcp_dnsmasq_config_generate();
is_true('a partial override inherits the pool next-server',
        strpos($out, 'dhcp-boot=tag:res-opt1-1,other.efi,,10.9.9.10') !== false);
/* a reservation with no PXE fields of its own is not tagged at all */
is_true('an ordinary reservation gets no tag',
        strpos($out, 'dhcp-host=00:aa:bb:cc:dd:ee,192.168.1.51') !== false
        && strpos($out, 'dhcp-host=00:aa:bb:cc:dd:ee,192.168.1.51,set:') === false);

/* --- nothing enabled ---------------------------------------------------- */
$config['dhcpd'] = array();
$empty = dhcp_dnsmasq_config_generate();
is_false('no ranges when nothing is enabled', strpos($empty, 'dhcp-range') !== false);
is_false('not authoritative when nothing is enabled', strpos($empty, 'dhcp-authoritative') !== false);

exit(mw_report('dhcp (dnsmasq)'));
