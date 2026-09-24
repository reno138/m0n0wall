<?php
/*
	$Id$
	part of m0n0wall (http://m0n0.ch/wall)
	
	Copyright (C) 2003-2008 Manuel Kasper <mk@neon1.net>.
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

function interfaces_secondaries_configure($if) {
	global $config, $g;
	$ifcfg = $config['interfaces'][$if] ?? null;
	$ifconfig = "";
	if (is_array($config['secondaries']['secondary'] ?? null)) {
		$a_secondaries = &$config['secondaries']['secondary'];
		foreach ($a_secondaries as $secondary) {
			if ($if == ($secondary['if'] ?? null)) {
				if (!ipv6enabled() && is_ipaddr6($secondary['ipaddr'] ?? '')){
					continue;
				}
				if (ipv6enabled() && is_ipaddr6($secondary['ipaddr'] ?? '')){
					$ifconfig = $config['interfaces'][$if]['if'] . " inet6 ";
				}
				if (is_ipaddr($secondary['ipaddr'] ?? '')){
					$ifconfig = $config['interfaces'][$if]['if'] . " inet ";
				}
				$ifconfig .=  ($secondary['ipaddr'] ?? '') . "/" . ($secondary['prefix'] ?? '')  . " alias";
				mwexec("/sbin/ifconfig " . $ifconfig);
			}
		}
	}
}

function interfaces_loopback_configure() {
	global $config, $g;

	mwexec("/sbin/ifconfig lo0 127.0.0.1");
	
	return 0;
}

function interfaces_vlan_configure() {
	global $config, $g;
	
	if (is_array($config['vlans']['vlan'] ?? null) && count($config['vlans']['vlan'])) {
		
		$i = 0;
		
		foreach ($config['vlans']['vlan'] as $vlan) {
			
			$cmd = "/sbin/ifconfig vlan{$i} create vlan " . 
				escapeshellarg($vlan['tag'] ?? '') . " vlandev " . 
				escapeshellarg($vlan['if'] ?? '');
			
			mwexec($cmd);
			
			/* make sure the parent interface is up */
			mwexec("/sbin/ifconfig " . escapeshellarg($vlan['if'] ?? '') . " up");
			
			$i++;
		}
	}
	
	return 0;
}

function interfaces_lan_configure() {
	global $config, $g;
	
	if ($g['booting'])
		echo "Configuring LAN interface... ";
	
	$lancfg = $config['interfaces']['lan'];
	
	/* MAC spoofing? */
	if (!empty($lancfg['spoofmac']))
		mwexec("/sbin/ifconfig " . escapeshellarg($lancfg['if']) . 
			" link " . escapeshellarg($lancfg['spoofmac']));
	
	/* media */
	if (!empty($lancfg['media']) || !empty($lancfg['mediaopt'])) {
		$cmd = "/sbin/ifconfig " . escapeshellarg($lancfg['if']);
		if (!empty($lancfg['media']))
			$cmd .= " media " . escapeshellarg($lancfg['media']);
		if (!empty($lancfg['mediaopt']))
			$cmd .= " mediaopt " . escapeshellarg($lancfg['mediaopt']);
		mwexec($cmd);
	}
	
	$addflags = "";
	if (strpos($lancfg['if'], "fxp") !== false)
		$addflags .= " link0";

	if (isset($config['system']['polling']))
		$addflags .= " polling";
	
	mwexec("/sbin/ifconfig " . escapeshellarg($lancfg['if']) . " " . 
		escapeshellarg($lancfg['ipaddr'] . "/" . $lancfg['subnet']) . $addflags);
	
	interfaces_lan_configure6();
	
	if (!$g['booting']) {
		/* make new hosts file */
		system_hosts_generate();
		
		/* reconfigure static routes (kernel may have deleted them) */
		system_routing_configure();
		
		/* reload ipfilter (address may have changed) */
		filter_configure();
		
		/* reload shaper (subnet may have changed) */
		shaper_configure();
		
		/* reload IPsec tunnels */
		vpn_ipsec_configure();
		
		/* reload dhcpd (gateway may have changed) */
		services_dhcpd_configure();
		
		/* reload dhcp6s (gateway may have changed) */
		services_dhcp6s_configure();
		
		/* dnsmasq (DNS and DHCP) was already regenerated and restarted by
		   services_dhcpd_configure() above -- one daemon now, not two. */
		
		/* reload webgui */
		system_webgui_start();
		
		/* reload captive portal */
		captiveportal_configure();
	}
	
	if ($g['booting'])
		echo "done\n";
	
	return 0;
}

function interfaces_lan_configure6() {
	global $config, $g;
	
	$lancfg = $config['interfaces']['lan'];
	remove_all_ipv6_addresses($lancfg['if']);
	mwexec('/sbin/ifconfig ' . $lancfg['if'] . ' inet6 -accept_rtadv no_radr');
	if (ipv6enabled()) {
		if (($lancfg['ipaddr6'] ?? null) == "6to4") {
			/* take second /64 from 6to4 prefix on WAN interface */
			$v6addr = calc_6to4_address("lan");
			if ($v6addr)
				mwexec("/sbin/ifconfig " . escapeshellarg($lancfg['if']) . " inet6 $v6addr prefixlen 64 alias");
		} else if (($lancfg['ipaddr6'] ?? null) == "DHCP-PD") {
			services_dhcp6c_configure();
		} else if (!empty($lancfg['ipaddr6']) && !empty($lancfg['subnet6'])) {
			mwexec('/sbin/ifconfig ' . escapeshellarg($lancfg['if']) .
				' inet6 ' . escapeshellarg($lancfg['ipaddr6']) .
				' prefixlen ' . escapeshellarg($lancfg['subnet6'] . ' alias')
			);
		}
	}
	interfaces_secondaries_configure('lan');
	
	if (!$g['booting']) {
		/* reload rtadvd */
		interfaces_rtadvd_configure();
	}
}

function interfaces_optional_configure() {
	global $config, $g;
	
	for ($i = 1; isset($config['interfaces']['opt' . $i]); $i++) {
		interfaces_optional_configure_if($i);
	}
	
	interfaces_optional_configure6();
	
	if (!$g['booting']) {
		/* reconfigure static routes (kernel may have deleted them) */
		system_routing_configure();
		
		/* reload ipfilter (address may have changed) */
		filter_configure();
		
		/* reload shaper (address may have changed) */
		shaper_configure();
		
		/* reload IPsec tunnels */
		vpn_ipsec_configure();
		
		/* reload dhcpd (interface enabled/disabled/bridged status may have changed) */
		services_dhcpd_configure();
		
		/* reload dhcp6s (gateway may have changed) */
		services_dhcp6s_configure();
		
		/* dnsmasq (DNS and DHCP) was already regenerated and restarted by
		   services_dhcpd_configure() above -- one daemon now, not two. */
	}
	
	return 0;
}

function interfaces_bridge_configure() {
	global $config, $g;
	// Setup the bridge sysctls to filter on member interfaces and not bridge itself
	mwexec("/sbin/sysctl net.link.bridge.pfil_member=1");
	mwexec("/sbin/sysctl net.link.bridge.pfil_bridge=0");
	$bridge_if_num = -1;
	$bridgearray = array();
	$iflist = array("lan", "wan");
	for ($i = 1; isset($config['interfaces']['opt' . $i]); $i++)
		if(isset($config['interfaces']['opt' . $i]['enable']))
			$iflist['opt' . $i] = 'opt' . $i;
	foreach($iflist as $if) {
		// go through all interfaces and check for bridged interfaces
		if (!empty($config['interfaces'][$if]['bridge'])) {
			// this interface is bridged
			$bridgefound = false;
			if ($bridge_if_num == -1) {
				// this is the first bridge, create the bridge0 interface
				$bridge_if_num++;
				$bridgearray[$bridge_if_num][] = convert_friendly_interface_to_real_interface_name($if);
				$bridgearray[$bridge_if_num][] = convert_friendly_interface_to_real_interface_name($config['interfaces'][$if]['bridge']);
			} else {
				// additional bridge
				// check if interface exists in another bridge
				// since the same int can't be added to two bridges
				$realif = convert_friendly_interface_to_real_interface_name($if);
				$realifbridge = convert_friendly_interface_to_real_interface_name($config['interfaces'][$if]['bridge']);
				for($x=0; $x <= $bridge_if_num; $x++) {
					if (in_array($realif, $bridgearray[$x])) {
						// the interface is already in this bridge
						$bridgefound = true;
						if (!in_array($realifbridge, $bridgearray[$x])) {
							// bridged interface isn't already in this
							// bridge, add it.
							$bridgearray[$bridge_if_num][] = $realifbridge;
						}
					} else {
						// see if the other member interface of the bridge is in existing bridge
						if (in_array($realifbridge, $bridgearray[$x])) {
							$bridgefound = true;
							if (!in_array($realif, $bridgearray[$x])) {
								// if real interface isn't already in
								// this bridge, add it.
								$bridgearray[$bridge_if_num][] = $realif;
							}
						}
					}
				}
				if (!$bridgefound) {
					// the interfaces of this bridge are not contained
					// in any existing bridge. Add new bridge interface.
					$bridge_if_num++;
					$bridgearray[$bridge_if_num][] = convert_friendly_interface_to_real_interface_name($if);
					$bridgearray[$bridge_if_num][] = convert_friendly_interface_to_real_interface_name($config['interfaces'][$if]['bridge']);
				}
			}
		}
	}
	// at this point, $bridgearray is fully populated for the number of bridges the system requires.
	// time to set them up.
	for($x=0; $x <= $bridge_if_num; $x++) {
		// destroy and create ifbridge interface
		mwexec("/sbin/ifconfig bridge{$x} destroy");
		mwexec("/sbin/ifconfig bridge{$x} create");
		// log commands run for debugging in /tmp
		$fd = fopen("{$g['tmp_path']}/bridge{$x}_config", "w");
		fwrite($fd, "/sbin/ifconfig bridge{$x} destroy \n");
		fwrite($fd, "/sbin/ifconfig bridge{$x} create \n");
		$bridgecmd = "/sbin/ifconfig bridge{$x} ";
		$lowestmtu = "1500";
		
		foreach ($bridgearray[$x] as $bridgeif) {
			// iterate through all the interfaces in this bridge
			// append to the bridgecmd for this interface
			$bridgecmd .= " addm $bridgeif ";
			// get MTU for this interface
			$mtu = get_interface_mtu($bridgeif);
			if (intval($mtu) == 0) {
				syslog(LOG_ERR, "An error occurred while trying to obtain the MTU setting for $bridgeif.  Using 1500.");
				$mtu = "1500";
			} else {
				if (intval($mtu) < intval($lowestmtu))
					$lowestmtu = $mtu;
			}
		}
		
		// force all bridged interfaces to same MTU, the lowest common denominator
		foreach ($bridgearray[$x] as $bridgeif) {
			mwexec("/sbin/ifconfig {$bridgeif} mtu {$lowestmtu}");
			fwrite($fd, "/sbin/ifconfig {$bridgeif} mtu {$lowestmtu} \n");
		}
		
		// bring up each interface
		foreach ($bridgearray[$x] as $bridgeif) {
			mwexec("/sbin/ifconfig {$bridgeif} up");
			fwrite($fd, "/sbin/ifconfig {$bridgeif} up \n");
		}
		
		// setup the bridge
		mwexec("{$bridgecmd}");
		fwrite($fd, "{$bridgecmd} \n");
		
		// in FreeBSD 6.x, without a final separate "up", it won't work
		mwexec("/sbin/ifconfig bridge{$x} up");
		fwrite($fd, "/sbin/ifconfig bridge{$x} up");
		
		fclose($fd);
	}
}

function interfaces_optional_configure6() {
	global $config, $g;
	
	for ($i = 1; isset($config['interfaces']['opt' . $i]); $i++) {
		interfaces_optional_configure_if6($i);
	}
	
	if (!$g['booting']) {
		/* reload rtadvd */
		interfaces_rtadvd_configure();
	}
	
	return 0;
}

function interfaces_optional_configure_if($opti) {
	global $config, $g;
	global $bridgeconfig;
	
	$optcfg = $config['interfaces']['opt' . $opti] ?? null;
	
	if ($g['booting']) {
		$optdescr = "";
		if (!empty($optcfg['descr']))
			$optdescr = " ({$optcfg['descr']})";
		echo "Configuring OPT{$opti}{$optdescr} interface... ";
	}
	
	if (isset($optcfg['enable'])) {		
		/* MAC spoofing? */
		if (!empty($optcfg['spoofmac']))
			mwexec("/sbin/ifconfig " . escapeshellarg($optcfg['if']) . 
				" link " . escapeshellarg($optcfg['spoofmac']));
		
		/* media */
		if (!empty($optcfg['media']) || !empty($optcfg['mediaopt'])) {
			$cmd = "/sbin/ifconfig " . escapeshellarg($optcfg['if']);
			if (!empty($optcfg['media']))
				$cmd .= " media " . escapeshellarg($optcfg['media']);
			if (!empty($optcfg['mediaopt']))
				$cmd .= " mediaopt " . escapeshellarg($optcfg['mediaopt']);
			mwexec($cmd);
		}
	
		$addflags = "";
		if (strpos($optcfg['if'], "fxp") !== false)
			$addflags .= " link0";
		
		if (isset($config['system']['polling']))
			mwexec("/sbin/ifconfig " . escapeshellarg($optcfg['if']) .  " polling");
	
		/* bridged? */
		if (!empty($optcfg['bridge'])) {
			interfaces_bridge_configure();
		} else {
			mwexec("/sbin/ifconfig " . escapeshellarg($optcfg['if']) . " " . 
				escapeshellarg($optcfg['ipaddr'] . "/" . $optcfg['subnet']) . $addflags);
		}
		interfaces_secondaries_configure('opt' . $opti);
	} else {
		mwexec("/sbin/ifconfig " . escapeshellarg($optcfg['if']) . 
			" delete down");
	}
	
	if ($g['booting'])
		echo "done\n";
	
	return 0;
}

function interfaces_optional_configure_if6($opti) {
	global $config, $g;
	
	$optcfg = $config['interfaces']['opt' . $opti] ?? null;
	
	if (isset($optcfg['enable'])) {
		remove_all_ipv6_addresses($optcfg['if'] ?? '');
		mwexec('/sbin/ifconfig ' . $optcfg['if'] . ' inet6 -accept_rtadv no_radr');
		if (ipv6enabled()) {
			if (($optcfg['ipaddr6'] ?? null) == "6to4") {
				$v6addr = calc_6to4_address("opt" . $opti);
				if ($v6addr)
					mwexec("/sbin/ifconfig " . escapeshellarg($optcfg['if']) . " inet6 $v6addr prefixlen 64 alias");
			} else if (($optcfg['ipaddr6'] ?? null) == "DHCP-PD") {
					services_dhcp6c_configure();
			} else if (!empty($optcfg['ipaddr6']) && !empty($optcfg['subnet6'])) {
				mwexec('/sbin/ifconfig ' . escapeshellarg($optcfg['if']) .
					' inet6 ' . escapeshellarg($optcfg['ipaddr6']) .
					' prefixlen ' . escapeshellarg($optcfg['subnet6'] . ' alias')
				);
			}
		interfaces_secondaries_configure( 'opt' . $opti );
		}
	}
	return 0;
}

function interfaces_wlan_configure() {
	global $config, $g;
	
	/* wireless configuration */
	if (is_array($config['wlans']['wlan'] ?? null) && count($config['wlans']['wlan'])) {
		$i = 0;
		
		foreach ($config['wlans']['wlan'] as $wlan) {
			$wlanmode = "ap";
			switch ($wlan['mode'] ?? null) {
				case 'ibss':
				case 'IBSS':
					$wlanmode = "ibss";
					break;
				case 'bss':
				case 'BSS':
					$wlanmode = "sta";
					break;
			}
			
			/* create subinterface */
			$ifcargs = "wlan$i create wlandev " . 
				escapeshellarg($wlan['if'] ?? '') . " wlanmode " . $wlanmode;
			
			if (!empty($wlan['standard']))
				$ifcargs .= " mode " . escapeshellarg($wlan['standard']);
			
			if (isset($wlan['ht']))
				$ifcargs .= " ht";
			else
				$ifcargs .= " -ht";

			$ifcargs .= " ssid " . escapeshellarg($wlan['ssid'] ?? '') . " channel " . 
				escapeshellarg($wlan['channel'] ?? '');

			/* $wlan, not $wlcfg: no such variable exists in this function, and
			   isset() on it hid that, so Hide SSID never took effect. */
			if ($wlanmode == "ap" && isset($wlan['hidessid']))
				$ifcargs .= " hidessid";
				
			$ifcargs .= " up";

			mwexec("/sbin/ifconfig " . $ifcargs);
			
			if (isset($wlan['txpower']) && strlen($wlan['txpower']) > 0) {
				/* must issue separate ifconfig call for txpower */
				mwexec("/sbin/ifconfig wlan$i txpower " . escapeshellarg($wlan['txpower']));
			}

			/* configure encryption (if needed) */
			interfaces_wlan_configure_encryption("wlan$i", $wlan);
			
			$i++;
		}
	}
	
	return 0;
}

function interfaces_wlan_configure_encryption($if, $wlcfg) {
	global $config, $g;
	
	/* kill any running hostapd */
	killbypid("{$g['varrun_path']}/hostapd-$if.pid");
	unlink_if_exists("{$g['varetc_path']}/hostapd-$if.conf");
	
	/* killing hostapd leaves the interface in down state - make sure it's up again */
	mwexec("/sbin/ifconfig " . escapeshellarg($if) . " up");

	if (!empty($wlcfg['wpa']['mode']) && $wlcfg['wpa']['mode'] != "none") {

		if (($wlcfg['mode'] ?? null) == "hostap") {
			/* use WPA in hostap mode */
			$hostapdcfg = generate_hostapd_config($if, $wlcfg);
			
			/* write config to temporary file */
			$fd = fopen("{$g['varetc_path']}/hostapd-$if.conf", "w");
			if (!$fd) {
				echo("Error: cannot open hostapd-$if.conf in interfaces_wlan_configure_encryption().\n");
				return 1;
			}
	
			fwrite($fd, $hostapdcfg);
			fclose($fd);
			
			/* start hostapd */
			mwexec("/usr/sbin/hostapd -B -P {$g['varrun_path']}/hostapd-$if.pid {$g['varetc_path']}/hostapd-$if.conf");
		}
		
	} else {
		/* use WEP (or no encryption) */
	
		if (isset($wlcfg['wep']['enable']) && is_array($wlcfg['wep']['key'] ?? null)) {
			$ifcargs = escapeshellarg($if) . " wepmode on";
			
			$i = 1;
			foreach ($wlcfg['wep']['key'] as $wepkey) {
				$wepkeyvalue = $wepkey['value'] ?? '';
				$ifcargs .= " wepkey " . escapeshellarg("{$i}:{$wepkeyvalue}");
				if (isset($wepkey['txkey'])) {
					$ifcargs .= " weptxkey {$i}";
				}
				$i++;
			}
			mwexec("/sbin/ifconfig " . $ifcargs);
		} else {
			/* no encryption - make sure WEP is disabled */
			mwexec("/sbin/ifconfig " . escapeshellarg($if) . " wepmode off");
		}
	}
}

function interfaces_wan_configure() {
	global $config, $g;
	
	$wancfg = $config['interfaces']['wan'];
	
	if ($g['booting'])
		echo "Configuring WAN interface... ";
	else {
		/* kill dhclient */
		mwexec("/usr/bin/killall dhclient");
		
		/* kill PPPoE client (mpd) */
		killbypid("{$g['varrun_path']}/mpd.pid");
		
		/* kill Modem client (mpd) */
		killbypid("{$g['varrun_path']}/mpd-modem.pid");
		
		/* wait for processes to die */
		sleep(2);
		
		unlink_if_exists("{$g['varetc_path']}/dhclient.conf");
		unlink_if_exists("{$g['varetc_path']}/mpd.conf");
		unlink_if_exists("{$g['vardb_path']}/wanip");
		unlink_if_exists("{$g['varetc_path']}/nameservers.inet.conf");
		unlink_if_exists("{$g['varetc_path']}/nameservers.inet6.conf");
	}
	
	/* remove all addresses first */
	while (mwexec("/sbin/ifconfig " . escapeshellarg($wancfg['if']) . " -alias") == 0);
	mwexec("/sbin/ifconfig " . escapeshellarg($wancfg['if']) . " down");
	
	if (!empty($wancfg['spoofmac']))
		mwexec("/sbin/ifconfig " . escapeshellarg($wancfg['if']) . 
			" link " . escapeshellarg($wancfg['spoofmac']));
		
	/* media */
	if (!empty($wancfg['media']) || !empty($wancfg['mediaopt'])) {
		$cmd = "/sbin/ifconfig " . escapeshellarg($wancfg['if']);
		if (!empty($wancfg['media']))
			$cmd .= " media " . escapeshellarg($wancfg['media']);
		if (!empty($wancfg['mediaopt']))
			$cmd .= " mediaopt " . escapeshellarg($wancfg['mediaopt']);
		mwexec($cmd);
	}
	
	$addflags = "";
	if (strpos($wancfg['if'], "fxp") !== false)
		$addflags .= " link0";
	
	if (isset($config['system']['polling']))
		mwexec("/sbin/ifconfig " . escapeshellarg($wancfg['if']) .  " polling") ;
	
	switch ($wancfg['ipaddr'] ?? null) {
	
		case 'dhcp':
			interfaces_wan_dhcp_configure();
			break;
			
		case 'pppoe':
			interfaces_wan_pppoe_configure();
			break;
			
		case 'pptp':
			interfaces_wan_pptp_configure();
			break;
			
		case 'modem':
			interfaces_wan_modem_configure();
			break;
			
		default:
			if (isset($wancfg['ispointtopoint']) && !empty($wancfg['pointtopoint'])) {
				mwexec("/sbin/ifconfig " . escapeshellarg($wancfg['if']) . " " . 
					escapeshellarg($wancfg['ipaddr'] . "/" . $wancfg['subnet']) . 
					" " . escapeshellarg($wancfg['pointtopoint']) . $addflags . " up");
			} else {
				mwexec("/sbin/ifconfig " . escapeshellarg($wancfg['if']) . " " . 
					escapeshellarg($wancfg['ipaddr'] . "/" . $wancfg['subnet']) . $addflags);
			}
			
			/* install default route */
			mwexec("/sbin/route delete default");
			mwexec("/sbin/route add default " . escapeshellarg($wancfg['gateway'] ?? ''));
			
			/* resync ipfilter (done automatically for DHCP/PPPoE/PPTP) */
			filter_resync();
	}
	
	interfaces_wan_configure6();
	
	if (!$g['booting']) {
		/* reconfigure static routes (kernel may have deleted them) */
		system_routing_configure();
		
		/* reload ipfilter */
		filter_configure();
		
		/* reload shaper */
		shaper_configure();
		
		/* reload ipsec tunnels */
		vpn_ipsec_configure();
		
		/* restart ez-ipupdate */
		services_dyndns_configure();
		
		/* force DNS update */
		services_dnsupdate_process();
		
		/* restart dnsmasq */
		services_dnsmasq_configure();
	}
	
	if ($g['booting'])
		echo "done\n";
	
	return 0;
}

function interfaces_wan_configure6($newwanip = false) {
	global $config, $g;
	
	$wancfg = $config['interfaces']['wan'];
	$wanif = get_real_wan_interface(true);
	
	remove_all_ipv6_addresses($wancfg['if']);
	remove_all_ipv6_addresses("stf0");
	remove_all_ipv6_addresses("gif0");
	services_dhcp6c_stop();
	mwexec('/sbin/ifconfig ' . $wanif . ' inet6 -accept_rtadv no_radr');	
	mwexec("/sbin/sysctl net.inet6.ip6.rfc6204w3=0");
	
	/* kill any running aiccu */
	if (file_exists("{$g['varrun_path']}/aiccu.pid")) {
		sigkillbypid("{$g['varrun_path']}/aiccu.pid", "TERM");
		
		/* AICCU doesn't exit immediately after receiving SIGTERM, as it only polls
		   its "running" flag once per second. We give it 3 seconds to exit, and then send
		   a SIGKILL if necessary */
		for ($i = 0; $i < 30 && file_exists("{$g['varrun_path']}/aiccu.pid"); $i++)
			usleep(100000);
		if (file_exists("{$g['varrun_path']}/aiccu.pid"))
			sigkillbypid("{$g['varrun_path']}/aiccu.pid", "KILL");
	}
	
	if (ipv6enabled()) {
		if (($wancfg['ipaddr6'] ?? null) == "6to4") {
			/* obtain current IPv4 address and make a 6to4 address out of it */
			$v6addr = calc_6to4_address("wan");
			
			if ($v6addr) {
				mwexec("/sbin/ifconfig stf0 create");
				mwexec("/sbin/ifconfig stf0 inet6 $v6addr prefixlen 16 alias");
				mwexec('/sbin/route delete -inet6 default');
		
				/* always use 6to4 anycast address 192.88.99.1 for now */
				mwexec('/sbin/route add -inet6 default 2002:c058:6301::');
			
				if (!$g['booting']) {
					/* a changed 6to4 prefix on WAN means we may also need to change the
					   IPv6 prefix on LAN/OPT */
					interfaces_lan_configure6();
					interfaces_optional_configure6();
				}
			}
		} else if (($wancfg['ipaddr6'] ?? null) == "DHCP") {
			services_dhcp6c_configure();
			mwexec('/sbin/ifconfig ' . $wanif . ' inet6 accept_rtadv -no_radr');
			mwexec("/sbin/sysctl net.inet6.ip6.rfc6204w3=1");
		} else if (($wancfg['ipaddr6'] ?? null) == "ppp") {
			if ($newwanip) {
				/* called from up-script -> add IPv6 default route */
				mwexec('/sbin/route delete -inet6 default');
				mwexec('/sbin/route add -inet6 default -iface ' . $g['pppoe_interface']);
				mwexec('/sbin/ifconfig ' . $wanif . ' inet6 accept_rtadv no_radr');
			}
			if (($config['interfaces']['lan']['ipaddr6'] ?? null) == "DHCP-PD") {
				services_dhcp6c_configure();
			}
		} else if (($wancfg['ipaddr6'] ?? null) == "aiccu") {
			/* fire up AICCU, which will take care of setting the IP address
			   on gif0 and adding the default route */
			
			/* can only start AICCU once the IPv4 connectivity is
			   ready; otherwise it will exit immediately... */
			if ($newwanip || is_ipaddr($wancfg['ipaddr'] ?? '')) {
				if (is_ipaddr($wancfg['ipaddr'] ?? '')) {
					sleep(10);
				}
				$aiccuuser = $wancfg['aiccu']['username'] ?? '';
				$aiccupass = $wancfg['aiccu']['password'] ?? '';
				$aiccutunnelid = $wancfg['aiccu']['tunnelid'] ?? '';
				$aiccuconf = <<<EOD
username {$aiccuuser}
password {$aiccupass}
tunnel_id {$aiccutunnelid}
ipv6_interface gif0
daemonize true
automatic true
requiretls false
pidfile {$g['varrun_path']}/aiccu.pid
defaultroute true

EOD;

				$fd = fopen("{$g['varetc_path']}/aiccu.conf", "w");
				fwrite($fd, $aiccuconf);
				fclose($fd);
			
				/* SixXS shut down in June 2017 and aiccu has nothing to talk to.
				   The config option is left in place so an existing config.xml
				   still parses, but nothing is started and the GUI says so. */
				log_error("IPv6: the SixXS/AICCU tunnel type no longer works -- SixXS shut down in 2017. Use a 6in4 tunnel or native IPv6.");
			
				/* at this point, it can take anywhere from a millisecond to forever
				   until gif0 has been configured by AICCU. Unfortunately, the
				   "setupscript" option in aiccu.conf isn't actually implemented
				   under Unix, so to figure out when gif0 comes up, we need to
				   watch it with a little shell script... */
				$watchsh = <<<EOD
#!/bin/sh

while true; do
	/sbin/ifconfig gif0 > /dev/null 2>&1
	if [ $? = 0 ]; then
		sleep 1
		/etc/rc.newwanip6
		exit
	fi
	sleep 1
done

EOD;
				$fd = fopen("{$g['tmp_path']}/gifwatch.sh", "w");
				fwrite($fd, $watchsh);
				fclose($fd);
				chmod("{$g['tmp_path']}/gifwatch.sh", 0755);
			
				mwexec_bg("{$g['tmp_path']}/gifwatch.sh");
			}
		} else {
			if (!empty($wancfg['ipaddr6']) && !empty($wancfg['subnet6']) && (!empty($wancfg['tunnel6']) || !empty($wancfg['gateway6']))) {
				$wanif6 = $wancfg['if'];
				$gw6 = escapeshellarg($wancfg['gateway6'] ?? '');
				
				/* use GIF tunnel? */
				if (!empty($wancfg['tunnel6'])) {
					$curwanip6 = get_current_wan_address(false);
					
					if ($curwanip6) {
						$wanif6 = "gif0";
						$gw6 = "-iface gif0";
						
						mwexec('/sbin/ifconfig gif0 create');
						mwexec('/sbin/ifconfig gif0 tunnel ' . escapeshellarg($curwanip6) . ' ' . escapeshellarg($wancfg['tunnel6']));
						mwexec('/sbin/ifconfig gif0 up');
					} else {
						$wanif6 = false;
					}
				}
				
				if ($wanif6) {
					mwexec('/sbin/ifconfig ' . escapeshellarg($wanif6) .
						' inet6 ' . escapeshellarg($wancfg['ipaddr6']) .
						' prefixlen ' . escapeshellarg($wancfg['subnet6'] . ' alias')
					);
					/* default route */
					mwexec('/sbin/route delete -inet6 default');
					mwexec('/sbin/route add -inet6 default ' . $gw6);
				}
			}
		}
	}
	if (!$g['booting']) {
		/* reload rtadvd */
		interfaces_rtadvd_configure();
	}
}

function interfaces_wan_dhcp_configure() {
	global $config, $g;
	
	$wancfg = $config['interfaces']['wan'];

	/* generate dhclient.conf */
	$fd = fopen("{$g['varetc_path']}/dhclient.conf", "w");
	if (!$fd) {
		echo("Error: cannot open dhclient.conf in interfaces_wan_dhcp_configure().\n");
		return 1;
	}
 
 	$dhclientconf = "";
 
 	if (!empty($wancfg['dhcphostname'])) {
		$dhclientconf .= <<<EOD
send dhcp-client-identifier "{$wancfg['dhcphostname']}";
interface "{$wancfg['if']}" {
	send host-name "{$wancfg['dhcphostname']}";
}

EOD;
	}

	fwrite($fd, $dhclientconf);
	fclose($fd);
	
	/* Fire up dhclient, backgrounding immediately rather than waiting for the
	   lease (-b; ISC's spelling was -nw).

	   The flags matter: FreeBSD's base dhclient is OpenBSD-derived and takes
	   "dhclient [-bdqu] [-c file] [-l file] [-p file] interface". The old
	   ISC flags -nw/-cf/-sf are not merely different spellings -- dhclient
	   rejects them, prints its usage and exits 1, so a WAN set to DHCP (the
	   factory default) never obtained an address at all. There is no -sf:
	   the script path is compiled in as /sbin/dhclient-script, which is
	   where m0n0wall installs its own.

	   -p because the default pidfile is /var/run/dhclient/dhclient.<if>.pid
	   and that directory does not exist on the image, which dhclient reports
	   as "Cannot open or create pidfile" before exiting. */
	mwexec("/sbin/ifconfig " . escapeshellarg($wancfg['if']) . " up");
	mwexec("/sbin/dhclient -b -c {$g['varetc_path']}/dhclient.conf " .
		"-p " . escapeshellarg("{$g['varrun_path']}/dhclient." . $wancfg['if'] . ".pid") . " " .
		escapeshellarg($wancfg['if']));
	
	return 0;
}

function interfaces_wan_dhcp_down() {
	global $config, $g;

	/* Base dhclient has no release (-r) -- that was ISC's, and the old call
	   passed no interface either, so this only ever reached the killall.
	   Kill the client and drop the address explicitly. */
	mwexec("/usr/bin/killall dhclient");
	sleep(1);
	if (!empty($config['interfaces']['wan']['if']))
		mwexec("/sbin/ifconfig " . escapeshellarg($config['interfaces']['wan']['if']) . " delete");
	/* base dhclient writes /var/run/dhclient.<interface>.pid */
	if (!empty($config['interfaces']['wan']['if']))
		unlink_if_exists("{$g['varrun_path']}/dhclient." . $config['interfaces']['wan']['if'] . ".pid");
	unlink_if_exists("{$g['varrun_path']}/dhclient.pid");
}

function interfaces_wan_dhcp_up() {
	interfaces_wan_dhcp_configure();

	sleep(10);
}

function interfaces_wan_pppoe_configure() {
	global $config, $g;
	
	$wancfg = $config['interfaces']['wan'];
	$pppoecfg = $config['pppoe'] ?? null;
	
	/* generate mpd.conf */
	$fd = fopen("{$g['varetc_path']}/mpd.conf", "w");
	if (!$fd) {
		echo("Error: cannot open mpd.conf in interfaces_wan_pppoe_configure().\n");
		return 1;
	}
	
	$mtu = 1492;
	if (!empty($pppoecfg['mtu']))
		$mtu = $pppoecfg['mtu'];
	
	$mpdconf = <<<EOD
startup:

pppoe:
	create bundle static B1
	set iface name ngwan0
	set iface route default
	set iface up-script /usr/local/sbin/ppp-linkup
	set iface enable tcpmssfix
	set ipcp yes vjcomp
	set ipcp ranges 0.0.0.0/0 0.0.0.0/0

EOD;


	/* IPv6 enabled on WAN interface? */
	if (($wancfg['ipaddr6'] ?? null) == "ppp") {
		$mpdconf .= "	set bundle enable ipv6cp\n";
	}

	if (isset($config['system']['dnsallowoverride'])) {
		$mpdconf .= <<<EOD
	set ipcp enable req-pri-dns

EOD;
		if (!isset($config['pppoe']['dnsnosec'])) {
			$mpdconf .= <<<EOD
	set ipcp enable req-sec-dns

EOD;
		}
	}
	
	$pppoeuser = $pppoecfg['username'] ?? '';
	$pppoepass = $pppoecfg['password'] ?? '';
	$pppoeprovider = $pppoecfg['provider'] ?? '';
	$mpdconf .= <<<EOD
	
	create link static L1 pppoe
	set link action bundle B1
	set auth authname "{$pppoeuser}"
	set auth password "{$pppoepass}"
	set link keep-alive 10 60
	set link max-redial 0
	set link no acfcomp protocomp
	set link disable pap chap
	set link accept chap
	set link mtu $mtu
	set pppoe iface {$wancfg['if']}
	set pppoe service "{$pppoeprovider}"
	open

EOD;
	
	fwrite($fd, $mpdconf);
	fclose($fd);
	
	/* fire up mpd */
	mwexec("/usr/local/sbin/mpd5 -b -d {$g['varetc_path']} -p {$g['varrun_path']}/mpd.pid pppoe");
	
	return 0;
}

function interfaces_wan_pppoe_down() {
	global $g;
	sigkillbypid("{$g['varrun_path']}/mpd.pid", "SIGUSR2");

	sleep(3);
}

function interfaces_wan_pppoe_up() {
	global $g;
	sigkillbypid("{$g['varrun_path']}/mpd.pid", "SIGUSR1");

	sleep(3);
}

function interfaces_wan_pptp_configure() {
	global $config, $g;
	
	$wancfg = $config['interfaces']['wan'];
	$pptpcfg = $config['pptp'] ?? null;
	
	/* generate mpd.conf */
	$fd = fopen("{$g['varetc_path']}/mpd.conf", "w");
	if (!$fd) {
		echo("Error: cannot open mpd.conf in interfaces_wan_pptp_configure().\n");
		return 1;
	}
		
	$mpdconf = <<<EOD
startup:

pptp:
	create bundle static B1
	set iface name ngwan0
	set iface route default
	set iface up-script /usr/local/sbin/ppp-linkup
	set ipcp no vjcomp
	set ipcp ranges 0.0.0.0/0 0.0.0.0/0

EOD;

	/* IPv6 enabled on WAN interface? */
	if (($wancfg['ipaddr6'] ?? null) == "ppp") {
		$mpdconf .= "	set bundle enable ipv6cp\n";
	}
	
	if (isset($config['system']['dnsallowoverride'])) {
		$mpdconf .= <<<EOD
	set ipcp enable req-pri-dns
	set ipcp enable req-sec-dns

EOD;
	}
	
	$pptpuser = $pptpcfg['username'] ?? '';
	$pptppass = $pptpcfg['password'] ?? '';
	$pptplocal = $pptpcfg['local'] ?? '';
	$pptpremote = $pptpcfg['remote'] ?? '';
	$mpdconf .= <<<EOD
	
	create link static L1 pptp
	set link action bundle B1
	set auth authname "{$pptpuser}"
	set auth password "{$pptppass}"
	set link keep-alive 10 60
	set link max-redial 0
	set link no acfcomp protocomp
	set link disable pap chap
	set link accept chap
	set pptp enable outcall
	set pptp disable windowing
	set pptp self {$pptplocal}
	set pptp peer {$pptpremote}
	open

EOD;

	fwrite($fd, $mpdconf);
	fclose($fd);
	
	/* configure interface */
	mwexec("/sbin/ifconfig " . escapeshellarg($wancfg['if']) . " " . 
		escapeshellarg(($pptpcfg['local'] ?? '') . "/" . ($pptpcfg['subnet'] ?? '')));
	
	/* fire up mpd */
	mwexec("/usr/local/sbin/mpd5 -b -d {$g['varetc_path']} -p {$g['varrun_path']}/mpd.pid pptp");
	
	return 0;
}

function interfaces_wan_pptp_down() {
	global $g;
	sigkillbypid("{$g['varrun_path']}/mpd.pid", "SIGUSR2");

	sleep(3);
}

function interfaces_wan_pptp_up() {
	global $g;
	sigkillbypid("{$g['varrun_path']}/mpd.pid", "SIGUSR1");

	sleep(3);
}

function interfaces_wan_modem_configure() {
	global $config, $g;
	
	$wancfg = $config['interfaces']['wan'];
	$modemcfg = $config['modem'] ?? null;
	
	/* generate mpd.conf */
	if (!file_exists("{$g['varetc_path']}/mpd-modem"))
		mkdir("{$g['varetc_path']}/mpd-modem");
	$fd = fopen("{$g['varetc_path']}/mpd-modem/mpd.conf", "w");
	if (!$fd) {
		echo("Error: cannot open mpd.conf in interfaces_wan_modem_configure().\n");
		return 1;
	}
		
	$mpdconf = <<<EOD
startup:

modem:
	create bundle static B1
	set iface name ngwan0
	set iface route default
	set iface up-script /usr/local/sbin/ppp-linkup
	set ipcp no vjcomp
	set ipcp ranges 0.0.0.0/0 10.10.10.0/0
	set iface disable on-demand
	set iface idle 0
	set iface enable tcpmssfix
	
EOD;

	/* IPv6 enabled on WAN interface? */
	if (($wancfg['ipaddr6'] ?? null) == "ppp") {
		$mpdconf .= "	set bundle enable ipv6cp\n";
	}
	
	if (isset($config['system']['dnsallowoverride'])) {
		$mpdconf .= <<<EOD
	set ipcp enable req-pri-dns
	set ipcp enable req-sec-dns

EOD;
	}
	
	$modemuser = $modemcfg['username'] ?? '';
	$modempass = $modemcfg['password'] ?? '';
	$modemapn = $modemcfg['apn'] ?? '';
	$mpdconf .= <<<EOD
	
	create link static L1 modem
	set auth authname "{$modemuser}"
	set auth password "{$modempass}"
	set link keep-alive 10 60
	set link max-redial 0
	set link disable pap chap
	set link accept chap pap eap
	set link action bundle B1
	set link disable multilink
	set link disable incoming
	set link mtu 1492
	set modem device "{$wancfg['if']}"
	set modem script DialPeer
	set modem idle-script Ringback
	set modem watch -cd
	set modem var \$DialPrefix "DT"
	set modem var \$Telephone "*99***1#"
	set modem var \$APNstring "{$modemapn}"
	open


EOD;

	fwrite($fd, $mpdconf);
	fclose($fd);
	
	if ($g['booting']) {
		echo 'Waiting for USB modems to settle... ';
		sleep(5);
	}
	/* fire up mpd */
	mwexec("/usr/local/sbin/mpd5 -b -d {$g['etc_path']}/mpd-modem -f {$g['varetc_path']}/mpd-modem/mpd.conf -p {$g['varrun_path']}/mpd-modem.pid modem");
	
	return 0;
}

function interfaces_wan_modem_down() {
	global $g;
	sigkillbypid("{$g['varrun_path']}/mpd-modem.pid", "SIGUSR2");

	sleep(3);
}

function interfaces_wan_modem_up() {
	global $g;
	sigkillbypid("{$g['varrun_path']}/mpd-modem.pid", "SIGUSR1");

	sleep(3);
}

function interfaces_rtadvd_configure() {
	global $config, $g;
	$syscfg = $config['system'] ?? null;

	/* kill any running rtadvd */
	killbyname('rtadvd');

	$wasrunning = file_exists("{$g['varrun_path']}/rtadvd.pid");

	if (!ipv6enabled())
		return 0;

	/* rtadvd enabled on any interfaces? */
	$rtadvdifs = '';
	$rtadvdconf = '';
	
	if (isset($config['interfaces']['lan']['ipv6ra'])) {
		$raflags = "";
		if (isset($config['interfaces']['lan']['ipv6ram'])) {
			$raflags .= "m";
		}
		if (isset($config['interfaces']['lan']['ipv6rao'])) {
			$raflags .= "o";
		}
		$rtadvdifs .= ' ' . $config['interfaces']['lan']['if'];
		$rtadvdconf .= $config['interfaces']['lan']['if'] . ":raflags=\"" . $raflags . "\":maxinterval#10:mininterval#4:prefixlen#";
		if (($config['interfaces']['lan']['ipv6mode'] ?? null) == "DHCP-PD") {
			$rtadvdconf .= 64 - ($config['interfaces']['lan']['slalen'] ?? null);
		} else {
			$rtadvdconf .= $config['interfaces']['lan']['subnet6'] ?? '';
		}
		if (isset($config['interfaces']['lan']['ipv6ramtu']) && $config['interfaces']['lan']['ipv6ramtu'] > 0) {
			$rtadvdconf .= ":mtu#" . $config['interfaces']['lan']['ipv6ramtu'];
		}

		$dnsservers = array();
		if (isset($config['dnsmasq']['enable']))
			$dnsservers = array($config['interfaces']['lan']['ipaddr6'] ?? '');
		else if (is_array($syscfg['dnsserver'] ?? null) && (!empty($syscfg['dnsserver'][0])))
			$dnsservers = $syscfg['dnsserver'];
		
		$dnsservers = array_filter($dnsservers, "is_ipaddr6");
		if (!empty($dnsservers))
			$rtadvdconf .= ":rdnss=\"" . join(",", $dnsservers) . "\"";

		$rtadvdconf .= ":dnssl=\"" . ($syscfg['domain'] ?? '') . "\"";
		$rtadvdconf .= ":\n";

	}
	
	if (isset($config['interfaces']['wan']['ipv6ra'])) {
		$wanif = get_real_wan_interface(true);
		$rtadvdifs .= ' ' . $wanif;
		$rtadvdconf .= $wanif . ":maxinterval#10:mininterval#4\n";
	}
	
	for ($i = 1; isset($config['interfaces']['opt' . $i]); $i++) {
		$optcfg = $config['interfaces']['opt' . $i];
		if (isset($optcfg['ipv6ra']) && isset($optcfg['enable']) &&
			!empty($optcfg['if']) && empty($optcfg['bridge'])) {
			$raflags = "";
			if (isset($config['interfaces']['opt' . $i]['ipv6ram'])) {
				$raflags .= "m";
			}
			if (isset($config['interfaces']['opt' . $i]['ipv6rao'])) {
				$raflags .= "o";
			}
			$rtadvdifs .= ' ' . $optcfg['if'];
			/* maybe this can be configurable in the future */
			$rtadvdconf .= $optcfg['if'] . ":raflags=\"" . $raflags . "\":maxinterval#10:mininterval#4:prefixlen#";
			if (($config['interfaces']['opt' . $i]['ipv6mode'] ?? null) == "DHCP-PD") {
				$rtadvdconf .= 64 - ($config['interfaces']['opt' . $i]['slalen'] ?? null);
			} else {
				$rtadvdconf .= $config['interfaces']['opt' . $i]['subnet6'] ?? '';
			}
			if (isset($config['interfaces']['opt' . $i]['ipv6ramtu']) && $config['interfaces']['opt' . $i]['ipv6ramtu'] > 0) {
				$rtadvdconf .= ":mtu#" . $config['interfaces']['opt' . $i]['ipv6ramtu'];
			}

			$dnsservers = array();
			if (isset($config['dnsmasq']['enable']))
				$dnsservers = array($optcfg['ipaddr6'] ?? '');
			else if (is_array($syscfg['dnsserver'] ?? null) && (!empty($syscfg['dnsserver'][0])))
				$dnsservers = $syscfg['dnsserver'];
			
			$dnsservers = array_filter($dnsservers, "is_ipaddr6");
			if (!empty($dnsservers))
				$rtadvdconf .= ":rdnss=\"" . join(",", $dnsservers) . "\"";

			$rtadvdconf .= ":dnssl=\"" . ($syscfg['domain'] ?? '') . "\"";
			$rtadvdconf .= ":\n";
		}
	}

	if (!$rtadvdifs)
		return 0;

	if ($g['booting'])
		echo 'Starting IPv6 router advertisement service... ';
	else if ($wasrunning) {
		/* rtadvd first sends out advertisements that
			there are no longer routes before effectively exiting
			(look at die() in rtadvd.c); this can take up to 10 seconds, but we
			don't want to wait that long - just give it time to send out one
			such advertisement */
		sleep(1);
		sigkillbyname('rtadvd', 'KILL');
	}

	/* this file is deleted here be
	se we might create a race condition
		when deleting it earlier */
	unlink_if_exists("{$g['varrun_path']}/rtadvd.pid");

	/* write rtadvd.conf */
	$fd = fopen("{$g['varetc_path']}/rtadvd.conf", 'w');
	if (!$fd) {
		printf("Error: cannot open rtadvd.conf in interfaces_rtadvd_configure().\n");
		return 1;
	}
	fwrite($fd, $rtadvdconf);
	fclose($fd);

	/* fire up rtadvd */
	mwexec("/usr/sbin/rtadvd -D -c {$g['varetc_path']}/rtadvd.conf $rtadvdifs 2>&1 & " .
		"echo \"$!\" > {$g['varrun_path']}/rtadvd.pid");

	if (!$g['booting']) {
		filter_configure();
	} else
		echo "done\n";

	return 0;
}

function interfaces_autoreassign() {
	global $config, $g;
	
	if (isset($config['interfaces']['noautoreassign']))
		return;
	
	$iflist = get_interface_list(true, false, false);
	
	$logifs = array('lan', 'wan');
	for ($i = 1; isset($config['interfaces']['opt' . $i]); $i++)
		$logifs[] = 'opt' . $i;
	
	/* Compare list of available interfaces with those in config to see whether
	   at least one of them is available. Bail out on VLAN/WLAN configs too - we
	   only intend to handle the normal case (one Ethernet interface per logical
	   interface) */
	foreach ($logifs as $logif) {
		$logifif = $config['interfaces'][$logif]['if'] ?? '';
		if (isset($iflist[$logifif]) || preg_match("/^(vlan|wlan)/", $logifif))
			return;
	}
	
	/* at this point, we have found that there are no VLANs/WLANs and none of the
	   configured physical interfaces can be found. Reconfigure automatically */
	echo <<<EOD


*******************************************************************************
* None of the assigned network interfaces could be found.                     *
* This usually happens when installing on a new system, or when moving an     *
* existing configuration to a different hardware. In that case, it does not   *
* indicate a problem.                                                         *
*                                                                             *
* The logical interfaces (LAN/WAN/OPT) will be reconfigured automatically     *
* using the available physical network interfaces. Please review the          *
* assignments and change them if necessary.                                   *
*******************************************************************************


EOD;
	
	if (count($iflist) < 2) {
		echo "ERROR: fewer than two network interfaces found. You need at least two interfaces (for LAN and WAN).\n\n";
		return;
	}
	
	/* sort list alphabetically to get some consistency */
	$ifnames = array_keys($iflist);
	sort($ifnames);
	
	/* assign first interface to LAN, second to WAN and any further interfaces to OPT */
	$config['interfaces']['lan']['if'] = $ifnames[0];
	$config['interfaces']['wan']['if'] = $ifnames[1];
	
	for ($i = 2; isset($ifnames[$i]); $i++) {
		$opti = $i - 1;
		if (isset($config['interfaces']['opt' . $opti])) {
			$config['interfaces']['opt' . $opti]['if'] = $ifnames[$i];
		}
	}
	
	write_config();
}

function get_real_wan_interface($ipv6 = false) {
	global $config, $g;
	
	$wancfg = $config['interfaces']['wan'];
	
	$wanif = $wancfg['if'];
	
	if ($ipv6) {
		if (($wancfg['ipaddr6'] ?? null) == "6to4")
			$wanif = "stf0";
		else if (($wancfg['ipaddr6'] ?? null) == "aiccu" && !isset($config['interfaces']['wan']['aiccu']['ayiya']))
			$wanif = "gif0";
		else if (($wancfg['ipaddr6'] ?? null) == "aiccu" && isset($config['interfaces']['wan']['aiccu']['ayiya']))
			$wanif = "tun0";
		else if (!empty($wancfg['tunnel6']))
			$wanif = "gif0";
		else if (($wancfg['ipaddr6'] ?? null) == "ppp")
			$wanif = $g['pppoe_interface'];
	} else {
		if ((($wancfg['ipaddr'] ?? null) == "pppoe") || (($wancfg['ipaddr'] ?? null) == "pptp") || (($wancfg['ipaddr'] ?? null) == "modem")) {
			$wanif = $g['pppoe_interface'];
		}
	}
	
	return $wanif;
}

function get_current_wan_address($ipv6 = false) {
	global $config, $g;
	
	$wancfg = $config['interfaces']['wan'];
	
	if (in_array($wancfg['ipaddr'] ?? null, array('pppoe','dhcp','pptp','modem')) || ($ipv6 && ($wancfg['ipaddr6'] ?? null) == "aiccu")) {
		/* dynamic WAN IP address, find out which one */
		$wanif = get_real_wan_interface($ipv6);
		
		if ($ipv6) {
			/* if the IPv4 address is dynamic, then the IPv6 address could also be
			   (in case we're using 6to4) */
			
			/* can't use netstat for IPv6, as it will always truncate addresses, even if -W is used :( */
			exec("/sbin/ifconfig " . escapeshellarg($wanif) . " 2>/dev/null", $ifinfo);
			
			foreach ($ifinfo as $line) {
				if (preg_match("/inet6 ([0-9a-f:]+) /", $line, $matches)) {
					if (is_ipaddr6($matches[1]))
						return $matches[1];
				}
			}
			
		} else {
			/* get interface info with netstat */
			exec("/usr/bin/netstat -nWI " . escapeshellarg($wanif) . " -f inet", $ifinfo);

			if (isset($ifinfo[1])) {
				$aif = preg_split("/\s+/", $ifinfo[1]);
				$curwanip = chop($aif[3] ?? '');

				if ($curwanip && is_ipaddr($curwanip) && ($curwanip != "0.0.0.0"))
					return $curwanip;
			}
		}
		
		return null;
	} else {
		/* static WAN IP address */
		return $wancfg[$ipv6 ? 'ipaddr6' : 'ipaddr'] ?? null;
	}
}

function get_interface_mac($interface) {
  
        /* build interface list with netstat */
        exec("/usr/bin/netstat -I $interface -nW -f link", $linkinfo);
        array_shift($linkinfo);
        $alink = preg_split("/\s+/", $linkinfo[0] ?? '');
        $mac = chop($alink[3] ?? '');
        return $mac;
}

function generate_hostapd_config($if, $wlcfg) {
	$wlssid = $wlcfg['ssid'] ?? '';
	$wpaversion = $wlcfg['wpa']['version'] ?? '';
	$config = <<<EOD
interface=$if
driver=bsd
logger_syslog=-1
logger_syslog_level=2
logger_stdout=0
ssid={$wlssid}
wpa={$wpaversion}

EOD;
	
	if (($wlcfg['wpa']['mode'] ?? null) == "psk") {
		$wpapsk = $wlcfg['wpa']['psk'] ?? '';
		$config .= <<<EOD
wpa_key_mgmt=WPA-PSK
wpa_passphrase={$wpapsk}

EOD;
	} else if (($wlcfg['wpa']['mode'] ?? null) == "enterprise") {
	
		$authport = 1812;
		$acctport = 1813;
		if (!empty($wlcfg['wpa']['radius']['authport']))
			$authport = $wlcfg['wpa']['radius']['authport'];
		if (!empty($wlcfg['wpa']['radius']['acctport']))
			$acctport = $wlcfg['wpa']['radius']['acctport'];
		$radiusserver = $wlcfg['wpa']['radius']['server'] ?? '';
		$radiussecret = $wlcfg['wpa']['radius']['secret'] ?? '';
	
		$config .= <<<EOD
ieee8021x=1
wpa_key_mgmt=WPA-EAP
auth_server_addr={$radiusserver}
auth_server_port={$authport}
auth_server_shared_secret={$radiussecret}
acct_server_addr={$radiusserver}
acct_server_port={$acctport}
acct_server_shared_secret={$radiussecret}

EOD;
	}
	
	if (($wlcfg['wpa']['cipher'] ?? null) == "tkip")
		$config .= "wpa_pairwise=TKIP\n";
	else if (($wlcfg['wpa']['cipher'] ?? null) == "ccmp")
		$config .= "wpa_pairwise=CCMP\n";
	else
		$config .= "wpa_pairwise=TKIP CCMP\n";
		
	if (isset($wlcfg['wpa']['grouprekey'])) {
		$config .= "wpa_group_rekey=".$wlcfg['wpa']['grouprekey']."\n";
	}
	
	return $config;
}

function get_interface_ipv6_adresses($if) {
	$addresses = array();
	unset($ifc);
	exec('/sbin/ifconfig ' . escapeshellarg($if) . ' 2>/dev/null', $ifc);

	foreach ($ifc as $i) {
		if (preg_match('/inet6 (.+) prefixlen (\d+)/', $i, $matches)) {
			$ip6 = preg_replace('/%.*$/', '', trim($matches[1]));
			array_push($addresses, array($ip6, (int)$matches[2]));
		}
	}

	return $addresses;
}

function remove_all_ipv6_addresses($if) {
	$addresses = get_interface_ipv6_adresses($if);

	foreach ($addresses as $adr) {
		if (!preg_match('/^fe80:/', $adr[0])) {
			mwexec('/sbin/ifconfig ' . escapeshellarg($if) .
				' inet6 ' . escapeshellarg($adr[0]) . ' -alias');
		}
	}
}

function calc_6to4_address($if) {
	$wan_v6nibbles = convert_to_6to4_nibbles(get_current_wan_address(false));
	if ($wan_v6nibbles) {
		$nth = null;
		if ($if == "wan")
			$nth = 0;
		else if ($if == "lan")
			$nth = 1;
		else if (preg_match('/^opt(\d+)$/', $if, $matches))
			$nth = $matches[1] + 1;
		
		return "2002:{$wan_v6nibbles}:{$nth}::1";
	}
	return false;
}

function get_dhcppd_address($if) {
	$addresses = get_interface_ipv6_adresses($if);
	$ipv6addr = null;

	foreach ($addresses as $adr) {
		if ((!preg_match('/^fe80:/', $adr[0])) || (!preg_match('/autoconf$/',$adr[0]))) {
			$ipv6addr=$adr;
		}
	}
	return $ipv6addr;
	
}

function suggest_ipv6_lan_addr(){
	$sugipv6lan = "No RA found! Maybe try again in a few minutes.";
	 /* get the prefix */
	exec("/usr/bin/tail -n 1000 /var/log/system.log", $logarr);
	
	foreach ($logarr as $logent) {
		$logent = preg_split("/\s+/", $logent, 6);
		$lograsrch = strstr($logent[5] ?? '' , "<prefix_check> prefix ");
		if ($lograsrch) {
			$prefixpos = strpos($lograsrch, "/",0);
			$sugipv6lan = substr($lograsrch,21,$prefixpos -21);	
			$sugipv6lan .= "1" . substr($lograsrch,$prefixpos,strpos($lograsrch, "from",0)-$prefixpos);
		} 
	}
	if (!is_ipaddr6andprefix ($sugipv6lan) && ($sugipv6lan != "No RA found. Maybe try again in a few minutes.")) {
		return "Error calculating IPv6 address!";
	} else {
		return $sugipv6lan;
	}
}
?>
