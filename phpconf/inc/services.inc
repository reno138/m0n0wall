<?php
/*
	$Id$
	part of m0n0wall (http://m0n0.ch/wall)
	
	Copyright (C) 2003-2007 Manuel Kasper <mk@neon1.net>.
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

function services_dhcp6c_stop() {
	global $g;

	/* kill any running dhcp6c */
	killbypid("{$g['varrun_path']}/dhcp6c.pid");
	mwexec('/sbin/sysctl net.inet6.ip6.accept_rtadv=0');
}

function services_dhcp6c_configure() {
	global $config, $g;
	
	/* kill any running dhcp6c */
	killbypid("{$g['varrun_path']}/dhcp6c.pid");
	
	/* write dhcp6c_duid */
	if ($config['interfaces']['wan']['v6duid']) {
		
		$dhcp6duid = $config['interfaces']['wan']['v6duid'] ;
		$fd = fopen("{$g['vardb_path']}/dhcp6c_duid", "w");
		if (!$fd) {
			printf("Error: cannot open dhcp6c_duid in services_dhcp6c_configure().\n");
			return 1;
		}
	
		$duidbytes = explode(":",$dhcp6duid);
	
		foreach ($duidbytes as $duidpiece) {
		    $tmpdhcp6duid .= pack("H*", $duidpiece);    
		}

		fwrite($fd, chr(strlen($tmpdhcp6duid)) . chr(0) . $tmpdhcp6duid);
		fclose($fd);
	}
	
	/* write dhcp6c.conf */
	$wanif = get_real_wan_interface();
	$fd = fopen("{$g['varetc_path']}/dhcp6c.conf", "w");
	if (!$fd) {
		printf("Error: cannot open dhcp6c.conf in services_dhcp6c_configure().\n");
		return 1;
	}
	
	if ($config['interfaces']['wan']['ipaddr6'] == "DHCP") {
		mwexec('/sbin/sysctl net.inet6.ip6.accept_rtadv=1');
		$d6wans = <<<EOD
		request domain-name-servers;
		script "/etc/dhcp6c-exit-hooks";
		send ia-na 0;

EOD;
	}
	$p = 1;
	if ($config['interfaces']['lan']['ipaddr6'] == "DHCP-PD") {
		$d6wanm = "\t\tsend ia-pd 0;\n";
		$d6pds = "id-assoc pd 0 {\n";
		$d6pde = "};\n";
		if (isset($config['interfaces']['lan']['slaid'])) {
			$d6pdi = $config['interfaces']['lan']['slaid'];
		} else {
			$d6pdi = $p;
		}
		if (isset($config['interfaces']['lan']['slalen'])) {
			$d6pdl = $config['interfaces']['lan']['slalen'];
		} else {
			$d6pdl = 16;
		}
		$d6lan .= <<<EOD
		prefix-interface {$config['interfaces']['lan']['if']} {
			sla-id {$d6pdi};
			sla-len {$d6pdl};
		};

EOD;
	$p++;
	}
			
	for ($i = 1; isset($config['interfaces']['opt' . $i]); $i++) {
		if ($config['interfaces']['opt' . $i]['ipaddr6'] == "DHCP-PD") {
			$d6wanm = "\t\tsend ia-pd 0;\n";
			$d6pds = "id-assoc pd 0 {\n";
			$d6pde = "};\n";
			if (isset($config['interfaces']['opt' . $i]['slaid'])) {
				$d6pdi = $config['interfaces']['opt' . $i]['slaid'];
			} else {
				$d6pdi = $p;
			}
			if (isset($config['interfaces']['opt' . $i]['slalen'])) {
				$d6pdl = $config['interfaces']['opt' . $i]['slalen'];
			} else {
				$d6pdl = 16;
			}
			$d6opt .= <<<EOD
		prefix-interface {$config['interfaces']['opt' . $i]['if']} {
			sla-id {$d6pdi};
			sla-len {$d6pdl};
		};

EOD;
			$p++;
		}
	}

	$dhcp6cconf = "interface {$wanif} {\n" . $d6wans . $d6wanm . "};\n" . $d6pds . $d6lan . $d6opt . $d6pde ;
 	$dhcp6cconf .= <<<EOD
id-assoc na 0 {
};
EOD;
	
	fwrite($fd, $dhcp6cconf);
	fclose($fd);

	/* fire up dhcp6c */
	$wanif = get_real_wan_interface();
	mwexec("/usr/local/sbin/dhcp6c -c {$g['varetc_path']}/dhcp6c.conf -p {$g['varrun_path']}/dhcp6c.pid {$wanif}" );

	return 0;

}

function services_dhcp6s_configure() {
	global $config, $g;
	
	/* kill any running dhcp6s */
	$dircont = opendir($g['varrun_path']);
	while ($file = readdir($dircont)) {
		if (preg_match("/dhcp6s/",$file)) killbypid("{$g['varrun_path']}/$file");
	}
	closedir($dircont);

	killbypid("{$g['varrun_path']}/dhcp6s.pid");
	if (!file_exists("{$g['varrun_path']}/dhcp6sctlkey"))  mwexec("touch {$g['varrun_path']}/dhcp6sctlkey");
	
	$syscfg = $config['system'];
	$dhcp6scfg = $config['dhcpd'];
	
	/* DHCPv6 enabled on any interfaces? */
	$dhcp6senable = false;
	foreach ($dhcp6scfg as $dhcpif => $dhcpifconf) {
		if (isset($dhcpifconf['v6enable']) && (($dhcpif == "lan") || (isset($config['interfaces'][$dhcpif]['ipaddr6']) && $config['interfaces'][$dhcpif]['if'] && (!$config['interfaces'][$dhcpif]['bridge']))))
			$dhcp6senable = true;
	}
	
	if (!$dhcp6senable)
		return 0;
	
	if ($g['booting'])
		echo "Starting DHCPv6 service... ";
	else
		sleep(1);

	$dhcp6sifs = array();
	foreach ($dhcp6scfg as $dhcpif => $dhcpifconf) {
		$ifcfg = $config['interfaces'][$dhcpif];
		
		/* write dhcp6s.conf */
		$fd = fopen("{$g['varetc_path']}/dhcp6s.{$ifcfg['if']}.conf", "w");
		if (!$fd) {
			printf("Error: cannot open dhcp6s.conf in services_dhcp6s_configure().\n");
			return 1;
		}
		$dhcp6sconf = <<<EOD
	
option domain-name "{$syscfg['domain']}";

EOD;
		if (!isset($dhcpifconf['v6enable']))
			continue;
		$v6subnet = gen_subnet6($ifcfg['ipaddr6'], $ifcfg['subnet6']);
		$dnscfg = "";
		unset($ifconfiginfo);
		exec("/sbin/ifconfig " . $ifcfg['if'], $ifconfiginfo);
		$ifmacaddr = "01:01:01:01:01:01";
		foreach ($ifconfiginfo as $ici) {	
			if (preg_match("/ether (\S+)/", $ici, $matches)) {
				$ifmacaddr = $matches[1];
			} 
		}
			
		if (is_array($dhcpifconf['dnsserver']) && ($dhcpifconf['dnsserver'][0])) {
			list($dnsconfig['dns1'],$dnsconfig['dns2'],$dnsconfig['dns3']) = $dhcpifconf['dnsserver'];
			if (is_ipaddr6($dnsconfig['dns1']))	$dnscfg .= "option domain-name-servers " . $dnsconfig['dns1'] . ";\n";
			if (is_ipaddr6($dnsconfig['dns2']))	$dnscfg .= "option domain-name-servers " . $dnsconfig['dns2'] . ";\n";
			if (is_ipaddr6($dnsconfig['dns3']))	$dnscfg .= "option domain-name-servers " . $dnsconfig['dns3'] . ";\n";
		} else if (isset($config['dnsmasq']['enable'])) {
			$dnscfg .= "option domain-name-servers " . $ifcfg['ipaddr6'] . ";\n";
		} else if (is_array($syscfg['dnsserver']) && ($syscfg['dnsserver'][0])) {
			list($dnsconfig['dns1'],$dnsconfig['dns2'],$dnsconfig['dns3']) = $syscfg['dnsserver'];
			if (is_ipaddr6($dnsconfig['dns1']))	$dnscfg .= "option domain-name-servers " . $dnsconfig['dns1'] . ";\n";
			if (is_ipaddr6($dnsconfig['dns2']))	$dnscfg .= "option domain-name-servers " . $dnsconfig['dns2'] . ";\n";
			if (is_ipaddr6($dnsconfig['dns3']))	$dnscfg .= "option domain-name-servers " . $dnsconfig['dns3'] . ";\n";
		}
		$dhcp6sconf .= <<<EOD
$dnscfg

interface {$ifcfg['if']} {
	preference 255;
	address-pool pool{$ifcfg['if']} {$dhcpifconf['v6defaultleasetime']} {$dhcpifconf['v6maxleasetime']};
};

pool pool{$ifcfg['if']} {
        range {$dhcpifconf['v6range']['from']} to {$dhcpifconf['v6range']['to']} ;
};

host m0n0wall {
        duid {$ifmacaddr};
        address {$ifcfg['ipaddr6']} infinity;
};

EOD;
		/* add static mappings */
		if (is_array($dhcpifconf['staticmap'])) {
			$i = 0;
			foreach ($dhcpifconf['staticmap'] as $sm) {
				if (is_ipaddr6($sm['ipaddr'])){
					$dhcp6sconf .= <<<EOD
host reserved{$i} {
        duid {$sm['mac']};
        address {$sm['ipaddr']} {$dhcpifconf['v6defaultleasetime']};
};

EOD;
					$i++;
				}
			}
		}
			
		$dhcp6sifs[] = $ifcfg['if'];
		fwrite($fd, $dhcp6sconf);
		fclose($fd);
	}
	
	/* fire up dhcp6s for each if */
	$i = 64705;
	foreach ($dhcp6sifs as $dhcp6sif) {
		mwexec("/usr/local/sbin/dhcp6s -c {$g['varetc_path']}/dhcp6s.{$dhcp6sif}.conf -k {$g['varrun_path']}/dhcp6sctlkey -p {$i} -P {$g['varrun_path']}/dhcp6s.{$dhcp6sif}.pid {$dhcp6sif}" );
		$i++;
	}
		
	if (!$g['booting']) {
		filter_configure();
	} else
		echo "done\n";
	
	return 0;
}

function services_dhcrelay_configure() {
	global $config, $g;
	
	/* kill any running dhcrelay */
	killbypid("{$g['varrun_path']}/dhcrelay.pid");
	
	$dhcrelaycfg = $config['dhcrelay'];
	
	/* DHCPRelay enabled on any interfaces? */
	$dhcrelayenable = false;
	
	if (is_array($dhcrelaycfg)) {
		foreach ($dhcrelaycfg as $dhcrelayif => $dhcrelayifconf) {
			if (isset($dhcrelayifconf['enable']) &&
				(($dhcrelayif == "lan") ||
				(isset($config['interfaces'][$dhcrelayif]['enable']) &&
				$config['interfaces'][$dhcrelayif]['if'] && (!$config['interfaces'][$dhcrelayif]['bridge'])))) {
				
				$dhcrelayenable = true;
				break;
			}
		}
	}
	
	if (!$dhcrelayenable)
		return 0;
	
	if ($g['booting'])
		echo "Starting DHCP relay service... ";
	else
		sleep(1);
	
	$dhcrelayifs = array();
	foreach ($dhcrelaycfg as $dhcrelayif => $dhcrelayifconf) {
		
		$ifcfg = $config['interfaces'][$dhcrelayif];
		
		if (!isset($dhcrelayifconf['enable']) ||
			(($dhcrelayif != "lan") &&
			(!isset($ifcfg['enable']) || !$ifcfg['if'] || $ifcfg['bridge'])))
			continue;
			
		$dhcrelayifs[] = $ifcfg['if'];
	}

	/* In order for the relay to work, it needs to be active on the 
	   interface in which the destination server sits */
	foreach ($config['interfaces'] as $ifname) {
		$subnet = $ifname['ipaddr'] . "/" . $ifname['subnet'];
		if (ip_in_subnet($dhcrelaycfg['server'],$subnet)) 
			$destif = $ifname['if'];	
	}
	
	if (!isset($destif)) 
		$destif = $config['interfaces']['wan']['if'];
	
	$dhcrelayifs[] = $destif;
	$dhcrelayifs = array_unique($dhcrelayifs);

	/* fire up dhcrelay */
	$cmd = "/usr/local/sbin/dhcrelay -i " .  join(" -i ", $dhcrelayifs);

	if (isset($dhcrelaycfg['agentoption']))	
		$cmd .=  " -a -m replace";

	$cmd .= " {$dhcrelaycfg['server']}";
	mwexec($cmd);
		
	if (!$g['booting']) {
		filter_configure();
	} else
		echo "done\n";
	
	return 0;
}

/* SUPERSEDED by dyndns.inc: services_dyndns_reset() now sends the update over
   HTTPS from PHP instead of writing a config for ez-ipupdate,
   whose last release was 2002 and whose provider list is dead. */

/* SUPERSEDED by dyndns.inc: services_dyndns_configure() now sends the update over
   HTTPS from PHP instead of writing a config for ez-ipupdate,
   whose last release was 2002 and whose provider list is dead. */

function services_dnsmasq_configure() {
	global $config, $g;

	/* kill any running dnsmasq */
	sigkillbypid("{$g['varrun_path']}/dnsmasq.pid", "TERM");

	/* dnsmasq is the DHCP server as well as the DNS forwarder, so it has to
	   run when EITHER is wanted. Its DHCP half is a separate file, generated
	   by dhcp_dnsmasq.inc from the same $config['dhcpd'] the webGUI has
	   always written, and included from dnsmasq.conf below. It is written
	   here, before the daemon starts, because dnsmasq refuses to start over
	   a conf-file it cannot open and rc.bootup reaches this function before
	   services_dhcpd_configure(). Until 2026-09-23 nothing included that
	   file at all, and DHCP was silently dead in every build. */
	$dns_on   = isset($config['dnsmasq']['enable']);
	$dhcpfile = "{$g['varetc_path']}/dnsmasq-dhcp.conf";
	file_put_contents($dhcpfile, dhcp_dnsmasq_config_generate());
	$dhcp_on  = count(dhcp_dnsmasq_enabled_interfaces()) > 0;

	if ($dns_on || $dhcp_on) {

		if ($g['booting']) {
			if ($dns_on && $dhcp_on)
				echo "Starting DNS forwarder and DHCP server... ";
			else if ($dns_on)
				echo "Starting DNS forwarder... ";
			else
				echo "Starting DHCP server... ";
		} else
			sleep(1);

		/* generate hosts file */
		system_hosts_generate();

		/* generate dnsmasq.conf */
		$fd = fopen("{$g['varetc_path']}/dnsmasq.conf", "w");
		if (!$fd) {
			printf("Error: cannot open dnsmasq.conf in services_dnsmasq_configure().\n");
			return 1;
		}
		$dnsmasqconf = "edns-packet-max=4096\n";

		/* DHCP only: no DNS listener at all */
		if (!$dns_on)
			$dnsmasqconf .= "port=0\n";

		/* the DHCP half -- see dhcp_dnsmasq.inc */
		$dnsmasqconf .= "conf-file={$dhcpfile}\n";
		if ($dhcp_on)
			$dnsmasqconf .= "dhcp-leasefile=" . dhcp_dnsmasq_leasefile() . "\n";

		/* "Register DHCP leases in DNS forwarder". With ISC dhcpd this meant
		   pointing dnsmasq at ISC's lease file. dnsmasq hands out the leases
		   itself now and always knows the names; the checkbox adds the
		   system domain so they resolve as FQDNs as well as bare names. */
		if (isset($config['dnsmasq']['regdhcp']) && !empty($config['system']['domain']))
			$dnsmasqconf .= "domain={$config['system']['domain']}\nexpand-hosts\n";

		$dnsmasqcfg = $config['dnsmasq'];
		if (isset($dnsmasqcfg['hosts']) && is_array($dnsmasqcfg['hosts'])) {
			foreach ($dnsmasqcfg['hosts'] as $host) {
				if (!is_array($host))
					continue;
				if (!empty($host['host']) && $host['host'] == '*' &&
				    !empty($host['domain']) && !empty($host['ip'])) {
					$dnsmasqconf .= "address=/{$host['domain']}/{$host['ip']}\n";
				}
				if (!empty($host['aliases'])) {
					$aliases = explode(' ', $host['aliases']);
					foreach ($aliases as $alias) {
						$dnsmasqconf .= "cname={$alias},{$host['host']}\n";
						$dnsmasqconf .= "cname={$alias}.{$host['domain']}," .
								"{$host['host']}.{$host['domain']}\n";
					}
				}
				if (isset($host['mx'])) {
					$dnsmasqconf .=	"mx-host={$host['domain']}," .
									"{$host['host']}.{$host['domain']}\n";
				}
			}
		}

		if (isset($config['dnsmasq']['allservers'])) {
			$dnsmasqconf .= "all-servers\n";
		}

		if (isset($config['dnsmasq']['strictorder'])) {
			$dnsmasqconf .= "strict-order\n";
		}

		if (isset($config['dnsmasq']['domainoverrides']) && is_array($config['dnsmasq']['domainoverrides'])) {
			foreach($config['dnsmasq']['domainoverrides'] as $override) {
				$dnsmasqconf .= "server=/{$override['domain']}/{$override['ip']}\n";
			}
		}

		if (isset($config['dnsmasq']['stoprebind'])) {
			$dnsmasqconf .= "stop-dns-rebind\n";
		}
		if (isset($config['dnsmasq']['log'])) {
			$dnsmasqconf .= "log-queries\n";
		}

		fwrite($fd, $dnsmasqconf);
		fclose($fd);

		/* run dnsmasq */
		mwexec("/usr/local/sbin/dnsmasq -C {$g['varetc_path']}/dnsmasq.conf");

		if ($g['booting'])
			echo "done\n";
	}

	/* The original ended here by restarting dhcpd, because ISC dhcpd was a
	   separate daemon that had to be bounced after a DNS change. dnsmasq now
	   IS the DHCP server and services_dhcpd_configure() delegates to this
	   very function -- calling back from here was infinite mutual recursion,
	   paced at exactly 1 Hz by the sleep(1) above. Boot never saw it
	   ($g['booting'] skips this block); console option 2 and every GUI save
	   did. filter_configure() stays: the rule set depends on which
	   interfaces serve DHCP and whether the forwarder is on. */
	if (!$g['booting'])
		filter_configure();

	return 0;
}

function services_snmpd_configure() {
	global $config, $g;

	/* kill any running snmpd */
	sigkillbypid("{$g['varrun_path']}/snmpd.pid", "TERM");

	if (isset($config['snmpd']['enable'])) {
	
		if ($g['booting'])
			echo "Starting SNMP agent... ";

		/* generate snmpd.conf */
		$fd = fopen("{$g['varetc_path']}/snmpd.conf", "w");
		if (!$fd) {
			printf("Error: cannot open snmpd.conf in services_snmpd_configure().\n");
			return 1;
		}
		
		$version = chop(file_get_contents("{$g['etc_path']}/version"));
		$specplatform = system_identify_specific_platform();
		$sysDescr = "m0n0wall " . php_uname("n") . " " . $version . " " .
			$specplatform['name'] . " " . php_uname("s") . " " . php_uname("r") .
			" " . php_uname("m");
		
		/* net-snmp replaces ucd-snmp, whose last release was 2002. It
		   inherited the directive names, so most of this is unchanged, with
		   two differences that matter:

		     rocommunity   ucd-snmp accepted a quoted string; net-snmp parses
		                   "rocommunity COMMUNITY [SOURCE [OID]]" and treats
		                   the quotes as part of the community name -- so the
		                   community silently becomes the wrong string and
		                   every poll is rejected.
		     agentaddress  ucd-snmp wrote "udp:161@ADDR"; net-snmp wants
		                   "udp:ADDR:161". The old form is not an error, it
		                   just does not bind where you asked. */
		$community = preg_replace('/[^A-Za-z0-9_.-]/', '',
		                          $config['snmpd']['rocommunity']);
		$snmpdconf = <<<EOD
sysDescr "$sysDescr"
sysLocation "{$config['snmpd']['syslocation']}"
sysContact "{$config['snmpd']['syscontact']}"
rocommunity {$community}

EOD;

		if (isset($config['snmpd']['bindlan'])) {
			$snmpdconf .= "agentaddress udp:{$config['interfaces']['lan']['ipaddr']}:161\n";
		} else {
			$snmpdconf .= "agentaddress udp:161\n";
		}

		fwrite($fd, $snmpdconf);
		fclose($fd);

		/* run snmpd */
		/* net-snmp's pidfile flag is lowercase -p; -P means something else
		   entirely (which MIB modules to load). With -P the daemon starts,
		   writes no pidfile, and killbypid() can never stop it again. */
		mwexec("/usr/local/sbin/snmpd -c {$g['varetc_path']}/snmpd.conf" .
			" -p {$g['varrun_path']}/snmpd.pid");

		if ($g['booting'])
			echo "done\n";
	}

	return 0;
}

function services_proxyarp_configure() {
	global $config, $g;

	/* kill any running choparp */
	killbyname("choparp");
	
	if (is_array($config['proxyarp']) && count($config['proxyarp'])) {
		
		$paa = array();
		
		/* group by interface */
		foreach ($config['proxyarp']['proxyarpnet'] as $paent) {
			if ($paent['interface'])
				$if = $paent['interface'];
			else
				$if = "wan";
			
			if (!is_array($paa[$if]))
				$paa[$if] = array();
			
			$paa[$if][] = $paent;
		} 
	
		foreach ($paa as $paif => $paents) {
			if ($paif == "wan" && !(is_ipaddr($config['interfaces']['wan']['ipaddr']) ||
					($config['interfaces']['wan']['ipaddr'] == "dhcp")))
				continue;
			
			$args = $config['interfaces'][$paif]['if'] . " auto";
		
			foreach ($paents as $paent) {
				if (isset($paent['network']))
					$args .= " " . escapeshellarg($paent['network']);
				else if (isset($paent['range']))
					$args .= " " . escapeshellarg($paent['range']['from'] . "-" . 
						$paent['range']['to']);
			}
			
			mwexec_bg("/usr/local/sbin/choparp " . $args);
		}
	}
}

function services_dnsupdate_process() {
	global $config, $g;
	
	/* Dynamic DNS updating active? */
	if (isset($config['dnsupdate']['enable'])) {
		
		$wanip = get_current_wan_address();
		
		if ($wanip) {
				
			$keyname = $config['dnsupdate']['keyname'];
			/* trailing dot */
			if (substr($keyname, -1) != ".")
				$keyname .= ".";
			
			$hostname = $config['dnsupdate']['host'];
			/* trailing dot */
			if (substr($hostname, -1) != ".")
				$hostname .= ".";
			
			/* write private key file
			   this is dumb - public and private keys are the same for HMAC-MD5,
			   but nsupdate insists on having both */
			$fd = fopen("{$g['varetc_path']}/K{$keyname}+157+00000.private", "w");
			$privkey .= <<<EOD
Private-key-format: v1.2
Algorithm: 157 (HMAC)
Key: {$config['dnsupdate']['keydata']}

EOD;
			fwrite($fd, $privkey);
			fclose($fd);
			
			/* write public key file */
			if ($config['dnsupdate']['keytype'] == "host") {
				$flags = 513;
				$proto = 3;
			} else if ($config['dnsupdate']['keytype'] == "user") {
				$flags = 0;
				$proto = 2;
			} else {
				$flags = 257;
				$proto = 3;
			}
			
			$fd = fopen("{$g['varetc_path']}/K{$keyname}+157+00000.key", "w");
			fwrite($fd, "{$keyname} IN KEY {$flags} {$proto} 157 {$config['dnsupdate']['keydata']}\n");
			fclose($fd);
			
			/* generate update instructions */
			$upinst =  "update delete {$hostname} A\n";
			$upinst .= "update add {$hostname} {$config['dnsupdate']['ttl']} A {$wanip}\n";
			$upinst .= "\n";	/* mind that trailing newline! */
			
			$fd = fopen("{$g['varetc_path']}/nsupdatecmds", "w");
			fwrite($fd, $upinst);
			fclose($fd);
			
			/* invoke nsupdate */
			$cmd = "/usr/bin/nsupdate -k {$g['varetc_path']}/K{$keyname}+157+00000.private";
			if (isset($config['dnsupdate']['usetcp']))
				$cmd .= " -v";
			$cmd .= " {$g['varetc_path']}/nsupdatecmds";
			
			mwexec_bg($cmd);
		}
	}
	
	return 0;
}

function services_wol_send($ipaddr, $subnet, $mac) {
	/* determine broadcast address */
	$bcip = gen_subnet_max($ipaddr, $subnet);
	
	mwexec("/usr/local/bin/wol -i {$bcip} {$mac}");
}

function services_croen_configure() {
	global $config, $g;

	// Default config
	croen_set_default_config();
	// Kill running croen daemon
	killbypid("{$g['varrun_path']}/croen.pid");
	// Kill running minicron daemon
	killbypid("{$g['varrun_path']}/croen_wait.pid");
	// Make sure there is no croen.tmp file present
	if (file_exists($g['tmp_path'].'/croen.tmp')) {
		unlink($g['tmp_path'].'/croen.tmp');
	}
	
	if (isset($config['croen']['enable'])) {
		// Print start message if booting
		if ($g['booting']) {
			echo "Starting scheduler... ";
		}
		
		// Set croen config vars
		$scheduler_path = '/etc/croen_jobs/scheduler';
		$conf_vars = Array(
			'pidfile' 		=> $g['varrun_path'].'/croen.pid',
			'tmpfile' 		=> $g['tmp_path'].'/croen.tmp',
			'call'			=> '/usr/local/bin/php '.$scheduler_path,
			'interval'		=> (isset($config['croen']['interval']) ? $config['croen']['interval'] * 60 : 600));
		
		// Check for a (hopefully) valid time
		if (time() > mktime(0, 0, 0, 1, 1, 2012)) {
			// Open config file
			$fd = fopen($g['varetc_path'].'/croen.conf', 'w');
			// Write config settings
			$conf_first = TRUE;
			foreach ($conf_vars AS $conf_name => $conf_var) {
				fwrite($fd, (!$conf_first ? "\n" : "").$conf_name." = ".$conf_var);
				$conf_first = FALSE;
			}
			// Write jobs
			foreach ($config['croen']['jobset'] AS $jobset_id => $jobset) {
				// Ignore disabled jobsets
				if (!isset($jobset['disabled'])) {
					fwrite($fd, "\njob = ".
						$jobset_id." ".$jobset['repeat'].(isset($jobset['time']) ? " ".$jobset['time'] : "").
						(isset($jobset['date']) ? " ".$jobset['date'] :
						(isset($jobset['weekday']) ? " ".$jobset['weekday'] :
						(isset($jobset['day']) ? " ".$jobset['day'] :
						(isset($jobset['minute']) ? " ".$jobset['minute'] : ""))))
					);
				}
			}
			// Close config file
			fclose($fd);
			
			// Start croen daemon
			mwexec("/usr/local/bin/croen");
		} else {
			// If time is invalid sleep for 60 seconds and try again (minicron)
			mwexec("/usr/local/bin/minicron 60 ".$g['varrun_path']."/croen_wait.pid ".$scheduler_path);
		}
		
		// Print end message if booting
		if ($g['booting']) {
			echo "done\n";
		}
	}
	
	return 0;
}

?>
