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

require_once("IPv6.php");

/* kill a process by pid file */
function killbypid($pidfile) {
	sigkillbypid($pidfile, "TERM");
	unlink_if_exists($pidfile);
}

/* sigkill a process by pid file */
function sigkillbypid($pidfile, $sig) {
	if (file_exists($pidfile)) {
		mwexec("/bin/kill -s $sig `/bin/cat " . $pidfile . "`");
	}
}

/* kill a process by name */
function killbyname($procname) {
	return mwexec("/usr/bin/killall " . escapeshellarg($procname));
}

/* kill a process by name */
function sigkillbyname($procname, $sig) {
	return mwexec("/usr/bin/killall -{$sig} " . escapeshellarg($procname));
}

/* return the subnet address given a host address and a subnet bit count */
function gen_subnet($ipaddr, $bits) {
	if (!is_ipaddr($ipaddr) || !is_numeric($bits))
		return "";
	
	return long2ip(ip2long($ipaddr) & gen_subnet_mask_long($bits));
}

/* return the subnet address given a host address and a subnet bit count, IPv6 variant */
function gen_subnet6($ipaddr, $bits) {
	if (!is_ipaddr6($ipaddr) || !is_numeric($bits))
		return '';
	
	return Net_IPv6::getNetmask($ipaddr, $bits);
}
/* return the broadcast address given a host address and a subnet bit count, IPv6 variant */
function gen_subnet_max6($ipaddr, $bits) {
	if (!is_ipaddr6($ipaddr) || !is_numeric($bits))
		return '';
	$ipasbin = Net_IPv6::_ip2Bin(Net_IPv6::removeNetmaskSpec($ipaddr));
	$binBcast = substr($ipasbin,0,$bits) . str_repeat('1',128 - $bits);
	
	return  Net_IPv6::_Bin2ip($binBcast);
}
/* return the highest (broadcast) address in the subnet given a host address and a subnet bit count */
function gen_subnet_max($ipaddr, $bits) {
	if (!is_ipaddr($ipaddr) || !is_numeric($bits))
		return "";
	
	return long2ip(ip2long($ipaddr) | ~gen_subnet_mask_long($bits));
}

/* returns a subnet mask (long given a bit count) */
function gen_subnet_mask_long($bits) {
	$sm = 0;
	for ($i = 0; $i < $bits; $i++) {
		$sm >>= 1;
		$sm |= 0x80000000;
	}
	return $sm;
}

/* same as above but returns a string */
function gen_subnet_mask($bits) {
	return long2ip(gen_subnet_mask_long($bits));
}

function is_numericint($arg) {
	return (preg_match("/[^0-9]/", $arg) ? false : true);
}

/* returns true if $ipaddr is a valid IPv4 or IPv6 address */
function is_ipaddr4or6($ipaddr) {
	if (is_ipaddr($ipaddr)) 
		return true;
	else if (ipv6enabled()) 
		return is_ipaddr6($ipaddr);
	else 
		return false;	
}

/* returns true if $ipaddr is a valid dotted IPv4 address */
function is_ipaddr($ipaddr) {
	if (!is_string($ipaddr))
		return false;
		
	$ip_long = ip2long($ipaddr);
	$ip_reverse = long2ip($ip_long);
 
	if ($ipaddr == $ip_reverse)
		return true;
	else
		return false;
}

/* returns true if $ipaddr is a valid IPv6 address with not prefix */
function is_ipaddr6($ipaddr) {
	if (!Net_IPv6::getNetmaskSpec($ipaddr)) {
		return Net_IPv6::checkIPv6($ipaddr);
	} else {
	return false;
	}
}

function is_ipaddr6andprefix($ipaddr) {
	if (Net_IPv6::getNetmaskSpec($ipaddr)) {
		return Net_IPv6::checkIPv6($ipaddr);
	} else {
	return false;
	}
}

/* returns MTU of the interface */
function get_interface_mtu($interface) {
       $mtu = null;
       $p = @popen("/sbin/ifconfig " . escapeshellarg($interface), "r");
       if ($p === false)
               return null;
       while (!feof($p)) {
               $line = fgets($p);
               if (preg_match("/mtu (\d+)/", $line, $matches)) {
                       $mtu = $matches[1];
                       break;
               }
       }
       pclose($p);
       
       return $mtu;
}

function isInNetmask6($ip, $netmask, $bits=null) {
	return Net_IPv6::isInNetmask($ip, $netmask, $bits);
}

function ipv6Uncompress($ip) {
	return Net_IPv6::Uncompress($ip);
}

/* returns true if $ipaddr is a valid dotted IPv4 address or an alias thereof */
function is_ipaddroralias($ipaddr) {
	
	global $aliastable;
	
	if (isset($aliastable[$ipaddr]) && is_ipaddr($aliastable[$ipaddr]))
		return true;
	else
		return is_ipaddr($ipaddr);
}

/* returns true if $ipaddr is a valid dotted IPv4 address or any alias */
function is_ipaddroranyalias($ipaddr) {
	
	global $aliastable;
	
	if (isset($aliastable[$ipaddr]))
		return true;
	else
		return is_ipaddr($ipaddr);
}

/* returns true if $subnet is a valid subnet in CIDR format */
function is_subnet($subnet) {
	if (!is_string($subnet))
		return false;
		
	/* A bare address has no '/', so list() would read an undefined index.
	   Harmless in PHP 4, a warning in PHP 8 -- and these validators are fed
	   arbitrary text straight from the webGUI forms. */
	$parts = explode('/', $subnet);
	if (count($parts) != 2)
		return false;
	list($hp,$np) = $parts;
	
	if (!is_ipaddr($hp))
		return false;
	
	if (!is_numeric($np) || ($np < 1) || ($np > 32))
		return false;
		
	return true;
}

/* returns true if $subnet is a valid IPv6 subnet in CIDR format */
function is_subnet6($subnet) {
	if (!is_string($subnet))
		return false;
		
	/* A bare address has no '/', so list() would read an undefined index.
	   Harmless in PHP 4, a warning in PHP 8 -- and these validators are fed
	   arbitrary text straight from the webGUI forms. */
	$parts = explode('/', $subnet);
	if (count($parts) != 2)
		return false;
	list($hp,$np) = $parts;
	
	if (!is_ipaddr6($hp))
		return false;
	
	if (!is_numeric($np) || ($np < 1) || ($np > 128))
		return false;
		
	return true;
}

/* returns true if $subnet is a valid subnet in CIDR format or an alias thereof */
function is_subnetoralias($subnet) {
	
	global $aliastable;
	
	if (isset($aliastable[$subnet]) && is_subnet($aliastable[$subnet]))
		return true;
	else
		return is_subnet($subnet);
}

/* returns true if $hostname is a valid hostname */
function is_hostname($hostname) {
	if (!is_string($hostname))
		return false;
		
	if (preg_match("/^[a-z0-9\-]+$/i", $hostname))
		return true;
	else
		return false;
}

/* returns true if $domain is a valid domain name */
/* NOTE for the PHP 8 sweep: this is NOT null-equivalent. is_domain(null) is
   false (the is_string guard), but is_domain("") is TRUE, because the regex
   below matches the empty string. Callers guarding a possibly-missing value
   must use "?? null", never "?? ''", or the validation silently passes. */
function is_domain($domain) {
	if (!is_string($domain))
		return false;
		
	if (preg_match("/^([a-z0-9\-]+\.?)*$/i", $domain))
		return true;
	else
		return false;
}

/* returns true if $uname is a valid DynDNS username */
function is_dyndns_username($uname) {
	if (!is_string($uname))
		return false;
		
	if (preg_match("/[^a-z0-9\-.@_]/i", $uname))
		return false;
	else
		return true;
}

/* returns true if $macaddr is a valid MAC address */
function is_macaddr($macaddr) {
	if (!is_string($macaddr))
		return false;
		
	$maca = explode(":", $macaddr);
	if (count($maca) != 6)
		return false;
	
	foreach ($maca as $macel) {
		if (($macel === "") || (strlen($macel) > 2))
			return false;
		if (preg_match("/[^0-9a-f]/i", $macel))
			return false;
	}
	
	return true;
}

/* returns true if $duid is a valid DUID address */
/* RFC3315 says that a 'servers MUST NOT restrict DUIDs to the types in this Document' which means the length could be anything, though a mac length is a good min*/
function is_duid($duid) {
	if (!is_string($duid))
		return false;
		
	$duida = explode(":", $duid);
	if (count($duida) < 7)
		return false;
	
	foreach ($duida as $duidl) {
		if (($duidl === "") || (strlen($duidl) > 2))
			return false;
		if (preg_match("/[^0-9a-f]/i", $duidl))
			return false;
	}
	
	return true;
}

/* returns true if $name is a valid name for an alias */
function is_validaliasname($name) {
	if (!preg_match("/[^a-zA-Z0-9-]/", $name))
		return true;
	else
		return false;
}

/* returns true if $port is a valid TCP/UDP port */
function is_port($port) {
	if (!is_numericint($port))
		return false;
		
	if (($port < 1) || ($port > 65535))
		return false;
	else
		return true;
}

/* returns a list of interfaces with MAC addresses
   (skips VLAN and other virtual interfaces) */
function get_interface_list($ethernet = true, $wireless = true, $serial = true) {
	
	global $g;
	
	/* build interface list with netstat */
	exec("/usr/bin/netstat -inW -f link", $linkinfo);
	array_shift($linkinfo);
	
	/* get dmesg output in order to parse interface driver names from it */
	$dmesg = system_get_dmesg_boot();
	
	$iflist = array();
	
	foreach ($linkinfo as $link) {
		$alink = preg_split("/\s+/", $link);
		$ifname = chop($alink[0]);
		
		if (substr($ifname, -1) == "*")
			$ifname = substr($ifname, 0, strlen($ifname) - 1);
		
		/* pflog/pfsync added: pf creates them, they carry no traffic of their own
		   and they are not valid VLAN parents, but they were offered as assignable
		   ports and as VLAN parent interfaces. */
		if (preg_match("/^(ppp|sl|gif|faith|lo|ng|ngwan|vlan|wlan|tun|enc|ipfw|bridge|usbus|pflog|pfsync)\d/", $ifname))
			continue;
		
		if (preg_match($g['wireless_regex'], $ifname)) {
			/* this is a wireless interface - should we include it? */
			if (!$wireless)
				continue;
		} else {
			/* this is not a wireless interface (so we assume it's Ethernet) */
			if (!$ethernet)
				continue;
		}
			
		$iflist[$ifname] = array();
		
		$iflist[$ifname]['mac'] = chop($alink[3]);
		$iflist[$ifname]['up'] = false;
		
		/* find out if the link on this interface is up */
		unset($ifinfo);
		exec("/sbin/ifconfig {$ifname}", $ifinfo);
		
		foreach ($ifinfo as $ifil) {
			if (preg_match("/status: (.*)$/", $ifil, $matches)) {
				if ($matches[1] == "active")
					$iflist[$ifname]['up'] = true;
				break;
			}
		}
		
		/* try to figure out driver name */
		if (preg_match("/$ifname:\s+<(.+?)>/", $dmesg, $matches)) {
			/* truncate at 40 characters; some of these get really long
			   and mess up the CLI and webGUI display */
			$drvname = $matches[1];
			if (strlen($drvname) > 40)
				$drvname = substr($drvname, 0, 40) . "...";
			$iflist[$ifname]['drvname'] = $drvname;
		}
	}
	if ($serial) {
		exec("/bin/ls /dev/cuaU*", $modemports);
		
		foreach ($modemports as $uport) {
			if (preg_match("!/dev/cuaU(\d+).(\d+)$!", $uport)) {
				$iflist[$uport]['mac'] = 'N/A';
				$iflist[$uport]['up'] = false;
			}		
		}
	}
	return $iflist;
}

/* convert friendly interface name (WAN, OPTx, etc.) to real interface (fxp0, ng0, etc.) */
function convert_friendly_interface_to_real_interface_name($interface) {
	global $config, $g;
	if($config['interfaces'][$interface]['ipaddr'] == "pppoe" or $config['interfaces'][$interface]['ipaddr'] == "pptp" or $config['interfaces'][$interface]['ipaddr'] == "modem")
		return $g['pppoe_interface'];
	$lc_interface = strtolower($interface);
	if($lc_interface == "lan") return $config['interfaces']['lan']['if'];
	if($lc_interface == "wan") return $config['interfaces']['wan']['if'];
	$ifdescrs = array();
	for ($j = 1; isset($config['interfaces']['opt' . $j]); $j++)
		$ifdescrs['opt' . $j] = "opt" . $j;
	foreach ($ifdescrs as $ifdescr => $ifname) {
		if(strtolower($ifname) == $lc_interface)
	    return $config['interfaces'][$ifname]['if'];
		if(strtolower($config['interfaces'][$ifname]['descr']) == $lc_interface)
			return $config['interfaces'][$ifname]['if'];
   }
   return $interface;
}

/* wrapper for exec() */
/* Log a line to syslog, which syslog.conf routes to /var/log/system.log and,
   if configured, to the remote server. Called from dyndns.inc and
   interfaces.inc; it had never been defined, so every Dynamic DNS update
   path died with "Call to undefined function log_error()". */
function log_error($text) {
	openlog("m0n0wall", LOG_ODELAY, LOG_USER);
	syslog(LOG_ERR, $text);
	closelog();
	return true;
}

/* Hash a webGUI password for /var/run/htpasswd, which lighttpd's
   mod_authn_file reads and checks with crypt(3).

   crypt() with one argument has been an ArgumentCountError since PHP 8.0 --
   before that it generated a random salt itself. Every caller passed one
   argument, so changing a password from the GUI or from console option 3
   was fatal. SHA-512 ($6$) rather than the DES the old default produced:
   FreeBSD's libcrypt and lighttpd both accept it, and DES silently truncates
   the password to eight characters. */
function system_password_hash($password) {
	return crypt($password, '$6$' . substr(bin2hex(random_bytes(9)), 0, 16) . '$');
}

function mwexec($command) {

	global $g;
	
	if ($g['debug']) {
		if (!$_SERVER['REMOTE_ADDR'])
			echo "mwexec(): $command\n";
		passthru($command, $retval);
	} else {
		exec("$command > /dev/null 2>&1", $oarr, $retval);
	}
	
	return $retval; 
}

/* wrapper for exec() in background; returns PID of background process */
function mwexec_bg($command) {

	global $g;
	
	if ($g['debug']) {
		if (!$_SERVER['REMOTE_ADDR'])
			echo "mwexec_bg(): $command\n";
	}
	
	$pid = shell_exec("nohup $command > /dev/null 2>&1 & echo \$!");
	return $pid;
}

/* unlink a file, if it exists */
function unlink_if_exists($fn) {
	if (file_exists($fn))
		unlink($fn);
}

/* make a global alias table (for faster lookups) */
function alias_make_table() {
	
	global $config, $g, $aliastable;
	
	$aliastable = array();
	
	if (isset($config['aliases']['alias']) && is_array($config['aliases']['alias'])) {
		foreach ($config['aliases']['alias'] as $alias) {
			if ($alias['name'])
				$aliastable[$alias['name']] = $alias['address'];
		}
	}
}

/* check if an alias exists */
function is_alias($name) {
	
	global $aliastable;
	
	return isset($aliastable[$name]);
}

/* expand a host or network alias, if necessary */
function alias_expand($name) {
	
	global $aliastable;
	
	if (isset($aliastable[$name]))
		return $aliastable[$name];
	else if (is_ipaddr($name) || is_subnet($name) || is_ipaddr6($name) || is_subnet6($name))
		return $name;
	else
		return null;
}

/* expand a host alias, if necessary */
function alias_expand_host($name) {
	
	global $aliastable;
	
	if (isset($aliastable[$name]) && is_ipaddr($aliastable[$name]))
		return $aliastable[$name];
	else if (is_ipaddr($name))
		return $name;
	else
		return null;
}

/* expand a network alias, if necessary */
function alias_expand_net($name) {
	
	global $aliastable;
	
	if (isset($aliastable[$name]) && is_subnet($aliastable[$name]))
		return $aliastable[$name];
	else if (is_subnet($name))
		return $name;
	else
		return null;
}

/* find out whether two subnets overlap */
function check_subnets_overlap($subnet1, $bits1, $subnet2, $bits2) {

	if (!is_numeric($bits1))
		$bits1 = 32;
	if (!is_numeric($bits2))
		$bits2 = 32;

	if ($bits1 < $bits2)
		$relbits = $bits1;
	else
		$relbits = $bits2;
	
	$sn1 = gen_subnet_mask_long($relbits) & ip2long($subnet1);
	$sn2 = gen_subnet_mask_long($relbits) & ip2long($subnet2);
	
	if ($sn1 == $sn2)
		return true;
	else
		return false;
}

/* compare two IP addresses */
function ipcmp($a, $b) {
	if (ip2long($a) < ip2long($b))
		return -1;
	else if (ip2long($a) > ip2long($b))
		return 1;
	else
		return 0;
}

/* return true if $addr is in $subnet, false if not */
function ip_in_subnet($addr,$subnet) {
	list($ip, $mask) = explode('/', $subnet);
	$mask = 0xffffffff << (32 - $mask);
	return ((ip2long($addr) & $mask) == (ip2long($ip) & $mask));
}

/* verify (and remove) the digital signature on a file - returns 0 if OK */
function verify_digital_signature($fname) {

	global $g;

	return mwexec("/usr/local/bin/verifysig " .
		escapeshellarg("{$g['etc_path']}/pubkey.pem") . " " .
		escapeshellarg($fname));
}

/* obtain MAC address given an IP address by looking at the ARP table */
function arp_get_mac_by_ip($ip) {
	exec("/usr/sbin/arp -n {$ip}", $arpoutput);
	
	if ($arpoutput[0]) {
		$arpi = explode(" ", $arpoutput[0]);
		$macaddr = $arpi[3];
		if (is_macaddr($macaddr))
			return $macaddr;
		else
			return false;
	}
	
	return false;
}

/* obtain MAC address given an IP address by looking at the NDP table */
function ndp_get_mac_by_ip($ip) {
	exec("/usr/sbin/ndp -n {$ip}", $ndpoutput);
	
	if ($ndpoutput[1]) {
		$ndpi = explode(" ", preg_replace("/ +/", " ",$ndpoutput[1]));
		$macaddr =  $ndpi[1];
		if (is_macaddr($macaddr))
			return $macaddr;
		else
			return false;
	}
	
	return false;
}

function get_mac_by_ip($ip) {
	if (is_ipaddr($ip)) return arp_get_mac_by_ip($ip);
	if (is_ipaddr6($ip)) return ndp_get_mac_by_ip($ip);
}

function mac_format($clientmac) {
    $mac =explode(":", $clientmac);

    global $config;

    $mac_format = $config['captiveportal']['radmac_format'] ? $config['captiveportal']['radmac_format'] : false;

    switch($mac_format) {

        case 'singledash':
        return "$mac[0]$mac[1]$mac[2]-$mac[3]$mac[4]$mac[5]";

        case 'ietf':
        return "$mac[0]-$mac[1]-$mac[2]-$mac[3]-$mac[4]-$mac[5]";

        case 'cisco':
        return "$mac[0]$mac[1].$mac[2]$mac[3].$mac[4]$mac[5]";

        case 'unformatted':
        return "$mac[0]$mac[1]$mac[2]$mac[3]$mac[4]$mac[5]";

        default:
        return $clientmac;
    }
}

function resolve_retry($hostname, $retries = 5) {

	if (is_ipaddr($hostname))
		return $hostname;

	for ($i = 0; $i < $retries; $i++) {
		$ip = gethostbyname($hostname);
		
		if ($ip && $ip != $hostname) {
			/* success */
			return $ip;
		}
		
		sleep(1);
	}
	
	return false;
}

function subnet_size_to_cidr($size) {
	$cidr = 32;
	
	while ($size > 1) {
		$size /= 2;
		$cidr--;
	}
	
	return $cidr;
}

/* converts the given IPv4 address to a string of v6 hex nibbles ("xxxx:xxxx"),
   mostly for use in 6to4 calculations */
function convert_to_6to4_nibbles($ipaddr) {
	if (!is_ipaddr($ipaddr))
		return false;
	$octets = explode('.', $ipaddr);
	return sprintf('%02x%02x:%02x%02x',	$octets[0], $octets[1], $octets[2], $octets[3]);
}

/* Generate a self-signed 2048-bit SSL cert/key valid for 3 years, in PEM format.
 *
 * Returns false only if the clock is implausible, which is a real possibility on
 * a firewall that has not reached an NTP server yet: a certificate whose notBefore
 * is in the future is rejected by every client.
 *
 * Two things here were broken and both failed CLOSED, which is how they went
 * unnoticed -- the caller's message on failure is "your system's clock is not
 * set", so a firewall that fell back to the insecure shared default certificate
 * blamed the clock:
 *
 *   - the sanity check required "BEGIN RSA PRIVATE KEY" (PKCS#1), but
 *     openssl_pkey_export() on OpenSSL 3 writes PKCS#8 ("BEGIN PRIVATE KEY").
 *     So the check could never pass and this function ALWAYS returned false.
 *   - digest_alg was sha1. Every current browser rejects a SHA-1 signature, so
 *     even a certificate that had been generated would have been refused.
 *
 * The comment also claimed 1024-bit and 2 years while the code said 2048 and
 * 3*365 days.
 */
function generate_self_signed_cert($orgname, $cn) {
	global $g;
	
	/* Check local clock first - must be set to something after the release date
	   (subtract a day to avoid TZ problems with early adopters).
	   
	   Read defensively: file_get_contents() returns false if the file is
	   missing, and "" - 86400 is a TypeError in PHP 8 rather than 0 - 86400. */
	$btraw = @file_get_contents("{$g['etc_path']}/version.buildtime.unix");
	if ($btraw !== false && is_numeric(trim($btraw))) {
		$buildtime = (int) trim($btraw) - 86400;
		if (time() < $buildtime)
			return false;
	}
	
	$dn = array(
	    "organizationName" => $orgname,
	    "commonName" => $cn
	);

	$config = array(
		"digest_alg" => "sha256",
		"private_key_bits" => 2048
	);

	$privkey = openssl_pkey_new($config);
	if ($privkey === false)
		return false;
	$csr = openssl_csr_new($dn, $privkey, $config);
	if ($csr === false)
		return false;
	$sscert = openssl_csr_sign($csr, null, $privkey, 3*365, $config, time());
	if ($sscert === false)
		return false;

	$certout = $pkeyout = '';
	openssl_x509_export($sscert, $certout);
	openssl_pkey_export($privkey, $pkeyout);

	/* sanity check -- accepts whatever PEM private key OpenSSL gave us */
	if (strpos($certout, "BEGIN CERTIFICATE") !== false && is_pem_private_key($pkeyout))
		return array('cert' => $certout, 'key' => $pkeyout);
	else
		return false;
}

/* Does this look like a PEM private key we can actually use?
 *
 * One validator for every page that accepts one, because they had all grown the
 * same bug independently: a test for the literal string "BEGIN RSA PRIVATE KEY",
 * which is PKCS#1 only. Every current openssl writes PKCS#8 by default
 * ("BEGIN PRIVATE KEY") and an EC key says "BEGIN EC PRIVATE KEY", so a key
 * generated today was rejected by the GUI even though the OpenSSL 3 that
 * lighttpd and strongSwan link against reads all three.
 *
 * Encrypted keys are deliberately NOT accepted: lighttpd, charon and mpd5 are
 * started with no console, so nothing can prompt for the passphrase and the
 * daemon would simply fail to start. is_pem_encrypted_private_key() lets a
 * caller say so specifically instead of reporting "not valid".
 */
function is_pem_private_key($key) {
	if (!is_string($key) || $key === '')
		return false;
	if (is_pem_encrypted_private_key($key))
		return false;
	return preg_match('/-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/', $key) === 1
	    && preg_match('/-----END (RSA |EC |DSA )?PRIVATE KEY-----/', $key) === 1;
}

/* A passphrase-protected key, in either the PKCS#8 form or the older
 * PKCS#1-with-Proc-Type header that openssl still emits with -aes256. */
function is_pem_encrypted_private_key($key) {
	if (!is_string($key))
		return false;
	return strpos($key, 'ENCRYPTED PRIVATE KEY') !== false
	    || strpos($key, 'Proc-Type: 4,ENCRYPTED') !== false;
}

/* The optional interfaces that actually exist, as number => config key.
 *
 * Returns e.g. array(1 => 'opt1', 3 => 'opt3') -- ordered by number, and with
 * GAPS PRESERVED. Both halves are what callers need: the number for a display
 * label ("OPT3"), an ?index= link and the interfaces_optional_configure_if()
 * family, and the key for $config['interfaces'][...].
 *
 * Why this exists. Fifty-odd sites across thirty-two files each rolled their own
 *
 *     for ($i = 1; isset($config['interfaces']['opt' . $i]); $i++)
 *
 * which stops dead at the first missing number. That was survivable only because
 * interfaces_assign.php closes the hole on delete by shifting opt3 down to opt2
 * -- and THAT is the renumbering that silently misassigns everything referring to
 * an interface by name. $config['dhcpd']['opt1'] is not shifted with it, so the
 * DHCP range configured for the deleted interface starts serving whichever
 * interface moved into its place, and a firewall rule naming opt3 stops matching
 * anything because opt3 no longer exists.
 *
 * The fix is to stop renumbering, which makes optN a stable identifier for the
 * life of the interface and leaves every reference to it correct. This helper is
 * the prerequisite: with gaps tolerated everywhere, closing them is no longer
 * necessary. It also removes a latent bug of its own -- a hand-edited or
 * partially restored config with a hole already defeated every one of those
 * loops, including the in-use checks that guard a VLAN delete.
 *
 * Deliberately NOT cached: callers mutate $config['interfaces'] and then
 * re-enumerate.
 */
function opt_interfaces() {
	global $config;

	$out = array();
	if (!isset($config['interfaces']) || !is_array($config['interfaces']))
		return $out;

	foreach ($config['interfaces'] as $key => $ifcfg) {
		if (!is_array($ifcfg))
			continue;
		if (!preg_match('/^opt(\d+)$/', $key, $m))
			continue;
		$out[(int) $m[1]] = $key;
	}
	ksort($out, SORT_NUMERIC);

	return $out;
}

/* The next free optional interface number.
 *
 * With gaps preserved this is no longer "count + 1": it is the lowest number not
 * in use, so a delete-then-add reuses the freed slot rather than climbing for
 * ever. interfaces_assign.php already looked for the first free number this way;
 * this puts it in one place.
 */
function opt_next_free() {
	$used = opt_interfaces();
	for ($i = 1; $i < 1000; $i++)
		if (!isset($used[$i]))
			return $i;
	return 0;               /* absurd, and the caller should refuse */
}

/* Is this an OpenSSH private key? A common paste mistake, and worth naming:
 * the generic "does not appear to be valid" sends people looking for a
 * corruption they do not have. */
function is_openssh_private_key($key) {
	return is_string($key) && strpos($key, 'BEGIN OPENSSH PRIVATE KEY') !== false;
}

/* Is this a PEM X.509 CRL? */
function is_pem_crl($crl) {
	if (!is_string($crl) || $crl === '')
		return false;
	return strpos($crl, '-----BEGIN X509 CRL-----') !== false
	    && strpos($crl, '-----END X509 CRL-----') !== false;
}

/* Validate certificate and key material from a form.
 *
 * ONE entry point, because the pages that accept a certificate had already
 * drifted apart in both what they accept and what they say -- the
 * "BEGIN RSA PRIVATE KEY" test was copied into five of them independently, and
 * each produced its own wording for the same failure.
 *
 *   $cert    PEM certificate ('' when $want is 'key')
 *   $key     PEM private key ('' when $want is 'cert')
 *   $daemon  who will read it, for the passphrase message -- "The web server",
 *            "The captive portal", "charon"
 *   $want    'both' (default) | 'cert' | 'key'
 *
 * Returns an array of error strings, empty when the material is usable, so a
 * caller writes:
 *
 *   $input_errors = array_merge($input_errors, pem_validate_keypair($c, $k, 'charon'));
 *
 * The order of the checks is the part that matters: the ENCRYPTED test has to
 * come before the general one, because is_pem_private_key() deliberately
 * returns false for an encrypted key and would otherwise swallow the specific
 * message in the generic one.
 */
function pem_validate_keypair($cert, $key, $daemon = 'This service', $want = 'both') {
	$errors = array();

	if ($want != 'key') {
		if (!is_pem_certificate($cert))
			$errors[] = "This certificate does not appear to be valid. It should be " .
			    "PEM, beginning with \"-----BEGIN CERTIFICATE-----\".";
	}

	if ($want != 'cert') {
		if (is_pem_encrypted_private_key($key)) {
			$errors[] = "This key is passphrase-protected. {$daemon} is started " .
			    "without a console, so it cannot prompt for one -- decrypt the key " .
			    "first, with: openssl pkey -in key.pem -out key-decrypted.pem";
		} else if (is_openssh_private_key($key)) {
			$errors[] = "That is an OpenSSH private key, not a PEM one. Convert it " .
			    "with: ssh-keygen -p -m PEM -f key";
		} else if (!is_pem_private_key($key)) {
			$errors[] = "This key does not appear to be valid. It should be a PEM " .
			    "private key, beginning with \"-----BEGIN PRIVATE KEY-----\".";
		}
	}

	/* Do they belong together? A mismatched pair is accepted by every check
	   above and then fails at the daemon, where the error is much harder to
	   connect back to this form. Only asked when both look well-formed, and
	   skipped if openssl is unavailable rather than guessing. */
	if (!$errors && $want == 'both' && function_exists('openssl_x509_check_private_key')) {
		if (@openssl_x509_check_private_key($cert, $key) !== true)
			$errors[] = "This certificate and key do not match each other. Check that " .
			    "both came from the same keypair.";
	}

	return $errors;
}

/* Does this look like a PEM certificate? */
function is_pem_certificate($cert) {
	if (!is_string($cert) || $cert === '')
		return false;
	return strpos($cert, '-----BEGIN CERTIFICATE-----') !== false
	    && strpos($cert, '-----END CERTIFICATE-----') !== false;
}

/* check whether a DHCP client range is valid on an interface with a given IP address and subnet mask;
   return an array of error strings (or an empty array on success) */
function check_dhcp_range($if_ipaddr, $if_subnet, $range_from, $range_to) {
	$input_errors = array();
	$subnet_start = (ip2long($if_ipaddr) & gen_subnet_mask_long($if_subnet));
	$subnet_end = (ip2long($if_ipaddr) | (~gen_subnet_mask_long($if_subnet)));
	
	$rangefrom = ip2long($range_from);
	$rangeto = ip2long($range_to);
	$ifip = ip2long($if_ipaddr);
	
	if (($rangefrom < $subnet_start) || ($rangefrom > $subnet_end) ||
	    ($rangeto < $subnet_start) || ($rangeto > $subnet_end))
		$input_errors[] = "The specified range lies outside of the current subnet.";
	
	if ($rangefrom > $rangeto)
		$input_errors[] = "The range is invalid (start address higher than end address).";
	
	if (($rangefrom == $subnet_start) || ($rangeto == $subnet_end))
		$input_errors[] = "The network address (" . long2ip($subnet_start) . ") or the broadcast address (" . long2ip($subnet_end) . ") cannot be used in the range.";
	
	if ($ifip >= $rangefrom && $ifip <= $rangeto)
		$input_errors[] = "The interface's IP address cannot be included in the range.";
	
	return $input_errors;
}

function check_v6dhcp_range($if_ipaddr6, $if_subnet6, $v6range_from, $v6range_to) {
	$input_errors = array();
	
	if (is_ipaddr6($if_ipaddr6)) {
		/* check that range lies in current interface subnet */
		$if_v6subnet = gen_subnet6($if_ipaddr6, $if_subnet6);
		if (!isInNetmask6($v6range_from, $if_v6subnet, $if_subnet6) || !isInNetmask6($v6range_to, $if_v6subnet, $if_subnet6)) {
			$input_errors[] = "The specified IPv6 range lies outside of the current subnet (make sure the interface is configured with an IPv6 address before you enable the DHCP server).";
		}
	}
	
	/* check range start/end */
	$v6range_from_array = explode(":",ipv6Uncompress($v6range_from));
	$v6range_to_array = explode(":",ipv6Uncompress($v6range_to));
	for ($i=0; $i<=7; $i++)		{
	  if ($v6range_from_array[$i] > $v6range_to_array[$i]) {
			$input_errors[] = "The IPv6 range is invalid (start address higher than end address).";
		  break;
		} elseif ($v6range_from_array[$i] < $v6range_to_array[$i]) {
		break;
	  }
	}
	return $input_errors;
}
/* Render an elapsed interval as something a human reads at a glance.
 *
 * Used by the WireGuard peer list for "last handshake". Deliberately coarse:
 * the operator wants to know whether a peer is alive, not the second it last
 * spoke, so anything past a day reads as days.
 */
function format_duration($seconds) {
	$seconds = (int)$seconds;
	if ($seconds < 0)
		return "in the future";
	if ($seconds < 60)
		return $seconds . " second" . ($seconds == 1 ? "" : "s");
	if ($seconds < 3600) {
		$m = (int)($seconds / 60);
		return $m . " minute" . ($m == 1 ? "" : "s");
	}
	if ($seconds < 86400) {
		$h = (int)($seconds / 3600);
		return $h . " hour" . ($h == 1 ? "" : "s");
	}
	$d = (int)($seconds / 86400);
	return $d . " day" . ($d == 1 ? "" : "s");
}

function format_bytes($bytes) {
	if ($bytes >= 1073741824) {
		return sprintf("%.2f GB", $bytes/1073741824);
	} else if ($bytes >= 1048576) {
		return sprintf("%.2f MB", $bytes/1048576);
	} else if ($bytes >= 1024) {
		return sprintf("%.0f KB", $bytes/1024);
	} else {
		return sprintf("%d bytes", $bytes);
	}
}

/* lock a file; decide that the lock is stale after $maxwait seconds */
function lock_file($lockfile, $maxwait = 20) {
	$n = 0;
	
	while ($n < $maxwait) {
		/* open the lock file in append mode to avoid race condition */
		if ($fd = @fopen($lockfile, "x")) {
			/* succeeded */
			fclose($fd);
			return;
		} else {
			/* file locked, wait and try again */
			usleep(rand(200000,500000));
			$n++;
		}
	}
}

function unlock_file($lockfile) {
	if (file_exists($lockfile))
		unlink($lockfile);
}

?>