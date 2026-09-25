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
	
function shaper_configure() {
	global $config, $g;
	
	if (isset($config['shaper']['enable'])) {
	
		if ($g['booting'])
			echo "Starting traffic shaper... ";
		
		/* generate shaper rules */
		$shaperrules = shaper_rules_generate();
		
		/* make sure ipfw and dummynet are loaded */
		mwexec("/sbin/kldload ipfw");
		mwexec("/sbin/kldload dummynet");
		
		/* change one_pass to 1 so ipfw stops checking after
		   a rule has matched */
		mwexec("/sbin/sysctl net.inet.ip.fw.one_pass=1");
		
		/* remove old shaper rules */
		mwexec("/sbin/ipfw -f delete set 4");
		
		/* remove old pipes/queues - note that we cannot use flush
		   if the captive portal per-user bandwidth shaping is also
		   enabled, since we'd delete any per-user shaping pipes as well */
		if (isset($config['captiveportal']['peruserbw'])) {
			/* delete pipes/queues one by one */
			$delpipes = array();
			$delqueues = array();
			$p = popen("/sbin/ipfw pipe show", "r");
			while (!feof($p)) {
				$line = trim(fgets($p));
				if (preg_match("/^(\d+):/", $line, $matches)) {
					if ($matches[1] < 50000)	/* per-user rules from 50000 */
						$delpipes[] = $matches[1];
				} else if (preg_match("/^q(\d+):/", $line, $matches))
					$delqueues[] = $matches[1];
			}
			pclose($p);
			
			foreach ($delpipes as $delpipe)
				mwexec("/sbin/ipfw pipe delete $delpipe");
			foreach ($delqueues as $delqueue)
				mwexec("/sbin/ipfw queue delete $delqueue");
		} else {
			/* "pipe flush" removes queues as well, and vice versa */
			mwexec("/sbin/ipfw -f pipe flush");
		}
		
		/* load shaper rules */
		
		/* XXX - seems like ipfw cannot accept rules directly on stdin,
		   so we have to write them to a temporary file first */
		$fd = fopen("{$g['tmp_path']}/ipfw.rules", "w");
		if (!$fd) {
			printf("Cannot open ipfw.rules in shaper_configure()\n");
			return 1;
		}
			
		fwrite($fd, $shaperrules);
		fclose($fd);
		
		mwexec("/sbin/ipfw {$g['tmp_path']}/ipfw.rules");
		
		unlink("{$g['tmp_path']}/ipfw.rules");
		
		/* make sure bridged packets are shaped as well */
		mwexec("/sbin/sysctl net.link.ether.bridge.ipfw=1");
		
		if ($g['booting'])
			echo "done\n";
		
	} else {
		mwexec("/sbin/sysctl net.link.ether.bridge.ipfw=0");
		/* Remove our own rules and pipes, always.
		
		   This used to kldunload dummynet and ipfw when the captive portal was
		   off. Both are compiled INTO this kernel (options IPFIREWALL and
		   options DUMMYNET in M0N0WALL_GENERIC), so the unload could only ever
		   fail -- leaving set 4 and every dummynet pipe live. The shaper
		   therefore could not be switched off without a reboot.
		
		   Deleting the set and flushing is what the captive-portal branch
		   always did, it is what actually works, and it is safe either way:
		   set 4 is the shaper's own set, and the portal keeps its rules in
		   set 1. Queues are flushed as well -- 'pipe flush' does not remove
		   them, so they would have survived. */
		mwexec("/sbin/ipfw -f delete set 4");
		mwexec("/sbin/ipfw -f queue flush");
		mwexec("/sbin/ipfw -f pipe flush");
	}
	
	return 0;
}

/* Remove entries from the pipe or queue list and fix every reference to them.
 *
 * Pipes and queues are referenced BY ARRAY INDEX: a rule says targetpipe = 2,
 * a queue says targetpipe = 0. So deleting an entry shifts the meaning of every
 * index above it, and the lists are re-indexed contiguously the next time the
 * config is written -- there is no way to keep a hole.
 *
 * Every caller used to do this inline, and all of them were wrong in the same
 * way: they looped once per deleted entry and compared an ALREADY-DECREMENTED
 * target against the next raw, pre-deletion index. Deleting two entries in one
 * action therefore under-counted the shift for every reference above the second
 * one, silently pointing rules at the wrong pipe -- or at one that no longer
 * exists, which ipfw rejects. The magic-shaper wizard did not renumber at all.
 *
 * Doing it in one pass removes the class of bug: the old -> new map is computed
 * from the survivors BEFORE anything is removed, so no arithmetic depends on
 * the order the victims are processed in.
 *
 * $type    'pipe' or 'queue'
 * $victims array of indices to remove
 *
 * A surviving rule or queue that pointed AT a victim cannot work any more, so it
 * is disabled rather than silently deleted or left pointing somewhere arbitrary.
 * Returns the number of entries disabled that way, so a caller can tell the user.
 */
function shaper_remove_entries($type, $victims) {
	global $config;

	if ($type !== 'pipe' && $type !== 'queue')
		return 0;
	if (!is_array($config['shaper'][$type] ?? null) || !is_array($victims))
		return 0;

	if (empty($victims))
		return 0;                         /* nothing to do, and nothing to touch */

	$victims = array_map('intval', $victims);
	$list    = &$config['shaper'][$type];

	/* old index -> new index over the survivors; null marks a victim */
	$map = array();
	$new = 0;
	foreach (array_keys($list) as $old) {
		$map[(int) $old] = in_array((int) $old, $victims, true) ? null : $new++;
	}

	foreach ($victims as $v)
		unset($list[$v]);
	$list = array_values($list);

	/* Which reference fields point at this kind of entry?
	   A queue belongs to a pipe, and a rule targets one or the other. */
	$refs = ($type === 'pipe')
	        ? array(array('rule', 'targetpipe'), array('queue', 'targetpipe'))
	        : array(array('rule', 'targetqueue'));

	$disabled = 0;
	foreach ($refs as $r) {
		list($section, $field) = $r;
		if (!is_array($config['shaper'][$section] ?? null))
			continue;
		foreach ($config['shaper'][$section] as $k => $unused) {
			$ent = &$config['shaper'][$section][$k];
			if (!isset($ent[$field]) || $ent[$field] === '')
				continue;
			$old = (int) $ent[$field];
			if (!array_key_exists($old, $map))
				continue;                     /* already dangling; leave it */
			if ($map[$old] === null) {
				/* it pointed at something that is now gone */
				if (!isset($ent['disabled'])) {
					$ent['disabled'] = true;
					$disabled++;
				}
			} else {
				$ent[$field] = $map[$old];
			}
			unset($ent);
		}
	}

	return $disabled;
}

function shaper_rules_generate() {
	global $config, $g;

	$wancfg = $config['interfaces']['wan'];
	$lancfg = $config['interfaces']['lan'];
	/* PPTP is removed from this port. Kept as a single false so the rule
	   walker below can still recognise and SKIP a restored config's pptp
	   rules, without reading a $config['pptpd'] section that no longer
	   exists -- that read warned on every shaper rebuild. */
	$pptp_server = false;
	
	$lanif = $lancfg['if'];
	$wanif = get_real_wan_interface();
	
	$lanip = $lancfg['ipaddr'];
	$lansa = gen_subnet($lancfg['ipaddr'], $lancfg['subnet']);
	$lansn = $lancfg['subnet'];
	
	/* optional interfaces. opt_interfaces(), not a loop counting up from opt1:
	   deleting an optional interface no longer renumbers the ones above it, so
	   the numbering can have gaps and a counting loop stops at the first one.
	   See util.inc. */
	$optcfg = array();
	
	foreach (opt_interfaces() as $optif) {
		$oc = $config['interfaces'][$optif];
		
		if (isset($oc['enable']) && $oc['if']) {
			$oic = array();
			$oic['ip'] = $oc['ipaddr'];
			$oic['if'] = $oc['if'];
			$oic['sa'] = gen_subnet($oc['ipaddr'], $oc['subnet']);
			$oic['sn'] = $oc['subnet'];
			
			$optcfg[$optif] = $oic;
		}
	}
	
	/* $i is not dead here: the rule walker below carries on incrementing it as
	   its "rule N" counter and never initialises it, so the numbers it prints
	   have always started at the first free OPT number rather than at 0 --
	   filter.inc resets $i to -1 before its walker, this one was never given the
	   same line. That defect is in diagnostic text only and is left for later;
	   the loop above used to exit at exactly the lowest unused OPT number, which
	   is what opt_next_free() answers, so nothing changes here. */
	$i = opt_next_free();
	
	$pptpip = $pptpsa = $pptpsn = "";
	if ($pptp_server) {
		$pptpip = "";
		$pptpsa = "";
		$pptpsn = "";
	}
	
	$rulei = 50000;
	
	/* add a rule to pass all traffic from/to the firewall,
	   so the user cannot lock himself out of the webGUI */
	$shaperrules = "add $rulei set 4 pass all from $lanip to any\n"; $rulei++;
	$shaperrules .= "add $rulei set 4 pass all from any to $lanip\n"; $rulei++;
	
	/* generate rules */
	if (isset($config['shaper']['rule']))	
		foreach ($config['shaper']['rule'] as $rule) {
			
		/* don't include disabled rules */
		if (isset($rule['disabled'])) {
			$i++;
			continue;
		}
		
		/* does the rule deal with a PPTP interface? */
		if ($rule['interface'] == "pptp") {
		
			/* always, now: PPTP is removed, so there is no interface to shape */
			if (!$pptp_server) {
				$i++;
				continue;
			}
				
			$nif = 16;
			$ispptp = true;
		} else {
			
			if (strstr($rule['interface'], "opt")) {
				if (!array_key_exists($rule['interface'], $optcfg)) {
					$i++;
					continue;
				}
			}
		
			$nif = 1;
			$ispptp = false;
		}
		
		if (!$pptp_server) {
			if ((($rule['source']['network'] ?? '') == "pptp") ||
				(($rule['destination']['network'] ?? '') == "pptp")) {
					$i++;
					continue;
				}
		}
		
		/* 'network' and 'address' are alternatives -- a rule has one or the
		   other, never both -- so each is absent half the time and both have
		   to be read with ?? / !empty(). */
		if (strstr($rule['source']['network'] ?? '', "opt")) {
			if (!array_key_exists($rule['source']['network'], $optcfg)) {
				$i++;
				continue;
			}
		}
		if (strstr($rule['destination']['network'] ?? '', "opt")) {
			if (!array_key_exists($rule['destination']['network'], $optcfg)) {
				$i++;
				continue;
			}
		}
		
		/* check for unresolvable aliases */
		if (!empty($rule['source']['address']) && !alias_expand($rule['source']['address'])) {
			$i++;
			continue;
		}
		if (!empty($rule['destination']['address']) && !alias_expand($rule['destination']['address'])) {
			$i++;
			continue;
		}
		
		for ($iif = 0; $iif < $nif; $iif++) {
			
			/* pipe or queue? */
			if (isset($rule['targetpipe']) && isset($config['shaper']['pipe'][$rule['targetpipe']])) {
				$pipen = $rule['targetpipe'] + 1;
				$line = "add $rulei set 4 pipe $pipen "; $rulei++;
			} else if (isset($rule['targetqueue']) && isset($config['shaper']['queue'][$rule['targetqueue']])) {
				$queuen = $rule['targetqueue'] + 1;
				$line = "add $rulei set 4 queue $queuen "; $rulei++;
			} else {
				printf("Neither existing pipe nor queue found in rule $i\n");
				break;
			}
			
			if (isset($rule['protocol'])) {
				$line .= "{$rule['protocol']} ";
			} else {
				$line .= "all ";
			}
			
			/* source address */
			if (isset($rule['source']['any'])) {
				$src = "any";
			} else if ($rule['source']['network']) {
				
				if (strstr($rule['source']['network'], "opt")) {
					$src = $optcfg[$rule['source']['network']]['sa'] . "/" .
						$optcfg[$rule['source']['network']]['sn'];
				} else {
					switch ($rule['source']['network']) {
						case 'lan':
							$src = "$lansa/$lansn";
							break;
						case 'pptp':
							$src = "$pptpsa/$pptpsn";
							break;
					}
				}
			} else if ($rule['source']['address']) {
				$src = alias_expand($rule['source']['address']);
			}
			
			if (!$src) {
				printf("No source address found in rule $i\n");
				break;
			}
			
			if (isset($rule['source']['not'])) {
				$line .= "from not $src ";
			} else {
				$line .= "from $src ";
			}
			
			if (!isset($rule['protocol']) || in_array($rule['protocol'], array("tcp","udp"))) {
				
				if (!empty($rule['source']['port'])) {
					$srcport = explode("-", $rule['source']['port']);
					
					if ((!$srcport[1]) || ($srcport[0] == $srcport[1])) {
						$line .= "{$srcport[0]} ";
					} else {
						$line .= "{$srcport[0]}-{$srcport[1]} ";
					}
				}
			}
			
			/* destination address */
			if (isset($rule['destination']['any'])) {
				$dst = "any";
			} else if ($rule['destination']['network']) {
				
				if (strstr($rule['destination']['network'], "opt")) {
					$dst = $optcfg[$rule['destination']['network']]['sa'] . "/" .
						$optcfg[$rule['destination']['network']]['sn'];
				} else {
					switch ($rule['destination']['network']) {
						case 'lan':
							$dst = "$lansa/$lansn";
							break;
						case 'pptp':
							$dst = "$pptpsa/$pptpsn";
							break;
					}
				}
			} else if ($rule['destination']['address']) {
				$dst = alias_expand($rule['destination']['address']);
			}
			
			if (!$dst) {
				printf("No destination address found in rule $i\n");
				break;
			}
			
			if (isset($rule['destination']['not'])) {
				$line .= "to not $dst ";
			} else {
				$line .= "to $dst ";
			}
			
			if (!isset($rule['protocol']) || in_array($rule['protocol'], array("tcp","udp"))) {
				
				if (!empty($rule['destination']['port'])) {
					$dstport = explode("-", $rule['destination']['port']);
					
					if ((!$dstport[1]) || ($dstport[0] == $dstport[1])) {
						$line .= "{$dstport[0]} ";
					} else {
						$line .= "{$dstport[0]}-{$dstport[1]} ";
					}
				}
			}
			
			/* all three are optional match refinements, blank by default */
			if (!empty($rule['iplen']))
				$line .= "iplen {$rule['iplen']} ";
				
			if (!empty($rule['iptos'])) 
				$line .= "iptos {$rule['iptos']} ";
			
			if (!empty($rule['tcpflags']))
				$line .= "tcpflags {$rule['tcpflags']} ";
				
			if (($rule['direction'] ?? '') == "in")
				$line .= "in ";
			else if ($rule['direction'] == "out")
				$line .= "out ";
			
			if ($ispptp) {
				$line .= "via ng" . ($iif+1);
			} else {
				if ($rule['interface'] == "wan")
					$if = $wanif;
				else
					$if = $config['interfaces'][$rule['interface']]['if'];
					
				$line .= "via {$if}";
			}
			
			$line .= "\n";
			$shaperrules .= $line;
		}
		
		$i++;
	}
	
	/* generate pipes */
	if (isset($config['shaper']['pipe'])) {
		foreach ($config['shaper']['pipe'] as $pipek => $pipe) {
			/* index + 1, for the same reason as the queues below: this is what
			   the rule emitter uses ($rule['targetpipe'] + 1). */
			$pipei = $pipek + 1;
			$line = "pipe $pipei config bw {$pipe['bandwidth']}Kbit/s ";
			
			/* Every one of these is optional in the GUI and is simply ABSENT
			   when left blank, so they are read with !empty() rather than for
			   truth -- four undefined-key warnings per pipe otherwise, printed
			   into the Apply page and the boot console. */
			if (!empty($pipe['delay'])) {
				$line .= "delay {$pipe['delay']} ";
			}
			
			if (!empty($pipe['plr'])) {
				$line .= "plr {$pipe['plr']} ";
			}
			
			if (!empty($pipe['qsize'])) {
				$line .= "queue {$pipe['qsize']} ";
			}
			
			switch ($pipe['mask'] ?? '') {
				case 'source':
					$line .= "mask src-ip 0xffffffff ";
					break;
				case 'destination':
					$line .= "mask dst-ip 0xffffffff ";
					break;
			}
			
			$line .= "\n";
			$shaperrules .= $line;
		}
	}
	
	/* generate queues */
	if (isset($config['shaper']['queue'])) {
		foreach ($config['shaper']['queue'] as $queuek => $queue) {
			
			/* The ipfw queue number is the array INDEX plus one, not a running
			   counter over the emitted queues.
			
			   A running counter was wrong because the 'continue' below does not
			   advance it, while the rule emitter derives its queue number from
			   the config index ($rule['targetqueue'] + 1). One queue with an
			   unresolvable pipe therefore shifted every later queue's number
			   by one and silently pointed every rule above it at the wrong
			   queue -- or at one that was never configured, which ipfw
			   rejects. Deriving both from the index makes them agree by
			   construction. */
			$queuei = $queuek + 1;
			$pipen = ($queue['targetpipe'] ?? -1) + 1;
			if (!isset($queue['targetpipe']) || !isset($config['shaper']['pipe'][$queue['targetpipe']])) {
				printf("Pipe $pipen for queue $queuei not found!\n");
				continue;
			}
			
			$line = "queue $queuei config pipe {$pipen}";
			if (!empty($queue['weight']))
				$line .= " weight {$queue['weight']}";
			
			switch ($queue['mask'] ?? '') {
				case 'source':
					$line .= " mask src-ip 0xffffffff ";
					break;
				case 'destination':
					$line .= " mask dst-ip 0xffffffff ";
					break;
			}
			
			$line .= "\n";
			$shaperrules .= $line;
		}
	}

	return $shaperrules;
}

?>
