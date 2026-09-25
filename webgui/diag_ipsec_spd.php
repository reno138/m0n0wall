#!/usr/local/bin/php
<?php 
/*
	$Id$
	part of m0n0wall (http://m0n0.ch/wall)
	
	Copyright (C) 2003-2012 Manuel Kasper <mk@neon1.net>.
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

$pgtitle = array("Diagnostics", "IPsec");

require("guiconfig.inc");

/* Installed IPsec policies, from strongSwan.
 *
 * Was "setkey -DP" plus "setkey -c" to delete. setkey belonged to ipsec-tools,
 * which went with racoon, and is not in the image -- so this page listed nothing
 * and its delete button ran a missing binary.
 *
 * strongSwan installs and removes its own policies as part of establishing and
 * tearing down a CHILD_SA; there is no separate SPD to edit, which is why there
 * is no delete control here any more. The way to remove a policy is to terminate
 * the SA that installed it, on the SAs tab.
 */

$swanctl_missing = !file_exists(SWANCTL_BIN);

$raw  = "";
$pols = array();
if (!$swanctl_missing) {
	$out = array();
	exec(SWANCTL_BIN . " --list-pols 2>&1", $out);
	$raw = implode("\n", $out);

	/* swanctl --list-pols prints, per policy:
	 *
	 *   conn1: TUNNEL, reqid 1
	 *     local  10.1.0.0/24
	 *     remote 10.2.0.0/24
	 *
	 * Only the header line and the two selectors are parsed; anything else is
	 * left to the verbatim output below. */
	$cur = null;
	foreach ($out as $line) {
		if ($line === "")
			continue;
		if ($line[0] !== " " && $line[0] !== "\t") {
			if (is_array($cur))
				$pols[] = $cur;
			$cur = array('name' => '', 'mode' => '', 'local' => '', 'remote' => '');
			if (preg_match('/^(\S+):\s*([A-Za-z_-]+)?/', $line, $m)) {
				$cur['name'] = $m[1];
				$cur['mode'] = $m[2] ?? '';
			}
		} else if (is_array($cur)) {
			$t = trim($line);
			if (strpos($t, 'local ') === 0)
				$cur['local'] = trim(substr($t, 6));
			else if (strpos($t, 'remote ') === 0)
				$cur['remote'] = trim(substr($t, 7));
		}
	}
	if (is_array($cur))
		$pols[] = $cur;
}
?>
<?php include("fbegin.inc"); ?>
<table width="100%" border="0" cellpadding="0" cellspacing="0">
  <tr><td class="tabnavtbl">
  <ul id="tabnav">
<?php 
    	$tabs = array('SAs' => 'diag_ipsec_sad.php',
            		  'Policies' => 'diag_ipsec_spd.php');
		dynamic_tab_menu($tabs);
?>
  </ul>
  </td></tr>
  <tr> 
    <td class="tabcont">
<?php if ($swanctl_missing): ?>
<p><strong>swanctl was not found.</strong> IPsec status cannot be read without it.</p>
<?php elseif (count($pols)): ?>
            <table width="100%" border="0" cellpadding="0" cellspacing="0" summary="inner content pane">
  <tr>
                <td nowrap class="listhdrr">Connection</td>
                <td nowrap class="listhdrr">Mode</td>
                <td nowrap class="listhdrr">Local network</td>
                <td nowrap class="listhdr">Remote network</td>
	</tr>
<?php foreach ($pols as $p): ?>
	<tr>
		<td class="listlr"><?=htmlspecialchars($p['name']);?></td>
		<td class="listr"><?=htmlspecialchars($p['mode']);?></td>
		<td class="listr"><?=htmlspecialchars($p['local']);?></td>
		<td class="listr"><?=htmlspecialchars($p['remote']);?></td>
	</tr>
<?php endforeach; ?>
</table>
<p><span class="vexpl">strongSwan installs and removes these itself as the
matching security association comes up and goes down, so there is nothing to
delete here. To remove a policy, terminate its SA on the
<a href="diag_ipsec_sad.php">SAs</a> tab.</span></p>
<?php else: ?>
<p><strong>No IPsec policies installed.</strong></p>
<?php endif; ?>
<?php if (!$swanctl_missing && $raw !== ""): ?>
<p>&nbsp;</p>
<p><span class="vexpl">Full output of <tt>swanctl --list-pols</tt>:</span></p>
<pre class="cmdoutput"><?=htmlspecialchars($raw);?></pre>
<?php endif; ?>
</td></tr></table>
<?php include("fend.inc"); ?>
