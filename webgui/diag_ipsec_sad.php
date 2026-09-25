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

/* Security associations, from strongSwan.
 *
 * This page used to drive setkey(8) -- "setkey -D" to list the kernel SAD and
 * "setkey -c" to delete entries. setkey came with ipsec-tools alongside racoon,
 * which this port replaced with strongSwan, and it is not in the image. So both
 * halves of the page were dead: the listing was always empty and the delete
 * button ran a missing binary.
 *
 * strongSwan does not expose the kernel SAD the way setkey did; it reports the
 * SAs IT established, which is the more useful view anyway because it carries
 * the connection name and the negotiated algorithms together. So the columns
 * follow swanctl rather than reproducing setkey's.
 *
 * swanctl --list-sas prints one block per IKE SA:
 *
 *   conn1: #1, ESTABLISHED, IKEv2, f1b2..._i c3d4..._r
 *     local  'C=CH, O=strongSwan' @ 10.0.0.1[500]
 *     remote '10.0.0.2' @ 10.0.0.2[500]
 *     AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
 *     established 5s ago, rekeying in 13805s
 *     child1: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-256
 *       ...
 *
 * The "#<n>" after the name is the unique identifier that
 * "swanctl --terminate --ike-id <n>" takes, and that is the only part of the
 * format this page parses -- the rest is shown verbatim, so a future strongSwan
 * that adds a field does not break the page.
 */

$swanctl_missing = !file_exists(SWANCTL_BIN);

/* terminate the selected SAs */
if (isset($_POST['del_x']) && is_array($_POST['entries'] ?? null) && !$swanctl_missing) {
	foreach ($_POST['entries'] as $entry) {
		if (!ctype_digit((string) $entry))
			continue;                    /* only ever an IKE SA unique id */
		mwexec(SWANCTL_BIN . " --terminate --ike-id " . escapeshellarg($entry) .
		       " --force --timeout 2 2>&1");
	}
	sleep(1);
}

/* list them */
$raw = "";
$sas = array();
if (!$swanctl_missing) {
	$out = array();
	exec(SWANCTL_BIN . " --list-sas 2>&1", $out);
	$raw = implode("\n", $out);
	foreach ($out as $line) {
		/* a top-level line is unindented; an indented one belongs to the block */
		if ($line === "" || $line[0] === " " || $line[0] === "\t")
			continue;
		if (preg_match('/^(\S+):\s+#(\d+),\s*([A-Za-z_-]+)(?:,\s*(IKEv\d))?/', $line, $m)) {
			$sas[] = array('name' => $m[1], 'id' => $m[2], 'state' => $m[3],
			               'version' => $m[4] ?? '');
		}
	}
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
<?php elseif (count($sas)): ?>
<form action="diag_ipsec_sad.php" method="post">
            <table width="100%" border="0" cellpadding="0" cellspacing="0" summary="inner content pane">
  <tr>
    			<td class="list">&nbsp;</td>
                <td nowrap class="listhdrr">Connection</td>
                <td nowrap class="listhdrr">ID</td>
                <td nowrap class="listhdrr">State</td>
                <td nowrap class="listhdr">IKE version</td>
                <td nowrap class="list"></td>
	</tr>
<?php foreach ($sas as $sa): ?>
	<tr>
		<td class="listt"><input type="checkbox" name="entries[]" value="<?=htmlspecialchars($sa['id']);?>" style="margin: 0 5px 0 0; padding: 0; width: 15px; height: 15px;"></td>
		<td class="listlr"><?=htmlspecialchars($sa['name']);?></td>
		<td class="listr">#<?=htmlspecialchars($sa['id']);?></td>
		<td class="listr"><?=htmlspecialchars($sa['state']);?></td>
		<td class="listr"><?=htmlspecialchars($sa['version']);?></td>
	</tr>
<?php endforeach; ?>
	 <tr> 
	   <td></td>
	 </tr> 
	 <tr> 
	   <td class="list" colspan="5"></td>
	   <td class="list"><input name="del" type="image" src="x.gif" width="17" height="17" title="terminate selected SAs" alt="terminate selected SAs" onclick="return confirm('Do you really want to terminate the selected security associations?')"></td>
	 </tr>
</table>
</form>
<?php else: ?>
<p><strong>No IPsec security associations.</strong></p>
<?php endif; ?>
<?php if (!$swanctl_missing && $raw !== ""): ?>
<p>&nbsp;</p>
<p><span class="vexpl">Full output of <tt>swanctl --list-sas</tt>, which carries the
negotiated algorithms, byte counters and rekey timers for each child SA:</span></p>
<pre class="cmdoutput"><?=htmlspecialchars($raw);?></pre>
<?php endif; ?>
</td></tr></table>
<?php include("fend.inc"); ?>
