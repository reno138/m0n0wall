<?php
/*
	firewall_geoip.php
	part of m0n0wall (http://m0n0.ch/wall)

	Copyright (C) 2026 m0n0wall contributors.
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

$pgtitle = array("Firewall", "GeoIP");
require("guiconfig.inc");

if (!is_array($config['geoip'] ?? null))
	$config['geoip'] = array();

$pconfig['interval'] = $config['geoip']['interval'] ?? 168;
$pconfig['country']  = $config['geoip']['country'] ?? '';

if ($_POST) {

	unset($input_errors);
	$pconfig = $_POST;

	if (($_POST['interval'] ?? '') !== '' && !is_numericint($_POST['interval']))
		$input_errors[] = "The refresh interval must be a whole number of hours (0 disables automatic refresh).";

	$extra = array();
	if (trim($_POST['country'] ?? '') !== '') {
		foreach (explode(',', $_POST['country']) as $cc) {
			$cc = trim($cc);
			if ($cc === '')
				continue;
			if (!is_country_code($cc)) {
				$input_errors[] = "\"" . htmlspecialchars($cc) . "\" is not a two-letter country code.";
				break;
			}
			$extra[strtoupper($cc)] = true;
		}
	}

	if (empty($input_errors)) {
		$config['geoip']['interval'] = ($_POST['interval'] ?? '') === '' ? 168 : (int)$_POST['interval'];
		if (empty($extra))
			unset($config['geoip']['country']);
		else
			/* a string, not a list -- see geoip_countries_in_use() */
			$config['geoip']['country'] = implode(',', array_keys($extra));

		write_config();

		if (!empty($_POST['updatenow'])) {
			/* Synchronous on purpose: the operator pressed a button and wants
			   to see the result, and a run takes seconds on a working link. */
			list($written, $errors) = geoip_update();
			foreach ($errors as $e)
				$input_errors[] = $e;
			if (!empty($written)) {
				geoip_tables_reload();
				$retval = filter_configure();
				$parts = array();
				foreach ($written as $cc => $n)
					$parts[] = "{$cc} ({$n} prefixes)";
				$savemsg = "Updated: " . implode(", ", $parts) . ".";
			} else if (empty($errors)) {
				$savemsg = "Nothing to update: no rule refers to a country yet.";
			}
		} else {
			services_geoip_configure();
			$savemsg = "The settings have been saved.";
		}
	}
}

$status = geoip_status();
$empty_tables = 0;
foreach ($status as $st)
	if ($st['prefixes'] == 0) $empty_tables++;
?>
<?php include("fbegin.inc"); ?>
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
<?php if (!empty($savemsg)) print_info_box($savemsg); ?>

<form action="firewall_geoip.php" method="post" name="iform" id="iform">
<table width="100%" border="0" cellpadding="6" cellspacing="0" summary="content pane">
  <tr>
    <td colspan="2" valign="top" class="listtopic">Country tables</td>
  </tr>
  <tr>
    <td width="22%" valign="top" class="vncell">Automatic refresh</td>
    <td width="78%" class="vtable">
      every <input name="interval" type="text" class="formfld" id="interval" size="6"
                   value="<?=htmlspecialchars($pconfig['interval']);?>"> hours
      <br><span class="vexpl">0 disables automatic refresh and leaves the button below.
      The registries publish daily; a country's ranges move slowly, and each refresh
      reads about 40 MB from the five registries.</span></td>
  </tr>
  <tr>
    <td width="22%" valign="top" class="vncell">Keep updated</td>
    <td width="78%" class="vtable">
      <input name="country" type="text" class="formfld" id="country" size="40"
             value="<?=htmlspecialchars($pconfig['country']);?>">
      <br><span class="vexpl">Extra country codes to keep up to date even though no rule
      uses them yet, comma separated. Countries named by a rule are always included --
      nothing is downloaded for a country nothing refers to.</span></td>
  </tr>
  <tr>
    <td width="22%" valign="top">&nbsp;</td>
    <td width="78%">
      <input name="Submit" type="submit" class="formbtn" value="Save">
      <input name="updatenow" type="submit" class="formbtn" value="Save and update now">
    </td>
  </tr>
</table>
<br>
<table width="100%" border="0" cellpadding="0" cellspacing="0" summary="status">
  <tr>
    <td class="listhdrr">Country</td>
    <td class="listhdrr">pf table</td>
    <td class="listhdrr">Prefixes</td>
    <td class="listhdr">Last updated</td>
  </tr>
<?php if (empty($status)): ?>
  <tr>
    <td class="listlr" colspan="4">No rule refers to a country, so no tables are needed.
    Add a rule with a source or destination type of <em>Country</em>.</td>
  </tr>
<?php else: foreach ($status as $cc => $st): ?>
  <tr>
    <td class="listlr"><?=htmlspecialchars($cc);?></td>
    <td class="listr">&lt;<?=htmlspecialchars(geoip_table_name($cc));?>&gt;</td>
    <td class="listr"><?php if ($st['prefixes'] == 0): ?><span class="red">0</span><?php
                            else: echo $st['prefixes']; endif; ?></td>
    <td class="listr"><?=$st['updated'] ? date("Y/m/d H:i:s", $st['updated']) : "never";?></td>
  </tr>
<?php endforeach; endif; ?>
</table>
<?php if ($empty_tables): ?>
<br>
<table width="100%" border="0" cellspacing="0" cellpadding="0" summary="info pane">
  <tr>
    <td><strong><span class="red">Note:</span></strong><br>
    <?=$empty_tables;?> table(s) above hold no prefixes. An empty pf table matches
    nothing, so a rule using that country currently has no effect &mdash; it does not
    block, and it does not pass. The tables live on a RAM disk and are empty after
    every reboot until a refresh succeeds, which needs a working WAN. Press
    <em>Save and update now</em>, or check the system log for the reason the last
    refresh failed.</td>
  </tr>
</table>
<?php endif; ?>
</form>
<?php include("fend.inc"); ?>
