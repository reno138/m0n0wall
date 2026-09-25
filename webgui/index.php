#!/usr/local/bin/php
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

$pgtitle = array("m0n0wall webGUI");
$pgtitle_omit = true;
require("guiconfig.inc");

/* find out whether there's hardware encryption (hifn) */
unset($hwcrypto);

$hwcrypto = hwcrypto_descr();

$specplatform = system_identify_specific_platform();
if (preg_match("/^CPU.*/m", $dmesg ?? '', $matches) )
	$cpudetail = " - " . $matches[0];

if ($_POST) {
	$config['system']['notes'] = base64_encode($_POST['notes']);
	write_config();
	header("Location: index.php");
	exit;
}
	exec("export QUERY_STRING=cpu;export REQUEST_METHOD=GET;/usr/local/www/stats.cgi" ,$cpuutil);
    $cpuu = $cpuutil[2] ?? null;

	exec("/sbin/sysctl -n vm.stats.vm.v_active_count vm.stats.vm.v_inactive_count " .
    	"vm.stats.vm.v_wire_count vm.stats.vm.v_cache_count vm.stats.vm.v_free_count", $memory);
    $totalMem = ($memory[0] ?? null) + ($memory[1] ?? null) + ($memory[2] ?? null) + ($memory[3] ?? null) + ($memory[4] ?? null);
    $freeMem = $memory[4] ?? null;
    $usedMem = $totalMem - $freeMem;
    /* DivisionByZeroError is fatal in PHP 8, and $totalMem is 0 whenever the
       sysctl exec returns nothing -- which took the dashboard down entirely
       rather than showing a wrong number. */
    $memUsage = ($totalMem > 0) ? round(($usedMem * 100) / $totalMem, 0) : 0;

?>
<?php include("fbegin.inc"); ?>
<form action="" method="POST">
            <table width="100%" border="0" cellspacing="0" cellpadding="0" summary="content pane">
              <tr align="center" valign="top"> 
                <td height="10" colspan="2">&nbsp;</td>
              </tr>
              <tr align="center" valign="top"> 
                <td height="170" colspan="2"><img src="logobig.gif" width="520" height="149" alt=""></td>
              </tr>
              <tr> 
                <td colspan="2" class="listtopic">System information</td>
              </tr>
              <tr> 
                <td width="25%" class="vncellt">Name</td>
                <td width="75%" class="listr">
                  <?php echo $config['system']['hostname'] . "." . $config['system']['domain']; ?>
                </td>
              </tr>
              <tr> 
                <td width="25%" valign="top" class="vncellt">Version</td>
                <td width="75%" class="listr"> <strong> 
                  <?php readfile("/etc/version"); ?>
                  </strong>
                  built on 
                  <?php readfile("/etc/version.buildtime"); ?>
                </td>
              </tr>
              <tr> 
                <td width="25%" class="vncellt">Platform</td>
                <td width="75%" class="listr"> 
                  <?=htmlspecialchars($specplatform['descr']); ?> <?=htmlspecialchars($cpudetail ?? ''); ?> 
                </td>
              </tr><?php if ($hwcrypto): ?>
              <tr> 
                <td width="25%" class="vncellt">Hardware crypto</td>
                <td width="75%" class="listr"> 
                  <?=htmlspecialchars($hwcrypto);?>
                </td>
              </tr><?php endif; ?>
              <tr> 
                <td width="25%" class="vncellt">System Date</td>
                <td width="75%" class="listr"> 
                   <?=exec("/bin/date");?>
                </td>
              </tr>
              <tr> 
                <td width="25%" class="vncellt">Uptime</td>
                <td width="75%" class="listr"> 
                  <?php
				  	exec("/sbin/sysctl -n kern.boottime", $boottime);
					preg_match("/sec = (\d+)/", $boottime[0] ?? '', $matches);
					$boottime = $matches[1] ?? null;
					$uptime = time() - $boottime;
					
					if ($uptime > 60)
						$uptime += 30;
					$updays = (int)($uptime / 86400);
					$uptime %= 86400;
					$uphours = (int)($uptime / 3600);
					$uptime %= 3600;
					$upmins = (int)($uptime / 60);
					
					$uptimestr = "";
					if ($updays > 1)
						$uptimestr .= "$updays days, ";
					else if ($updays > 0)
						$uptimestr .= "1 day, ";
					$uptimestr .= sprintf("%02d:%02d", $uphours, $upmins);
					echo htmlspecialchars($uptimestr);
				  ?>
                </td>
              </tr>
              <?php if (!empty($config['lastchange'])): ?>
              <tr> 
                <td width="25%" class="vncellt">Last config change</td>
                <td width="75%" class="listr"> 
                  <?=htmlspecialchars(date("D M j G:i:s T Y", $config['lastchange']));?>
                </td>
              </tr>
              <?php endif; ?>
   			  <tr> 
                <td width="25%" class="vncellt">CPU usage</td>
                <td width="75%" class="listr">
                <?php pc_gauge($cpuu,50) ?>
                </td>		
              </tr>
   			  <tr> 
                <td width="25%" class="vncellt">Memory usage</td>
                <td width="75%" class="listr">
			  	<?php pc_gauge($memUsage,50) ?>
			  	</td>
              </tr>
			  <?php
					/* System sensors.
					
					   This used to shell out to /usr/local/bin/mbmon, which is
					   not in the image -- so the "Enable Motherboard Monitoring"
					   option on System: Advanced configured nothing and this
					   block never rendered. Shipping mbmon would not have been
					   the right fix either: it reads a handful of Super I/O
					   chips from the early 2000s and knows nothing about any
					   CPU made since.
					
					   FreeBSD reports CPU temperature through coretemp(4) on
					   Intel and amdtemp(4) on AMD, and chassis temperature
					   through ACPI thermal zones, all as sysctls. That covers
					   essentially every machine this will run on, needs no
					   extra binary, and the two drivers are kernel modules
					   loaded by system.inc when the option is on. */
					if (isset($config['system']['webgui']['sensors']['enable'])) {
						$fahrenheit = (($config['system']['webgui']['sensors']['type'] ?? null) == 'F');
						$sensors = array();

						/* dev.cpu.N.temperature and the ACPI thermal zones both
						   read back as "42.0C" -- tenths of a Kelvin formatted
						   by the kernel, so the unit is always C here. */
						$sysctls = array();
						exec("/sbin/sysctl -n hw.ncpu 2>/dev/null", $ncpuout);
						$ncpu = (int) ($ncpuout[0] ?? 1);
						for ($c = 0; $c < $ncpu; $c++)
							$sysctls["CPU $c"] = "dev.cpu.$c.temperature";
						/* thermal zones, however many the firmware exposes */
						$tzout = array();
						exec("/sbin/sysctl -N hw.acpi.thermal 2>/dev/null", $tzout);
						foreach ($tzout as $tzname) {
							if (preg_match('/^hw\.acpi\.thermal\.(tz\d+)\.temperature$/', trim($tzname), $tzm))
								$sysctls["Thermal zone " . substr($tzm[1], 2)] = trim($tzname);
						}

						foreach ($sysctls as $label => $oid) {
							$v = array();
							exec("/sbin/sysctl -n " . escapeshellarg($oid) . " 2>/dev/null", $v);
							$raw = trim($v[0] ?? '');
							if ($raw === '' || !preg_match('/^(-?[0-9.]+)\s*C$/', $raw, $vm))
								continue;
							$deg = (float) $vm[1];
							$sensors[$label] = $fahrenheit
							                   ? sprintf('%.1f &deg;F', $deg * 9 / 5 + 32)
							                   : sprintf('%.1f &deg;C', $deg);
						}

						if (count($sensors)) {
					?>
				<tr>
				<td width="25%" class="vncellt">System temperatures</td>
				<td width="75%" class="listr">
				<table width="100%">
					<?php foreach ($sensors as $label => $val): ?>
				<tr>
				<td align="right" width="30%" class="listsensor"><?=htmlspecialchars($label);?></td>
				<td align="left" width="70%" class="listsensorval"><?=$val;?></td>
				</tr>
					<?php endforeach; ?>
				</table>
				</td>
				</tr>
					<?php
						}
					}
						?>
              <tr> 
                <td width="25%" class="vncellt" valign="top">Notes</td>
                <td width="75%" class="listr">
                  <textarea name="notes" cols="75" rows="7" id="notes" class="notes"><?=htmlspecialchars(base64_decode($config['system']['notes'] ?? ''));?></textarea><br>
                  <input name="Submit" type="submit" class="formbtns" value="Save">
                </td>
              </tr>
            </table>
</form>
            <?php include("fend.inc"); ?>
