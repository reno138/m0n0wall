<?php
/*
	datadisk.inc
	part of m0n0wall (http://m0n0.ch/wall)

	The persistent data partition.

	m0n0wall's root is a RAM disk and /cf holds only the firmware and
	config.xml, so nothing written at run time survived a reboot: the logs
	that would explain a failure were gone by the time anyone looked, and
	anything that needs state across reboots (Tailscale's node identity, an
	installed package) had nowhere to keep it. The install disk, meanwhile, was
	almost entirely unallocated -- the image lays out a few tens of MB and the
	rest sat empty.

	So at boot, on a disk with room, a partition labelled m0n0data is created
	in the space at the END of the disk, formatted once (UFS, soft updates with
	journaling -- a crash costs a journal replay, not a full fsck) and mounted
	at /data. /var/log becomes a link to /data/log. On a disk without room -- a
	small CompactFlash card -- nothing changes: logs stay on the RAM disk,
	bounded by the small newsyslog.conf, exactly as before.

	Why the end of the disk: a firmware upgrade dd's the whole image over the
	start of the disk, partition table included. Images are budgeted at
	DATADISK_IMAGE_BUDGET; the data partition never starts before twice that,
	so no image within budget can reach it. rc.firmware re-adds its table entry
	after the dd -- the data itself is never written. See rc.firmware.
*/

/* The GPT label, the mount point and the log directory under it. */
define('DATADISK_LABEL',   'm0n0data');
define('DATADISK_MOUNT',   '/data');
define('DATADISK_LOGDIR',  '/data/log');

/* The firmware image size target (stage 5 fails a build that exceeds it). */
define('DATADISK_IMAGE_BUDGET', 120 * 1024 * 1024);

/* The data partition never starts before this: twice the image budget, so a
   future image can grow to the budget without touching it. */
define('DATADISK_MIN_START', 2 * DATADISK_IMAGE_BUDGET);

/* Below this there is no point: 1 GB of logs (newsyslog-disk.conf's budget)
   plus room for packages and their state. */
define('DATADISK_MIN_SIZE', 1536 * 1024 * 1024);

/* Parse "gpart show -p <disk>" output into
 *   array('start' => .., 'size' => .., 'corrupt' => bool,
 *         'parts' => array(array('start','size','name','type'), ...),
 *         'free'  => array(array('start','size'), ...))
 * in the provider's sectors. Returns null for output that is not a table. */
function datadisk_parse_gpart_show($text) {
	$t = null;
	foreach (preg_split('/\r?\n/', $text) as $line) {
		if (preg_match('/^=>\s+(\d+)\s+(\d+)\s+\S+\s+\S+\s+\([^)]*\)(.*)$/', $line, $m)) {
			$t = array('start' => (int)$m[1], 'size' => (int)$m[2],
			           'corrupt' => (stripos($m[3], 'CORRUPT') !== false),
			           'parts' => array(), 'free' => array());
		} else if ($t && preg_match('/^\s+(\d+)\s+(\d+)\s+-\s+free\s+-/', $line, $m)) {
			$t['free'][] = array('start' => (int)$m[1], 'size' => (int)$m[2]);
		} else if ($t && preg_match('/^\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)/', $line, $m)) {
			$t['parts'][] = array('start' => (int)$m[1], 'size' => (int)$m[2],
			                      'name' => $m[3], 'type' => $m[4]);
		}
	}
	return $t;
}

/* Where the data partition goes, as array('start' => sector, 'size' => sectors),
 * or null when the disk has no room for one.
 *
 * Only the LAST free region is considered, and only if nothing follows it:
 * the partition must sit at the end of the disk. Its start is pushed up to
 * DATADISK_MIN_START and aligned to 1 MB; its size is rounded down to 1 MB. */
function datadisk_placement($table, $sectorsize) {
	if (!$table || empty($table['free']) || $sectorsize < 512)
		return null;

	$last = end($table['free']);
	$tabend = $table['start'] + $table['size'];
	if ($last['start'] + $last['size'] != $tabend)
		return null;			/* something sits after the free space */
	foreach ($table['parts'] as $p)
		if ($p['start'] >= $last['start'])
			return null;

	$align = intdiv(1024 * 1024, $sectorsize);
	$start = max($last['start'], intdiv(DATADISK_MIN_START, $sectorsize));
	$start = intdiv($start + $align - 1, $align) * $align;
	$end   = $last['start'] + $last['size'];
	if ($end <= $start)
		return null;
	$size  = intdiv($end - $start, $align) * $align;

	if ($size * $sectorsize < DATADISK_MIN_SIZE)
		return null;
	return array('start' => $start, 'size' => $size);
}

/* The boot disk's sector size, from "gpart list". */
function datadisk_sectorsize($disk) {
	exec("/sbin/gpart list " . escapeshellarg($disk) . " 2>/dev/null", $out);
	foreach ($out as $l)
		if (preg_match('/^\s*Sectorsize:\s*(\d+)/', $l, $m))
			return (int)$m[1];
	return 512;
}

/* Set up /data and point /var/log at it, or leave logs on the RAM disk.
 * Returns true when logs are persistent. Called from rc.bootup before any
 * logger (pflogd, syslogd) starts. */
function datadisk_setup() {
	global $g;

	$dev  = "/dev/gpt/" . DATADISK_LABEL;
	$disk = trim(@file_get_contents("{$g['varetc_path']}/cfdevice"));
	$mode = "ram";

	if ($disk !== "" && !file_exists($dev)) {
		/* The image's GPT is sized for its own content, so on any larger disk
		   the backup header is not at the last LBA and gpart reports the table
		   CORRUPT -- and refuses to add a partition to it. recover rewrites the
		   backup header at the real end. */
		exec("/sbin/gpart show -p " . escapeshellarg($disk) . " 2>/dev/null", $o1);
		$t = datadisk_parse_gpart_show(implode("\n", $o1));
		if ($t && $t['corrupt']) {
			mwexec("/sbin/gpart recover " . escapeshellarg($disk));
			$o1 = array();
			exec("/sbin/gpart show -p " . escapeshellarg($disk) . " 2>/dev/null", $o1);
			$t = datadisk_parse_gpart_show(implode("\n", $o1));
		}

		$p = datadisk_placement($t, datadisk_sectorsize($disk));
		if ($p) {
			echo "Creating the persistent data partition... ";
			$rc = mwexec("/sbin/gpart add -t freebsd-ufs -l " . DATADISK_LABEL .
				" -b {$p['start']} -s {$p['size']} " . escapeshellarg($disk));
			/* -j: soft updates + journaling, so a crash is a journal replay */
			if ($rc == 0)
				$rc = mwexec("/sbin/newfs -j -L " . DATADISK_LABEL . " " . $dev);
			echo ($rc == 0) ? "done\n" : "failed\n";
			if ($rc != 0)
				log_error("datadisk: could not create {$dev} on {$disk}; logs stay on the RAM disk");
		}
	}

	if (file_exists($dev)) {
		@mkdir(DATADISK_MOUNT, 0755);
		/* -p preens (replays the journal); only if that fails, -y repairs */
		if (mwexec("/sbin/fsck -p -t ufs {$dev}") != 0)
			mwexec("/sbin/fsck -y -t ufs {$dev}");
		/* Soft-updates journaling, so a crash is a journal replay rather than
		   a full check. newfs -j hands this to tunefs, which images before
		   2026-09-29 lacked -- their partitions came out unjournaled. It is a
		   no-op when already enabled, and needs the filesystem unmounted,
		   which it is here. */
		mwexec("/sbin/tunefs -j enable {$dev}");
		if (mwexec("/sbin/mount -o noatime {$dev} " . DATADISK_MOUNT) == 0) {
			@mkdir(DATADISK_LOGDIR, 0755);
			/* dmesg.boot describes ONE boot, and system_get_dmesg_boot() only
			   writes it when it is missing -- so on persistent storage it
			   would describe the boot the partition was made on, forever.
			   Keep the last boot's as .prev (useful after a crash) and let this
			   boot write its own. */
			if (file_exists(DATADISK_LOGDIR . "/dmesg.boot"))
				@rename(DATADISK_LOGDIR . "/dmesg.boot", DATADISK_LOGDIR . "/dmesg.boot.prev");
			/* this boot's files -- dmesg.boot and the logs etc/rc touched -- go
			   onto the disk; logs already there are kept, not overwritten */
			foreach (glob("{$g['varlog_path']}/*") as $f) {
				$dst = DATADISK_LOGDIR . "/" . basename($f);
				if (!file_exists($dst)) {
					@copy($f, $dst);
					/* copy() applies the umask, not the source mode; the logs
					   are 0600 */
					@chmod($dst, fileperms($f) & 0777);
				}
			}
			/* logs are 0600, whoever created them (etc/rc's touch, an older
			   image's copy) */
			foreach (array_merge(glob(DATADISK_LOGDIR . "/*.log") ?: array(),
			                     glob(DATADISK_LOGDIR . "/pflog.cap*") ?: array()) as $f)
				@chmod($f, 0600);
			mwexec("/bin/rm -rf " . escapeshellarg($g['varlog_path']));
			symlink(DATADISK_LOGDIR, $g['varlog_path']);
			$mode = "disk";
		} else {
			log_error("datadisk: could not mount {$dev}; logs stay on the RAM disk");
		}
	}

	/* the rotation limits that fit where the logs actually are */
	@copy($mode == "disk" ? "/etc/newsyslog-disk.conf" : "/etc/newsyslog.conf",
	      "{$g['varetc_path']}/newsyslog.conf");
	@file_put_contents("{$g['varrun_path']}/datadisk", $mode . "\n");
	return ($mode == "disk");
}

?>
