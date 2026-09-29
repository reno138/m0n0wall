<?php
/*
 * datadisk.inc: where the persistent data partition goes.
 *
 * Getting this wrong writes a filesystem over the firmware, or puts the data
 * where the next upgrade's dd overwrites it -- so the placement arithmetic is
 * pinned here against real "gpart show -p" output.
 */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/datadisk.inc';

/* The test VM's disk as installed: 8 GB, image laid out at the start, backup GPT
   header at the image's end rather than the disk's (hence CORRUPT). */
$vm = <<<T
=>      40  16777136    da0  GPT  (8.0G) [CORRUPT]
        40      4096  da0p1  efi  (2.0M)
      4136       128  da0p2  freebsd-boot  (64K)
      4264     92120  da0p3  freebsd-ufs  (45M)
     96384  16680792         - free -  (8.0G)
T;
$t = datadisk_parse_gpart_show($vm);
is_true ('parses a GPT table', $t !== null);
is_true ('sees the CORRUPT flag', $t['corrupt']);
is_same ('three partitions', count($t['parts']), 3);
is_same ('one free region', count($t['free']), 1);

$p = datadisk_placement($t, 512);
is_true ('an 8 GB disk gets a data partition', $p !== null);
is_same ('it starts at twice the 120 MB image budget (sector 491520)', $p['start'], 491520);
is_same ('1 MB aligned start', $p['start'] % 2048, 0);
is_same ('1 MB aligned size', $p['size'] % 2048, 0);
is_true ('it ends at or before the end of the table',
         $p['start'] + $p['size'] <= $t['start'] + $t['size']);
is_true ('it never overlaps the firmware partition',
         $p['start'] >= 4264 + 92120);
is_true ('and uses nearly the whole rest of the disk (> 7.5 GB)',
         $p['size'] * 512 > 7.5 * 1024 * 1024 * 1024);

/* a 120 MB image -- the whole budget -- still ends well before it */
is_true ('a full-budget image cannot reach it',
         (120 * 1024 * 1024) / 512 < $p['start']);

/* a 1 GB CompactFlash card: no data partition, logs stay in RAM */
$cf = <<<T
=>      40  1953445    ada0  GPT  (954M)
        40     4096  ada0p1  efi  (2.0M)
      4136      128  ada0p2  freebsd-boot  (64K)
      4264    92120  ada0p3  freebsd-ufs  (45M)
     96384  1857101          - free -  (907M)
T;
is_same ('a 1 GB card gets none', datadisk_placement(datadisk_parse_gpart_show($cf), 512), null);

/* a 4K-native drive: gpart counts 4096-byte sectors */
$k4 = <<<T
=>       6  2097146    nvd0  GPT  (8.0G)
         6      512  nvd0p1  efi  (2.0M)
       518       16  nvd0p2  freebsd-boot  (64K)
       534    11515  nvd0p3  freebsd-ufs  (45M)
     12049  2085103          - free -  (8.0G)
T;
$p4 = datadisk_placement(datadisk_parse_gpart_show($k4), 4096);
is_same ('4K sectors: the start is still 240 MB in (sector 61440)', $p4['start'], 61440);
is_same ('4K sectors: 1 MB alignment is 256 sectors', $p4['size'] % 256, 0);

/* something after the free space -- not the end of the disk: refuse */
$mid = <<<T
=>      40  16777136    da0  GPT  (8.0G)
        40      4096  da0p1  efi  (2.0M)
      4136       128  da0p2  freebsd-boot  (64K)
      4264     92120  da0p3  freebsd-ufs  (45M)
     96384   8000000         - free -  (3.8G)
   8096384   8680792  da0p5  freebsd-ufs  (4.1G)
T;
is_same ('free space in the middle is not used', datadisk_placement(datadisk_parse_gpart_show($mid), 512), null);

/* already has its data partition, nothing free after it */
$done = <<<T
=>      40  16777136    da0  GPT  (8.0G)
        40      4096  da0p1  efi  (2.0M)
      4136       128  da0p2  freebsd-boot  (64K)
      4264     92120  da0p3  freebsd-ufs  (45M)
     96384    395136         - free -  (193M)
    491520  16285696  da0p4  freebsd-ufs  (7.8G)
T;
is_same ('an existing data partition is not duplicated', datadisk_placement(datadisk_parse_gpart_show($done), 512), null);

is_same ('garbage is not a table', datadisk_parse_gpart_show("gpart: Unknown command: show."), null);

exit(mw_report('datadisk.inc'));
