# m0n0wall, modernized

[m0n0wall](https://m0n0.ch/wall/) was a small FreeBSD firewall: a read-only
root, one XML config file and a PHP webGUI, built for CompactFlash on
Soekris/ALIX boards. Manuel Kasper ended the project in February 2015; the
last commit (r576, `branches/freebsd8`) signs off with "Goodbye M0n0wall :(".

This repository picks it up from there. The goal is to **keep the look and
behaviour of m0n0wall and replace everything underneath it** with things that
are maintained today. It is an unofficial continuation and is not affiliated
with the original authors.

> **Status: development.** It builds, installs, and runs in a VM. Everything
> listed below has been exercised on a running test box, but it has not
> carried production traffic. Real IPv6 transit and DHCP-PD against an ISP are
> untested.

## What changed

| Area | m0n0wall 1.8.x | Here |
|---|---|---|
| OS | FreeBSD 8.4 | FreeBSD 15.1, amd64 |
| Packet filter | ipfilter | **pf** (ipfw + dummynet kept for the traffic shaper) |
| PHP | 4.4.9 | 8.4 |
| Web server | mini_httpd | lighttpd |
| IPsec | racoon | strongSwan (IKEv2 / AES-256 / SHA-256 / DH14 defaults) |
| DHCP server | ISC dhcpd 4.1 | dnsmasq (already in the image for DNS) |
| Dynamic DNS | ez-ipupdate | built-in PHP over HTTPS |
| SNMP | ucd-snmp 4.2 | net-snmp |
| VPN | PPTP | **removed** (insecure); native WireGuard (`wg(4)`) added |
| Logs | RAM only | optional persistent data partition at the end of the boot disk |

The old size limit is gone. 12 MB made sense for 128 MB of RAM and a
CompactFlash card; the architecture is still minimal (read-only root, one
`config.xml`), but the image budget is now 120 MB.

Other things worth knowing:

- **The pf ruleset is generated from the same config the ipfilter one was.**
  `phpconf/inc/filter_pf.inc` produces it, and `tests/compare_ipf_pf.php`
  checks it against the original generator's output. (ipf's `><` port range is
  exclusive; pf's `lo:hi` is inclusive. Copying the arithmetic would widen
  every ranged rule by one port at each end.)
- **Optional interfaces keep their names.** Deleting `opt2` no longer renames
  `opt3` to `opt2` behind the backs of the DHCP ranges and firewall rules that
  refer to it.
- **WAN, VLAN and IPv6 changes apply live.** Only re-plugging the LAN still
  needs a reboot.
- **Firmware images are signed with your own key**, generated on the build
  host the first time you build. Back it up: an installed box only accepts
  upgrades signed by the key it was built with.
- **Several silent upstream bugs are fixed.** Two examples: a firewall rule
  with destination "L2TP clients" was never emitted, and the boot-time WAN
  setup looped forever on any NIC that exists.

## Building

See [BUILDING.md](BUILDING.md). It needs a FreeBSD 15 amd64 host; it does not
cross-build from Linux. A full userland rebuild takes a few minutes, while the
kernel stage takes longer.

## Tests

```sh
sh tests/run.sh          # PHP=/path/to/php to pick a binary
```

The suites run off-target on any PHP 8.4+ (Linux included): a syntax check of
every PHP file, then around 900 unit tests covering the pf generator,
config parsing, DHCP, IPsec, WireGuard, IPv6, VLANs, the shaper and the
captive portal. The build adds gates the unit tests cannot cover: every ELF
must load under the image's own runtime linker, and every PHP function called
must exist in the image's PHP.

## History and branches

The git history is converted from the original Subversion repository, so
authorship goes back to 2006 intact.

- `main`: this work, on top of upstream's final commit.
- `freebsd8`: upstream's last code (1.8.x, r576). Note that `freebsd8` is
  newer than `freebsd10`, which was started and abandoned in 2014.
- `freebsd10`, `freebsd6`, `freebsd5`, `1.23`: older upstream branches.
  `freebsd5` was deleted in SVN and recovered by the conversion.
- `release-*` tags: the upstream release tags.

`CHANGELOG` is upstream's and stops at 1.8.2b. Changes since then are in the
git log.

## Licence

BSD 2-Clause; see [LICENSE](LICENSE). Copyright (C) 2003-2007 Manuel Kasper
and the m0n0wall contributors. Their notices stay in every file that carries
them.
