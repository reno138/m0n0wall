# Building the image

Everything here was verified on a FreeBSD 15.1-RELEASE amd64 machine. Each
prerequisite listed is one that actually caused a failure during development,
and most of them fail in a way that names something other than the real cause.

## What you need

- **FreeBSD 15.0 or later, amd64.** Not a cross-build. `buildworld`, `makefs`
  and `mkimg` are FreeBSD tools and there is no path to them from Linux.
- **4 GB RAM, 4 cores, 25 GB free.** The kernel build is the expensive part;
  the staging root for the third-party components is about 1.2 GB before it is
  trimmed.
- **The FreeBSD source tree** at `/usr/src`, matching your release.
- **Root.** Stages 1 to 3 populate a staging root and set ownership.

A virtual machine is fine. If you are on Proxmox, use VirtIO SCSI so disks
appear as `da0` and behave like ordinary SCSI under `camcontrol` and
`diskinfo`, which is the path the installer exercises.

## Preparing the host

```sh
# source tree, matching your release
pkg install -y git perl5
git clone -b releng/15.1 https://git.freebsd.org/src.git /usr/src

# the checkout of this project
git clone <this-repo> ~/m0n0wall-src

# a build root, with the source tree symlinked where the scripts expect it
mkdir -p ~/mw-build
ln -s ~/m0n0wall-src ~/mw-build/freebsd15
```

The symlink name matters: the scripts refer to `$MW_BUILDPATH/freebsd15`. It is
named for the FreeBSD release the tree targets, as the original was named
`freebsd8`.

## Building

```sh
env MW_BUILDPATH=$HOME/mw-build sh ~/mw-build/freebsd15/build/scripts/doall.sh
```

Images land in `$MW_BUILDPATH/images`:

| File | What it is |
|---|---|
| `generic-pc-<ver>.amd64.img` | gzipped disk image, `dd` it to the target |
| `generic-pc-<ver>.amd64.iso` | bootable CD, runs live and can install |
| `generic-pc-serial-<ver>.amd64.img` | same, console on serial |

Roughly 34 MB and 76 MB respectively. The build takes about 30 minutes, almost
all of it the kernel.

To run one stage at a time:

```sh
cd ~/mw-build/freebsd15/build/scripts
env MW_BUILDPATH=$HOME/mw-build sh 5makeimage.sh
```

## What each stage does

| Stage | Does | Needs a rebuild when |
|---|---|---|
| 1 | image root from the FreeBSD base system, via a file manifest plus its `ldd` closure | you change `minibsd/m0n0wall.files` |
| 2 | third-party components, extracted from a throwaway package root by `ldd` closure | you change the component list |
| 3 | m0n0wall's own helper scripts; builds nothing any more | rarely |
| 4 | the kernel, from `build/kernelconfigs/M0N0WALL_GENERIC.amd64` | you change the kernel config |
| 5 | assembles the images | always, it is the cheap one |

Stage 4 is the slow one. If you are iterating on the userland, run 1, 2, 3 and
5 and leave the kernel alone.

## Two things that will confuse you

**The kernel config contains entries no driver line references.** `iflib`,
`hid`, `hidbus` and `usbhid` look like dead weight and are not. FreeBSD has
been splitting shared infrastructure out of the drivers that use it, and the
dependency is invisible at the point of use. Removing `iflib` fails the build
with `'ifdi_if.h' file not found` from inside `dev/e1000`; removing the HID
entries compiles cleanly and then fails at *link* with undefined `hid_locate`.
The config has a header explaining this. Delete them only after a clean build
proves they are unused.

**The image is built from the host's boot components.** Stage 5 copies
`/boot/loader.efi`, `/boot/gptboot`, `/boot/pmbr` and `/boot/cdboot` from the
running system. Whatever your build host has is what ships, so build on a host
at the release you intend to target. Detach any installation media from the
build host too: anything mounted is a contamination risk.

## Image layout

GPT, and the same image boots both firmware types:

```
p1  efi           2 MB   FAT with /EFI/BOOT/BOOTX64.EFI      -> UEFI
p2  freebsd-boot  61 KB  gptboot, reached via the pmbr       -> legacy BIOS
p3  freebsd-ufs   rest   kernel.gz, mfsroot.gz, boot/, conf/
```

Nothing detects anything: UEFI firmware finds the ESP, BIOS runs the
bootstrap in the protective MBR. Each ignores the other's path. The installer
also registers an NVRAM boot entry with `efibootmgr`, because
`/EFI/BOOT/BOOTX64.EFI` is officially the removable-media fallback and not all
firmware tries it for a fixed disk.

The root is a compressed filesystem unpacked into RAM at boot, which is why
image size is memory cost and why the build goes to such lengths to stay
small. Installing the component packages directly rather than extracting their
`ldd` closure produces a 1.1 GB root — larger than the pfSense and OPNsense
installers, and unbootable on the hardware this targets.

## Changing what is in the image

**Adding a base-system binary:** add it to `build/minibsd/m0n0wall.files`. One
entry per line, relative to `/`, with `:` separating hardlink aliases. Its
libraries are resolved automatically. Note that the manifest historically did
*not* list `ifconfig`, because stage 3 used to install a patched copy by hand.

**Adding a third-party component:** add the package to `PKGS` in
`2makebinaries.sh` and the binaries you want to `WANT_BIN`. Only what you name
is copied; the rest of the package stays in the staging root. Verify the paths
against the package itself rather than assuming — strongSwan puts `charon` in
`libexec/ipsec`, not `sbin`.

**Adding a kernel driver:** edit `build/kernelconfigs/M0N0WALL_GENERIC.amd64`
and re-run stage 4.

## Licence

m0n0wall is BSD 2-Clause, Copyright (C) 2003-2007 Manuel Kasper
<mk@neon1.net>. Those notices stay in every file that carries them. The git
history is converted from the original Subversion repository, so authorship is
intact back to 2006.
