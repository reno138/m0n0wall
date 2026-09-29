#!/usr/bin/perl

# $Id$

# arguments: source_tree dest_tree

use File::Copy;
use File::Basename;
use File::Path qw(make_path);

# Failures used to be printed and ignored, so a build could finish "successfully"
# with a file missing from the image (lib/geom/geom_part.so: its directory did
# not exist, copy() failed, the build went on). Now they are counted, and the
# exit status says so; the caller stops the build.
my $errors = 0;

exit unless $#ARGV == 2;

print "Populating MiniBSD tree: $ARGV[2]\n";

# populate_tree(treefile, srcpath, destpath)
sub populate_tree {
	my @args = @_;
	
	open TREEFILE, $args[0];
	
	TREE: while (<TREEFILE>) {
		
		next TREE if /^#/;
		next TREE if /^ *$/;
		# ldd lists the kernel's vDSO as "[vdso] (0x...)": not a file, nothing
		# to copy. It was reported as a copy error on every build.
		next TREE if /^\s*\[vdso\]/;
		
		@srcfiles = split(/:/);
		chomp @srcfiles;

		$srcfile = shift(@srcfiles);
		@srcstat = stat($args[1] . "/" . $srcfile);		

		if (! -e $args[2] . "/" . $srcfile) {
			# the destination directory may not exist yet (lib/geom/)
			make_path(dirname($args[2] . "/" . $srcfile));
			if (copy($args[1] . "/" . $srcfile, $args[2] . "/" . $srcfile)) {
				printf "Copy $args[1]/$srcfile -> $args[2]/$srcfile ($srcstat[4]/$srcstat[5]/%04o)\n", ($srcstat[2] & 07777);
				chown $srcstat[4], $srcstat[5], $args[2] . "/" . $srcfile;
				chmod $srcstat[2] & 07777, $args[2] . "/" . $srcfile;
			} else {
				print "ERROR while copying file $args[1]/$srcfile\n";
				$errors++;
			}
		} else {
			printf "Skipping as exists; Copy $args[1]/$srcfile -> $args[2]/$srcfile ($srcstat[4]/$srcstat[5]/%04o)\n", ($srcstat[2] & 07777);
		}
		foreach $lnfile (@srcfiles) {
			if (link($args[2] . "/" . $srcfile, $args[2] . "/" . $lnfile)) {
				print "Link $args[2]/$srcfile -> $args[2]/$lnfile\n";
			} else {
				print "ERROR while linking file $args[2]/$srcfile\n";
				$errors++;
			}
		}
	}
}

populate_tree $ARGV[0], $ARGV[1], $ARGV[2];

if ($errors) {
	print "$errors file(s) could not be copied or linked -- see ERROR lines above\n";
	exit 1;
}
exit 0;
