#!/usr/bin/env python2
#
# This script attempts to perform several actions:
#  1) load all package details
#  2) load all CVE details
#  3) write out state files for all packages (only if their state changes)
#  4) write out a file list of all changed non-CVE packages
#  5) produce a Makefile for:
#     a) all CVE-open source packages
#     b) a single execution of all unaffected packages
#
# Copyright 2009-2018 Canonical, Ltd.
# Author: Kees Cook <kees@ubuntu.com>
# Author: Steve Beattie <sbeattie@ubuntu.com>
# License: GPLv3
import sys, os
import cve_lib
import source_map
import html_export

# Build target directory tree
target = os.environ['TARGET']
if not os.path.exists(target):
    os.mkdir(target)
rawdir = os.path.join(target,'.raw')
if not os.path.exists(rawdir):
    os.mkdir(rawdir)

map = source_map.load()

# Generate list of all CVEs
(cves, uems) = cve_lib.get_cve_list()
# Drop all embargoed CVEs
for cve in uems:
    if cve in cves:
        cves.remove(cve)
uems = []
# Load all active CVEs
cveinfo = cve_lib.load_all(cves, uems)

# Makefile preamble
print '''SCRIPTS=$(shell echo $$SCRIPTS)
TARGET=$(shell echo $$TARGET)
PKGOUT=$(shell echo $$TARGET)/pkg
ACTIVE=$(shell echo $$ACTIVE)
GIT_COMMIT=$(shell git rev-parse HEAD)
'''

#  cveinfo:  cve ->
#       dict( fields...
#             'pkgs' -> dict(  pkg -> dict(  release ->  (state, notes)   ) )

pkginfo = dict()
# Build list of packages that have CVEs
for cve in cves:
    for pkg in cveinfo[cve]['pkgs']:
        # Aliases: "linux-source-2.6.15" should appear in "linux" output...
        pkg_list = [pkg]
        if cve_lib.pkg_aliases.has_key(pkg):
            pkg_list += cve_lib.pkg_aliases[pkg]
        for report_pkg in pkg_list:
            # Validate that this pkg exists at least in one release where it is
            # still "needed" in some way.
            skip = True
            if cveinfo[cve]['pkgs'].has_key(report_pkg):
                for rel in html_export.releases:
                    pkgrel = rel
                    if rel == cve_lib.devel_release:
                        pkgrel = 'devel'
                    if cveinfo[cve]['pkgs'][report_pkg].has_key(pkgrel) and cveinfo[cve]['pkgs'][report_pkg][pkgrel][0] not in cve_lib.status_closed:
                        skip = False
            if not skip:
                # This uses "pkg" not "report_pkg" since it is a possible alias
                pkginfo.setdefault(pkg,set())
                pkginfo[pkg].add(cve)

# Generate list of all source packages not affected by CVEs
pkgs = set()
clean = set()
for rel in html_export.releases:
    for pkg in map[rel].keys():
        if pkg not in pkginfo:
            clean.add(pkg)
        pkgs.add(pkg)
# Look for packages listed the in the active CVEs, but not yet in the archive.
# Normally, this isn't possible, but can happen for things like new LTS
# backport kernels.
for pkg in pkginfo:
    if pkg not in pkgs:
        pkgs.add(pkg)
        print '# forcing "%s" to exist' % (pkg)

# For each package, load raw status, compare, and re-write if it changed.
# If the package lacks CVEs and it changed, add to the "need_cleaning" list.
need_cleaning = set()
need_forced_update = set()
for pkg in sorted(pkgs):
    status = set()
    update = False

    status_file = os.path.join(rawdir,pkg)
    if not os.path.exists(status_file):
        # If it doesn't exist, we must update it
        update = True
    else:
        for line in file(status_file):
            status.add(line.strip())

    # If our status differs from the on-disk, we must update
    if pkg in pkginfo:
        for cve in pkginfo[pkg]:
            if cve not in status:
                update = True
    for cve in status:
        if pkg in pkginfo:
            if cve not in pkginfo[pkg]:
                update = True
                # A CVE was removed from the list, this must trigger
                # an update to remove it from the summary in the case
                # of none of the remaining CVEs having changed.
                need_forced_update.add(pkg)
        else:
            # Went from something (status populated) to nothing (pkginfo empty)
            update = True

    # Perform update if needed
    if update:
        out = file(status_file+'.new','w')
        if pkg in pkginfo:
            for cve in sorted(pkginfo[pkg]):
                print >>out, cve
        else:
            # This is a pkg without CVEs open any more
            need_cleaning.add(pkg)
        out.close()
        os.rename(status_file+'.new', status_file)

# Append to the need_cleaning file to trigger regeneration of specific subset
# of needed files.
need_cleaning_file = os.path.join(target, '.need_cleaning')
out = file(need_cleaning_file,'a')
for pkg in sorted(need_cleaning):
    print >>out, pkg
out.close()

# Output list of dirty packages
print "DIRTY = \\"
for pkg in sorted(pkginfo):
    print "\t$(PKGOUT)/%s.html \\" % (pkg)
print ""

# Print default target
print '''all: $(DIRTY)

# This creates the base html output directory
$(PKGOUT)/.stamp:
\tmkdir -p $(dir $@)
\ttouch $@

# This is to trigger a rebuild of all non-CVE packages if the HTML export
# script changes.
$(PKGOUT)/.force_cleaned: $(SCRIPTS)/html_export.py $(PKGOUT)/.stamp
\tcd $(TARGET)/.raw/ && find . -type f -size 0 | xargs $(SCRIPTS)/html-export-pkg.py --commit $(GIT_COMMIT) --cveless $(PKGOUT)
\ttouch $@ $(PKGOUT)/.cleaned

# This triggers updating of all known changed non-CVE packages.
$(PKGOUT)/.cleaned: $(TARGET)/.need_cleaning $(PKGOUT)/.force_cleaned
\tcat $(TARGET)/.need_cleaning | xargs $(SCRIPTS)/html-export-pkg.py --commit $(GIT_COMMIT) --cveless $(PKGOUT)
\tcat /dev/null > $(TARGET)/.need_cleaning
\ttouch $@
'''

# Print per-dirty-package targets
for pkg in sorted(pkginfo):
    cve_str = " ".join(['$(ACTIVE)/%s' % (x) for x in sorted(pkginfo[pkg])])
    triggers = "$(SCRIPTS)/html_export.py"
    if pkg in need_forced_update:
        triggers += " $(TARGET)/.pkgs-makefile"
    print '''$(PKGOUT)/%s.html: $(PKGOUT)/.cleaned %s %s
\t$(SCRIPTS)/html-export-pkg.py --commit $(GIT_COMMIT) $(shell basename $@ .html) %s > $@.tmp
\tmv $@.tmp $@
''' % (pkg, triggers, cve_str, cve_str)
