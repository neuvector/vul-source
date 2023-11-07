#!/usr/bin/env python2

# Author: Kees Cook <kees@ubuntu.com>
# Author: Jamie Strandboge <jamie@ubuntu.com>
# Copyright (C) 2005-2008 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 2 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

import os
import re
import sys
import optparse
import cve_lib

import source_map
source_map = source_map.load()
releases = cve_lib.releases

parser = optparse.OptionParser()
parser.add_option("-S", "--skip-devel", help="Show only those CVEs *not* in the current devel release", action="store_true")
parser.add_option("-D", "--only-devel", help="Show only those CVEs in the current devel release", action="store_true")
parser.add_option("-m", "--only-supported", help="Show only those CVEs that are supported", action="store_true")
parser.add_option("-t", "--totals", help="Display totals", action="store_true")
parser.add_option("-d", "--debug", help="Report debug information while loading", action="store_true")
(opt, args) = parser.parse_args()

releases = cve_lib.releases
for eol in cve_lib.eol_releases:
    if eol in releases:
        releases.remove(eol)
if opt.skip_devel and len(cve_lib.devel_release)>0:
    releases.remove(cve_lib.devel_release)
if opt.only_devel:
    releases = [cve_lib.devel_release]

(cves, uems) = cve_lib.get_cve_list()
info = cve_lib.load_all(cves, uems)

# Who says Python is easier to read than Perl?  ;)
cves = [cve for cve in cves if
    info[cve].has_key('pkgs') and len([pkg for pkg in info[cve]['pkgs'].keys()
        if len([rel for rel in releases
            if info[cve]['pkgs'][pkg].has_key(rel) and
                info[cve]['pkgs'][pkg][rel][0] in ['needed','needs-triage'] and
                (not opt.only_supported or
                 cve_lib.is_supported(source_map, pkg, rel, info[cve]))])>0 ])>0]

def the_date(a):
    try:
        return info[a]['PublicDate']
    except:
        print "%s: %s" % (a, " ".join(info[a]))
        raise

for priority in ['untriaged'] + cve_lib.priorities:
    shown = False
    for cve in sorted(cves, key=the_date):
        if not info[cve].has_key('pkgs'):
            continue

        pkglist = set()
        for pkg in info[cve]['pkgs']:
            for cve_rel in cve_lib.releases + ['devel']:
                rel = cve_rel
                if cve_rel == 'devel':
                    rel = cve_lib.devel_release

                # Skip reporting on anything that doesn't exist
                if not info[cve]['pkgs'][pkg].has_key(cve_rel):
                    continue
                # Skip reporting on anything that is closed
                if info[cve]['pkgs'][pkg][cve_rel][0] in ['released','not-affected']:
                    continue
                # Skip if the pkg is not supported
                if opt.only_supported and not cve_lib.is_supported(source_map, pkg, rel, info[cve]):
                    continue

                # Only report if we have a matching priority
                this_priority = info[cve]['Priority'][0]
                if info[cve].has_key('Priority_%s' % (pkg)):
                    this_priority = info[cve]['Priority_%s' % (pkg)][0]
                if this_priority == priority:
                    pkglist.add(pkg)

        if len(pkglist):
            if not shown:
                print priority
                shown = True
            print "\t%s %s (%s)" % (info[cve]['PublicDate'], info[cve]['Candidate'], ", ".join(sorted(pkglist)))
