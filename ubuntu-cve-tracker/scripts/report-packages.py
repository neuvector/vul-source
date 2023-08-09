#!/usr/bin/env python3

# Author: Kees Cook <kees@ubuntu.com>
# Copyright (C) 2009 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# Reports the packages fixed for a given release, along with their CVEs.
#
# ./scripts/report-packages.py hardy
#
# export REL="hardy"; export NAMED=10; (./scripts/report-packages.py --action plot $REL | sort -n -k 8 | awk '{print $1 " " $8}' | tail -n $NAMED; echo -n "others "; ./scripts/report-packages.py --action plot $REL | sort -n -k 8 | head -n -$NAMED | awk '{ sum+=$8 }END{print sum}') | ./scripts/pie-chart.py ; scp pie.png vinyl:outflux.net/html/

from __future__ import print_function

import os
import sys
import optparse

import cve_lib
import usn_lib

import source_map
source_map = source_map.load()
releases = cve_lib.releases
config = cve_lib.read_config()

parser = optparse.OptionParser()
parser.add_option("-S", "--skip-devel", help="Show only those CVEs *not* in the current devel release", action="store_true")
parser.add_option("-D", "--only-devel", help="Show only those CVEs in the current devel release", action="store_true")
parser.add_option("--db", help="Specify the USN database to load", metavar="FILENAME", default=config['usn_db_copy'])
parser.add_option("-d", "--debug", help="Report debug information while loading", action="store_true")
parser.add_option("--priority", help="Report only CVEs with a matching priority", action="store", metavar="PRIORITY")
parser.add_option("--action", help="Change report style ('list'(default), 'plot'", action="store", metavar="ACTION", default='list')
(opt, args) = parser.parse_args()

if not os.path.exists(opt.db):
    print("Cannot read %s" % (opt.db), file=sys.stderr)
    sys.exit(1)
db = usn_lib.load_database(opt.db)

releases = cve_lib.releases
for eol in cve_lib.eol_releases:
    if eol in releases:
        releases.remove(eol)
if opt.skip_devel and len(cve_lib.devel_release)>0:
    releases.remove(cve_lib.devel_release)

if opt.only_devel:
    releases = [cve_lib.devel_release]

# Global CVE info cache
info = dict()

release = None
if len(args)>0:
    release = args[0]
if release and release not in releases:
    raise ValueError("'%s' must be one of '%s'" % (release, "', '".join(releases)))

def fixed_map(priority=None):
    fixed = dict()
    for usn in sorted(db.keys()):
        if 'cves' not in db[usn]:
            continue
        for cve in db[usn]['cves']:
            if not cve.startswith('CVE-'):
                continue

            if not release or release in db[usn]['releases']:
                # Load CVE if it isn't already cached
                if cve not in info:
                    try:
                        info.setdefault(cve, cve_lib.load_cve(cve_lib.find_cve(cve)))
                    except Exception as e:
                        print("Skipping %s: %s" % (cve, str(e)), file=sys.stderr)
                        continue
                # Skip those without PublicDates for the moment
                if info[cve]['PublicDate'].strip() == "":
                    print("%s: empty PublicDate" % (cve), file=sys.stderr)
                    continue

                # Check priority
                # from the all releases or a specific release, find the
                # mapping of CVE priority based on the package that was
                # fixed in the USN.  In the case of multiple match, first
                # most specific wins.
                for rel in db[usn]['releases']:
                    if not release or release == rel:
                        if 'sources' in db[usn]['releases'][rel]:
                            for pkg in db[usn]['releases'][rel]['sources']:

                                # For now, hard-code list of source packages
                                # we're ignoring.  This will need to be dealt
                                # with in a better way once we have a fuller
                                # understanding of the ramifications of having
                                # multiple source packages for the kernel.
                                if pkg in ['linux-mvl-dove','linux-fsl-imx51','linux-ec2','linux-qcm-msm','linux-ti-omap', 'linux-armadaxp'] and 'linux' in db[usn]['releases'][rel]['sources']:
                                    continue
                                # Skip updates duplicated in firefox
                                if pkg in ['xulrunner-1.9.2','thunderbird'] and 'firefox' in db[usn]['releases'][rel]['sources']:
                                    continue

                                specificity, cve_priority = cve_lib.contextual_priority(info[cve], pkg, rel)
                                if type(cve_priority) == list:
                                    cve_priority = cve_priority[0]
                                if not priority or cve_priority == priority:
                                    report_pkg = pkg
                                    if pkg in cve_lib.pkg_alternates:
                                        report_pkg = cve_lib.pkg_alternates[pkg]
                                    fixed.setdefault(report_pkg, dict())
                                    fixed[report_pkg].setdefault(cve_priority, set())
                                    fixed[report_pkg][cve_priority].add(cve)
    return fixed

priorities = ['untriaged'] + cve_lib.priorities

if opt.action == 'list':
    fixed = fixed_map(opt.priority)
    for pkg in fixed:
        print(pkg)
        for priority in priorities:
            count = 0
            cves = []
            if priority in fixed[pkg]:
                count = len(fixed[pkg][priority])
                cves = sorted(fixed[pkg][priority])
            print("\t%s(%d): %s" % (priority, count, " ".join(cves)))
elif opt.action == 'plot':
    fixed = fixed_map(opt.priority)
    for pkg in fixed:
        print(pkg, end=' ')
        total = 0
        for priority in priorities:
            count = 0
            if priority in fixed[pkg]:
                count = len(fixed[pkg][priority])
            print(count, end=' ')
            total += count
        print(total)
else:
    raise ValueError("No such --action '%s'" % (opt.action))

