#!/usr/bin/env python2
#
# This script reports how many CVEs and packages a given set of USNs
# touched.
#
# Copyright (C) 2008-2009 Canonical, Ltd
# Author: Kees Cook <kees@ubuntu.com>
from __future__ import print_function

import sys, time, usn_lib
import optparse

parser = optparse.OptionParser()
parser.add_option("--prose", help="Report in prose instead of just numbers.", action='store_true')
parser.add_option("--plain", help="Report only the numbers.", action='store_true')
(opt, args) = parser.parse_args()


reverted = usn_lib.get_reverted()
db = None
db_filename = None
try:
    db_filename = args.pop(0)
    db = usn_lib.load_database(db_filename)
except:
    print("Need to specify the database (eg database.pickle)", file=sys.stderr)
    sys.exit(1)

cves = set()
srcs = set()
usns = args
for usn in usns:
    if usn not in db:
        print("USN-%s not found in %s" % (usn, db_filename), file=sys.stderr)
        continue
    for cve in db[usn]['cves']:
        if not cve.startswith('CVE-'):
            continue
        cves.add(cve)

    for rel in db[usn]['releases']:
        try:
            for pkg in db[usn]['releases'][rel]['sources']:
                srcs.add(pkg)
        except:
            print("Warning: %s (release %s) lacks source packages?!" % (usn, rel), file=sys.stderr)
            pass

usn_count = len(usns)
cve_count = len(cves)
src_count = len(srcs)

def pluralize(count,singular,plural=None):
    if count == 1:
        return singular
    else:
        if plural:
            return plural
        else:
            return singular + "s"

if opt.prose:
    # We published 29 Ubuntu Security Notices which fixed 63 security issues
    # (CVEs) across 30 supported packages.
    print('Published %d %s which fixed %d %s (%s) %s %d %s.' % \
         (
            usn_count, pluralize(usn_count,'Ubuntu Security Notice'),
            cve_count, pluralize(cve_count,'security issue'),
                       pluralize(cve_count,'CVE'),
            pluralize(src_count,'in','across'),
            src_count, pluralize(src_count,'supported package')
         ))
elif opt.plain:
    print('%d %d %d' % ( usn_count, cve_count, src_count ))
else:
    #echo "$usns USN$usn_plural published covering $cves CVE$cve_plural in $pkgs supported package$pkg_plural"
    print('%d %s published covering %d %s in %d supported %s.' % \
        (
            usn_count, pluralize(usn_count,"USN"),
            cve_count, pluralize(cve_count,"CVE"),
            src_count, pluralize(src_count,"package")
        ))
