#!/usr/bin/env python2
#
# This script reports how many "updates" (CVEs per package per USN)
# happen per month and per year.
#
# Copyright (C) 2008-2016 Canonical, Ltd
# Author: Kees Cook <kees@ubuntu.com>
from __future__ import print_function

import cve_lib
import optparse
import os
import sys
import time
import usn_lib

import source_map
source_map = source_map.load()

config = cve_lib.read_config()
default_db = config['usn_db_copy']
if '-all' not in default_db:
    tmp = os.path.splitext(default_db)
    if len(tmp) == 2:
        default_db = "%s-all%s" % (tmp[0], tmp[1])

parser = optparse.OptionParser()
parser.add_option("--with-eol", help="Also show those CVEs in EOL releases", action="store_true", default=False)
parser.add_option("--db", help="Specify the USN database to load", metavar="FILENAME", default=default_db)
(opt, args) = parser.parse_args()

reverted = usn_lib.get_reverted()

if not os.path.exists(opt.db):
    print("Cannot read %s" % (opt.db), file=sys.stderr)
    sys.exit(1)
db = usn_lib.load_database(opt.db)

releases = cve_lib.releases
if opt.with_eol is False:
    for eol in cve_lib.eol_releases:
         if eol in releases:
             releases.remove(eol)

def report(epoch, usn, cve, pkg, rel, pri):
    print('%s: %s: %s: %s %s (%s)' % (time.strftime("%Y-%m-%d",time.gmtime(epoch)),usn, cve, pkg, pri, rel))

info = dict()

def _get_cve_priority(cve, pkg, rel):
    prio = 'unknown'
    if cve in info:
        prio = cve_lib.contextual_priority(info[cve], pkg, rel)[1]

    return prio

for usn in db:
    cves = []
    if 'cves' not in db[usn]:
        #print("Skipped USN lacking 'cves': %s" % (usn), file=sys.stderr)
        cves = ['unknownCVE']
    else:
        cves = db[usn]['cves']

    for cve in cves:
        if ' CVE' in cve:
            print("Bad CVE name (%s) in USN-%s" % (cve, usn), file=sys.stderr)
        #if not cve.startswith('CVE-'):
        #    print("Skipped weird CVE in USN-%s: %s" % (usn,cve), file=sys.stderr)
        #    continue
        ## Skip checking CVEs that were reverted for a given USN
        #if usn in reverted and cve in reverted[usn]:
        #    continue

        if cve.startswith('CVE') and cve not in info:
            try:
                info.setdefault(cve, cve_lib.load_cve(cve_lib.find_cve(cve)))
            except Exception as e:
                print("Skipping %s: %s" % (cve, str(e)), file=sys.stderr)
                continue

        for rel in db[usn]['releases']:
            if rel not in releases:
                continue

            if 'sources' not in db[usn]['releases'][rel]:
                if 'archs' not in db[usn]['releases'][rel]:
                    # Old USN, lacks either sources or archs, use first binary
                    pkg = db[usn]['releases'][rel]['binaries'].keys()[0]
                    report(db[usn]['timestamp'], usn, cve, pkg, rel,
                           _get_cve_priority(cve, pkg, rel))
                else:
                    for filename in db[usn]['releases'][rel]['archs']['source']['urls'].keys():
                        if filename.endswith('.dsc'):
                            pkg = filename.split('/').pop().split('_').pop(0)
                            report(db[usn]['timestamp'], usn, cve, pkg, rel,
                                   _get_cve_priority(cve, pkg, rel))
            else:
                for pkg in db[usn]['releases'][rel]['sources']:
                    report(db[usn]['timestamp'], usn, cve, pkg, rel,
                           _get_cve_priority(cve, pkg, rel))
