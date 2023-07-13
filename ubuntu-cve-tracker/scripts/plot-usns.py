#!/usr/bin/env python2
#
# This script produces plot data for how many source packages were fixed
# each month.
#
# Copyright (C) 2008 Canonical, Ltd
# Author: Kees Cook <kees@ubuntu.com>
# License: GPLv3
import sys, time, usn_lib, cve_lib
import optparse
import cve_lib

import pprint
pp = pprint.PrettyPrinter(indent=4)

parser = optparse.OptionParser()
parser.add_option("--target", help="What target to graph: 'usn'(default), 'cve', 'src', 'bin'", metavar="TARGET", action='store', default='usn')
parser.add_option("--release", help="What release to include (default is all)", metavar="RELEASE", action='store', default=None)
parser.add_option("--release-multiply", help="Multiply USN counts by number of releases updated for that USN", action='store_true', default=False)
parser.add_option("--cve-multiply", help="Multiply USN counts by number of CVEs updated for that USN", action='store_true', default=False)
(opt, args) = parser.parse_args()

if opt.target not in ['usn','src','bin','cve']:
    print >>sys.stderr, "Unknown target '%s'" % (opt.target)
    sys.exit(1)

config = cve_lib.read_config()
db = None
db_filename = config['usn_db_copy']
if len(args) > 0:
    db_filename = args.pop(0)
db = usn_lib.load_database(db_filename)

columns = ['total', 'untriaged'] + cve_lib.priorities

cves = dict()
if opt.target == 'cve':
    cve_lib.read_config()

months = dict()
month_cves = dict()
for usn in sorted(db.keys()):
    when = time.strftime('%Y-%m', time.gmtime(int(db[usn]['timestamp'])))
    months.setdefault(when, dict())
    for column in columns:
        months[when].setdefault(column ,0)
    month_cves.setdefault(when, 0)

    if opt.target == 'usn':
        if opt.release and opt.release not in db[usn]['releases']:
            continue

        count = 1

        if opt.cve_multiply and db[usn].has_key('cves'):
            cve_count = 1
            for cve in db[usn]['cves']:
                # Skip non-CVEs:
                if not cve.startswith('CVE'):
                    continue
                cve_count += 1
            count *= cve_count

        if opt.release_multiply:
            release_count = len(db[usn]['releases'])
            if release_count < 1:
                release_count = 1
            count *= release_count

        months[when]['total'] += count

    else:
        if opt.target == 'cve':
            if not db[usn].has_key('cves'):
                continue
            for cve in db[usn]['cves']:
                # Skip non-CVEs:
                if not cve.startswith('CVE'):
                    continue
                if opt.release and opt.release not in db[usn]['releases']:
                    continue
                if not cves.has_key(cve):
                    try:
                        cves.setdefault(cve,cve_lib.load_cve(cve_lib.find_cve(cve)))
                    except Exception, e:
                        print >> sys.stderr, "Skipping %s: %s" % (cve, str(e))
                        continue
                months[when]['total'] += 1
                months[when][cves[cve]['Priority'][0]] += 1
        else:
            for rel in db[usn]['releases']:
                if opt.release and rel != opt.release:
                    continue

                if opt.target == 'src':
                    if not db[usn]['releases'][rel].has_key('sources'):
                        # Assume that the early USNs updated 1 srcpkg per release
                        months[when]['total'] += 1
                        #pp.pprint(db[usn])
                        continue
                    for pkg in db[usn]['releases'][rel]['sources']:
                        months[when]['total'] += 1
                elif opt.target == 'bin':
                    if not db[usn]['releases'][rel].has_key('binaries'):
                        # Assume that the early USNs updated 1 binpkg per release
                        months[when]['total'] += 1
                        #pp.pprint(db[usn])
                        continue
                    for pkg in db[usn]['releases'][rel]['binaries']:
                        months[when]['total'] += 1

print '# date',
for column in columns:
    print column,
print
for month in sorted(months.keys()):
    print month,
    for column in columns:
        print months[month][column],
    print
