#!/usr/bin/env python3
# Author: Kees Cook <kees@ubuntu.com>
# Copyright (C) 2011 Canonical Ltd.
#
# Reports CVE counts fixed for each USN.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# Fetch the USN database first. Override location with --database
#  wget http://people.canonical.com/~ubuntu-security/usn/database.pickle
#
import functools, sys, optparse, usn_lib
from source_map import version_compare

parser = optparse.OptionParser()
parser.add_option("-v", "--verbose", dest="verbose", help="Report specific CVEs", action='store_true')
parser.add_option("-D", "--database", help="Specify location of USN data (default 'database.pickle')", default="database.pickle")
parser.add_option("-R", "--reverted", help="Specify location of reverted CVE list (default '%default')", default="meta_lists/reverted-CVEs.txt")
parser.add_option("-d", "--debug", dest="debug", help="Report additional debugging while processing USNs", action='store_true')
parser.add_option("-s", "--summary", help="Print summary at the end of total USNs and total unique CVEs from those USNs", action='store_true')
parser.add_option("--since", type=float, help="Report only USNs with timestamp after this (in seconds from UTC)", default=0)
parser.add_option("--before", type=float, help="Report only USNs with timestamp before this (in seconds from UTC)", default=sys.float_info.max)
parser.add_option("-r", "--release", help="Report only for USNs that affect the specified release")
(opt, args) = parser.parse_args()

reverted = usn_lib.get_reverted(opt.reverted)
db       = usn_lib.load_database(opt.database)

unique_cves     = set()
usns            = set()

for usn in sorted(db, key=functools.cmp_to_key(version_compare)):
    # This USN is ancient and lacks any CVE information
    if not 'cves' in db[usn]:
        if (opt.debug):
            print("%s lacks CVEs" % (usn))
        continue

    timestamp = db[usn]['timestamp']
    if timestamp > opt.before:
        if opt.debug:
            print("%s is too new (%f > %f)" % (usn, timestamp, opt.before))
        continue
    if timestamp < opt.since:
        if opt.debug:
            print("%s is too old (%f < %f)" % (usn, timestamp, opt.since))
        continue

    if opt.release is not None and opt.release not in db[usn]['releases']:
        if opt.debug:
            print("%s does not apply to release %s" % (usn, opt.release))
        continue

    usns.add(usn)
    # for some reason these are sometimes URLs
    cves = filter(lambda cve: cve.startswith('CVE'), db[usn]['cves'])
    for cve in cves:
        unique_cves.add(cve)
    print("USN-%s: %d" % (usn, len(list(cves))))
    if opt.verbose:
        for cve in sorted(cves):
            print("\t" + cve)

if opt.summary:
    print("%d USNs covering %d unique CVEs" % (len(usns), len(unique_cves)))
