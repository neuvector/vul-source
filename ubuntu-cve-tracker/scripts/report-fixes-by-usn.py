#!/usr/bin/env python3
# Author: Kees Cook <kees@ubuntu.com>
# Copyright (C) 2008 Canonical Ltd.
#
# Reports which CVEs were fixed for a given release and source package
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# Fetch the USN database first. Override location with --database
#  wget http://people.canonical.com/~ubuntu-security/usn/database.pickle
#
import sys, optparse, textwrap, re, functools
import usn_lib, cve_lib
from source_map import version_compare

parser = optparse.OptionParser()
#parser.add_option("-v", "--verbose", dest="verbose", help="Report logic while processing USNs", action='store_true')
parser.add_option("-D", "--database", help="Specify location of USN data (default '%default')", default="database.pickle")
parser.add_option("-R", "--reverted", help="Specify location of reverted CVE list (default '%default')", default="meta_lists/reverted-CVEs.txt")
parser.add_option("-p", "--priority", dest="priority", help="Comma separated list of priorities to report (default: all)", action='store')
parser.add_option("-L", "--description", dest="description", help="Description regex to report", action='store')
parser.add_option("-d", "--debug", dest="debug", help="Report additional debugging while processing USNs", action='store_true')
parser.add_option("-s", "--summary", dest="summary", help="Provide a summary including USN, CVEs and packages count", action='store_true')
parser.add_option("--since", type=float, help="Report only USNs with timestamp after this (in seconds from UTC)",
                      default=0)
parser.add_option("--before", type=float, help="Report only USNs with timestamp before this (in seconds from UTC)",
                      default=sys.float_info.max)
parser.add_option("-r", "--release", dest="release", help="Report only USNs affecting this release")
parser.add_option("-P", "--source-package", dest="src", help="Report only USNs affecting this source package")
parser.add_option("--version-after", dest="version_after", help="Report only USNs affecting versions of the source package after the specified one")
parser.add_option("--version-last", dest="version_last", help="Report only USNs affecting versions of the source package up to and including this specified one")
(opt, args) = parser.parse_args()

reverted = usn_lib.get_reverted(opt.reverted)
db       = usn_lib.load_database(opt.database)

report_priorities = opt.priority
if report_priorities:
    report_priorities = opt.priority.split(',')

# Report CVEs fixed _after_ the "after" version, up to and including "last"
# i.e. (after,last]
unique_cves = set()
usns = []
for usn in sorted(db, key=functools.cmp_to_key(version_compare)):
    # This USN is ancient and lacks any CVE information
    if not 'cves' in db[usn]:
        if (opt.debug):
            print("%s lacks CVEs" % (usn))
        continue
    # This USN did not include any updates for the requested release
    if not opt.release in db[usn]['releases']:
        if (opt.debug):
            print("%s lacks release for %s" % (usn, opt.release))
        continue
    # This USN is ancient and lacks source package information
    if not 'sources' in db[usn]['releases'][opt.release]:
        if (opt.debug):
            print("%s lacks source packages for %s" % (usn, opt.release))
        continue
    # This USN did not include updates for the requested package
    if opt.src and not opt.src in db[usn]['releases'][opt.release]['sources']:
        if (opt.debug):
            print("%s lacks update for %s (%s)" % (usn, opt.src, ", ".join(db[usn]['releases'][opt.release]['sources'].keys())))
        continue

    usn_timestamp = db[usn]['timestamp']
    if usn_timestamp > opt.before:
        if opt.debug:
            print
            "Discarding USN in result as its timestamp is grater than --before %s (%f > %f)" % (
            usn, usn_timestamp, opt.before)
        continue
    if usn_timestamp < opt.since:
        if opt.debug:
            print
            "Discarding USN in result as its timestamp is less than --since  %s (%f < %f)" % (usn, usn_timestamp, opt.since)
        continue

    usns.append(usn)

    version = None
    if opt.src:
        version = db[usn]['releases'][opt.release]['sources'][opt.src]['version']
    if not opt.src or  (version_compare(version, opt.version_after)>0 and \
                    version_compare(version, opt.version_last)<=0):
        report = 'USN-%s' % (usn)
        if version:
            report += ' (%s)' % (version)
        else:
            report += ' (%s)' % (", ".join(["%s %s" % (x, db[usn]['releases'][opt.release]['sources'][x]['version']) for x in db[usn]['releases'][opt.release]['sources']]))
        cves = []

        for cve in sorted(db[usn]['cves']):
            info = None
            if cve.startswith("CVE-") and usn in usns:
                unique_cves.add(cve)
            if report_priorities or opt.description:
                # Skip non-CVEs and missing CVEs.
                try:
                    filename = cve_lib.find_cve(cve)
                    info = cve_lib.load_cve(filename)
                except:
                    continue
            if report_priorities:
                specificity, cve_priority = cve_lib.contextual_priority(info, opt.src, opt.release)
                # Skip CVEs that we aren't interested in.
                if not cve_priority in report_priorities:
                    continue
                cve = "%s (%s)" % (cve, cve_priority)
            if opt.description:
                text = info.get('Ubuntu-Description', info['Description']).strip()
                # Skip CVEs that do not match the description we're interested in.
                if not re.search(opt.description, text):
                    continue
                text = textwrap.fill(text, 60)
                cve += "\n\t\t%s" % ("\n\t\t".join(text.splitlines()))
            cves.append(cve)
        if len(cves) > 0:
            if not opt.summary:
                print(report)
                print("\t%s" % ("\n\t".join(cves)))

if opt.summary:
    print("USNs published for %s: %d " % (opt.release, len(usns)))
    print("USNs: %s" % " ".join(usns))
    print("Unique CVEs fixed for %s: %d " % (opt.release, len(unique_cves)))
    print("CVEs: %s" % " ".join(unique_cves))
