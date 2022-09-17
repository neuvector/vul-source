#!/usr/bin/env python2

# Author: Kees Cook <kees@ubuntu.com>
# Copyright (C) 2011-2013 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# Reports the latest version of a given source packages known to the USN db.
#
# ./scripts/report-version.py linux precise
#
from __future__ import print_function

import os
import sys
import optparse
import cve_lib
import usn_lib

import apt_pkg
apt_pkg.init_system()

releases = cve_lib.releases
esm_releases = cve_lib.esm_releases + cve_lib.esm_infra_releases
config = cve_lib.read_config()

parser = optparse.OptionParser()
parser.add_option("--db", help="Specify the USN database to load", metavar="FILENAME", default=config['usn_db_copy'])
parser.add_option("-d", "--debug", help="Report debug information while loading", action="store_true")
(opt, args) = parser.parse_args()

if not os.path.exists(opt.db):
    print("Cannot read %s" % (opt.db), file=sys.stderr)
    sys.exit(1)
db = usn_lib.load_database(opt.db)

releases = cve_lib.releases
for eol in cve_lib.eol_releases:
    if eol in releases:
        releases.remove(eol)
if len(cve_lib.devel_release) > 0:
    releases.remove(cve_lib.devel_release)

src = args[0]

release = None
if len(args) > 1:
    release = args[1]
if release and release not in releases and release not in esm_releases:
    raise ValueError("'%s' must be one of '%s'" % (release, "', '".join(releases + esm_releases)))

highest = '~'
for usn in sorted(db.keys()):
    if not release or release in db[usn]['releases']:
        for rel in db[usn]['releases']:
            if not release or release == rel:
                if 'sources' in db[usn]['releases'][rel]:
                    if src in db[usn]['releases'][rel]['sources']:
                        version = db[usn]['releases'][rel]['sources'][src]['version']
                        if apt_pkg.version_compare(version, highest) > 0:
                            highest = version

print(highest)
