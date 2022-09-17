#!/usr/bin/env python2
# Author: Kees Cook <kees@ubuntu.com>
# Copyright (C) 2011-2017 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 2 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# Fetch the USN database and pass it as the first argument
#  wget http://people.canonical.com/~ubuntu-security/usn/database-all.pickle
#  ./scripts/publish-active-usns.py database-all.pickle database.pickle
#
# This will report USNs that only apply to EOL releases
#
from __future__ import print_function

import sys
import os
import os.path
import optparse

import usn_lib
from cve_lib import releases, is_active_release, is_active_esm_release

parser = optparse.OptionParser()
parser.add_option("-d", "--debug", help="Show additional debugging while loading USNs", action='store_true')
parser.add_option("-r", "--report", help="Show which USNs have expired", action='store_true')
parser.add_option("-v", "--verbose", help="When using --report, shows releases for each reported USN", action='store_true')
(opt, args) = parser.parse_args()

cves = dict()

if len(args) < 2:
    print("Usage: %s IN-PICKLE OUT-PICKLE" % (sys.argv[0]), file=sys.stderr)
    sys.exit(1)

db_in = args[0]
db_out = args[1]

if opt.debug:
    print("Loading %s ..." % (db_in), file=sys.stderr)
db = usn_lib.load_database(db_in)

usns = sorted(db, key=lambda a:list(map(int,a.split('-'))))
for usn in usns:
    if opt.debug:
        print('Checking %s' % (usn), file=sys.stderr)

    supported = False
    eol = []
    for rel in sorted(db[usn]['releases']):
        eol.append(rel)
        # Logic is a bit side-ways here to account for releases that cve_lib
        # doesn't even admit to knowing about.
        if rel in releases and (is_active_release(rel) or is_active_esm_release(rel)):
            supported = True

    if not supported:
        del db[usn]
        suffix = ""
        if opt.verbose:
            suffix = " (%s)" % (", ".join(eol))
        if opt.report:
            print("%s%s" % (usn, suffix))

usn_lib.save_database(db, db_out)
