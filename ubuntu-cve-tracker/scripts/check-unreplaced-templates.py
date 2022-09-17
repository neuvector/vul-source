#!/usr/bin/env python3

# Author: Kees Cook <kees@ubuntu.com>
# Copyright (C) 2011-2019 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 2 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# This will report USNs that have unreplaced template fields
#
from __future__ import print_function

import sys
import cve_lib
import json
import optparse
import usn_lib

parser = optparse.OptionParser()
parser.add_option("-d", "--debug", help="Report additional debugging while loading USNs", action='store_true')
parser.add_option("-v", "--verbose", help="Show isummary and package descriptions for each reported USN", action='store_true')
parser.add_option("-u", "--update", help="Clear unfilled isummary template fields", action='store_true')
parser.add_option("-j", "--json", help="Check json instead of default pickle database", action='store_true')
(opt, args) = parser.parse_args()

cves = dict()

config = cve_lib.read_config()

changed = False
if opt.json:
    db = json.load(sys.stdin)
else:
    dbfile = None
    if len(args) < 1:
        dbfile = config['usn_db_copy']
    else:
        dbfile = args[0]

    if opt.debug:
        print("Loading %s ..." % (dbfile), file=sys.stderr)
    db = usn_lib.load_database(dbfile)

if len(args) < 2:
    usns = sorted(db, key=lambda a: list(map(int, a.split('-'))))
else:
    usns = args[1:]

for usn in usns:
    if opt.debug:
        print('Checking %s' % (usn), file=sys.stderr)

    # Validate required fields
    for field in ['description', 'title', 'summary']:
        if field not in db[usn]:
            raise ValueError("USN %s missing '%s' field" % (usn, field))

    # Validate required field contents
    for field in ['description', 'title', 'summary', 'cves', 'isummary', 'action']:
        if field in db[usn] and 'XXX' in db[usn][field]:
            if field != 'isummary':
                raise ValueError("USN %s has 'XXX' in '%s' field" % (usn, field))
            else:
                print(usn)
                if opt.verbose:
                    print(db[usn]['isummary'])
                if opt.update:
                    changed = True
                    db[usn]['isummary'] = ""

                # Assume that unfilled isummary means invalid source description
                for release in db[usn]['releases']:
                    for src in db[usn]['releases'][release]['sources']:
                        if 'description' in db[usn]['releases'][release]['sources'][src]:
                            if opt.verbose:
                                print("\t%s %s: %s" % (release, src, db[usn]['releases'][release]['sources'][src]['description']))
                            if opt.update:
                                changed = True
                                db[usn]['releases'][release]['sources'][src]['description'] = ""

    # Check for knonwn-invalid version details
    bad_versions = set(['(needed)'])
    for release in db[usn]['releases']:
        if 'binaries' not in db[usn]['releases'][release]:
            print("No binaries?! USN %s %s" % (usn, release))
            continue
        for pkg in db[usn]['releases'][release]['binaries']:
            if 'version' in db[usn]['releases'][release]['binaries'][pkg]:
                if db[usn]['releases'][release]['binaries'][pkg]['version'] in bad_versions:
                    print(usn)
                    if opt.verbose:
                        print("\t%s %s bad version '%s'" % (release, pkg, db[usn]['releases'][release]['binaries'][pkg]['version']))
                    if opt.update:
                        changed = True
                        db[usn]['releases'][release]['binaries'][pkg]['version'] = ''

if opt.update and changed:
    usn_lib.save_database(db, dbfile)
