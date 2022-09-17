#!/usr/bin/env python2

# Author: Tyler Hicks <tyhicks@canonical.com>
# Copyright (C) 2017 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# This script looks for active CVEs that have open packages in main/restricted
# that are no longer supported (e.g. LTS end-of-life).
#
#
from __future__ import print_function
import glob
import optparse
import os
import os.path
import sys

import cve_lib
import source_map

parser = optparse.OptionParser()
parser.add_option("-p", "--package", dest="package", default=None, help="Source package to abandon.")
parser.add_option("-r", "--release", dest="release", default=None, help="Only abandon the package in the specified release. The default is to abandon the package in all releases.")
parser.add_option("-u", "--update", dest="update", help="Make changes to CVE files. The default is to only report changes that would be made.", action='store_true')
(opt, args) = parser.parse_args()

if not opt.package:
    print("ERROR: must specify a source package", file=sys.stderr)
    sys.exit(1)

src = opt.package
pkgs = source_map.load()

cves = glob.glob('%s/CVE-*' % cve_lib.active_dir)
if os.path.islink('embargoed'):
    cves += glob.glob('embargoed/CVE-*')
    cves += glob.glob('embargoed/EMB-*')

for filename in cves:
    cve = os.path.basename(filename)
    try:
        data = cve_lib.load_cve(filename)
    except ValueError as e:
        if not cve.startswith('EMB'):
            print(e, file=sys.stderr)
        continue

    if src not in data['pkgs']:
        continue

    if opt.release:
        if opt.release not in data['pkgs'][src]:
            continue

        releases = [opt.release]
    else:
        releases = data['pkgs'][src].keys()
        if 'upstream' in releases:
            releases.remove('upstream')

    for release in releases:
        state = data['pkgs'][src][release][0]
        open_states = ['needed', 'needs-triage', 'deferred']

        if state not in open_states:
            continue

        print('%s: %s abandoned (%s)' % (cve, src, release))

        if opt.update:
            cve_lib.update_state(filename, src, release, 'ignored', 'abandoned')
