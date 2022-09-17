#!/usr/bin/env python3

# Author: Kees Cook <kees@ubuntu.com>
# Author: Jamie Strandboge <jamie@ubuntu.com>
# Copyright (C) 2005-2016 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 2 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# This script will load the package versions from the current devel release
# and scan for any upstream_PKG versions that have been exceeded, and then
# mark the devel_PKG as not-affected.
#
from __future__ import print_function

import glob
import optparse
import os
import os.path
import sys

import cve_lib
import source_map

import apt
import apt_pkg

parser = optparse.OptionParser()
parser.add_option("-u", "--update", help="Update CVEs with released package versions", action='store_true')
parser.add_option("--stable-pending", help="Update 'pending' state CVEs in stable releases too", action='store_true')
parser.add_option("--prerelease", help="When comparing versions, include prerelease versions in match", action='store_true')
parser.add_option("-p", "--packages", help="Only operate on packages", action="append", type="string")
parser.add_option("-r", "--release", help="Specify release (default is 'devel')", default="devel")
parser.add_option("-s", "--status", help="Specify status, default is 'not-affected' for the devel release and 'released' for stable")
(opt, args) = parser.parse_args()

# The script expects the devel release to be specified as 'devel', so make
# it easier on the user.
if opt.release == cve_lib.devel_release:
    opt.release = 'devel'

pkgs = source_map.load()

cves = glob.glob('%s/CVE-*' % cve_lib.active_dir)
if os.path.islink('embargoed'):
    cves += glob.glob('embargoed/CVE-*')
    cves += glob.glob('embargoed/EMB-*')


def get_status(opt_status, release, version=None, release_version=None):
    status = ""
    if opt_status:
        status = opt_status
    elif version and release_version and apt_pkg.version_compare(release_version, version) >= 0:
        status = "not-affected"
    elif release == 'devel' or release == cve_lib.devel_release:
        status = "not-affected"
    else:
        status = "released"
    return status


for filename in cves:
    cve = os.path.basename(filename)
    try:
        data = cve_lib.load_cve(filename)
    except ValueError as e:
        if not cve.startswith('EMB'):
            print(e, file=sys.stderr)
        continue
    for src in data['pkgs']:
        if opt.packages and src not in opt.packages:
            continue
        # skip supported products and snap since there is no release to sync from
        if 'product' in data['pkgs'][src] or 'snap' in data['pkgs'][src]:
            continue
        if opt.release in data['pkgs'][src] and 'upstream' in data['pkgs'][src]:
            upstream_state, upstream_notes = data['pkgs'][src]['upstream']
            # Skip bad released versions
            if upstream_state != 'released' or upstream_notes == "" or ' ' in upstream_notes or ',' in upstream_notes:
                continue

            state, notes = data['pkgs'][src][opt.release]

            release = opt.release
            if release == 'devel':
                release = cve_lib.devel_release
            if src not in pkgs[release]:
                continue

            curver = pkgs[release][src]['version']
            # Strip epoch for upstream comparison
            if ':' in curver:
                curver = curver[curver.find(':') + 1:]
            # Handle "really" versions
            if 'really' in curver:
                curver = curver.split('really', 1)[1]
            if opt.prerelease:
                upstream_notes += "~"
            if state not in ['released', 'DNE', 'not-affected'] and apt_pkg.version_compare(upstream_notes, curver) <= 0:
                # Leave specified version, if it was from "pending"
                version = ""
                if state == 'pending':
                    version = notes
                if version == "":
                    version = pkgs[release][src]['version']

                status = get_status(opt.status, release)
                print('%s: %s upstream (%s) to \'%s\' < %s (%s)' % (cve, src, upstream_notes, status, release, version))

                if opt.update:
                    cve_lib.update_state(filename, src, opt.release, status, version)
                    pass

        # Look for CVEs marked "pending" for a version that is in the archive already
        for release in cve_lib.releases:
            rel = release
            if rel == 'devel':
                rel = cve_lib.devel_release
            elif not opt.stable_pending:
                continue
            elif opt.release != "devel" and release != opt.release:
                # honor -r with --stable-pending
                continue
            if release in data['pkgs'][src] and rel in pkgs and src in pkgs[rel]:
                state, notes = data['pkgs'][src][release]
                curver = pkgs[rel][src]['version']
                if state == 'pending' and notes != '' and apt.version_compare(notes, curver) <= 0:
                    status = get_status(opt.status, release, notes, pkgs[release][src]['release_version'])
                    if opt.stable_pending:
                        print('%s: %s pending (%s) to \'%s\' <= %s (rel=%s/cur=%s)' % (cve, src, notes, status, rel, pkgs[release][src]['release_version'], curver))
                    else:
                        print('%s: %s pending (%s) to \'%s\' <= %s (%s)' % (cve, src, notes, status, rel, curver))

                    if opt.update:
                        cve_lib.update_state(filename, src, release, status, notes)
