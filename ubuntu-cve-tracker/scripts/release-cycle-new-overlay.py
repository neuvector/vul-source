#!/usr/bin/env python3

# Author: Tyler Hicks <tyhicks@canonical.com>
# Copyright (C) 2017 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# This script adds tracking for a new overlay PPA in active CVEs. If the
# package is supported by the overlay PPA, the status is copied from the base
# release. If the package is not supported by the overlay PPA, the status is
# set to DNE with a comment recording the current status in the base release.
#
#
import sys, os, os.path
import optparse, glob

import cve_lib
import source_map

parser = optparse.OptionParser()
parser.add_option("-r", "--release", dest="release", default=None, help="Release to create in <base>/<ppa> form. Precise ESM would use precise/esm")
parser.add_option("-u", "--update", dest="update", help="Make changes to CVE files. The default is to only report changes that would be made.", action='store_true')
(opt, args) = parser.parse_args()

if not opt.release:
    print("ERROR: must specify release", file=sys.stderr)
    sys.exit(1)
elif not cve_lib.is_overlay_ppa(opt.release):
    print("ERROR: must specify a release with an overlay PPA", file=sys.stderr)
    sys.exit(1)

release = opt.release
(product, base_release) = cve_lib.split_overlay_ppa_from_release(release)

pkgs = source_map.load()

cves = glob.glob('%s/CVE-*' % cve_lib.active_dir)
cves += glob.glob('%s/CVE-*' % cve_lib.retired_dir)
cves += glob.glob('%s/CVE-*' % cve_lib.ignored_dir)
if os.path.islink(cve_lib.embargoed_dir):
    cves += glob.glob('%s/CVE-*' % cve_lib.embargoed_dir)
    cves += glob.glob('%s/EMB-*' % cve_lib.embargoed_dir)

for filename in cves:
    cve = os.path.basename(filename)
    cvedir = os.path.basename(os.path.dirname(filename))
    try:
        data = cve_lib.load_cve(filename)
    except ValueError as e:
        if not cve.startswith('EMB'):
            print(e, file=sys.stderr)
        continue

    for src in data['pkgs']:
        # skip if base_release is not tracked. Don't add trusty/esm if trusty is not present
        if not base_release in data['pkgs'][src]:
            continue

        # skip if release is already present. Don't add trusty/esm again if it already exists
        if release in data['pkgs'][src]:
            continue

        (base_state, base_notes) = data['pkgs'][src][base_release]
        if product == 'esm-apps':
            if not cve_lib.is_supported(pkgs, src, base_release):
                state = base_state
                notes = base_notes

                print('%s/%s: %s is supported in %s. The state will be copied from %s.' % (cvedir, cve, src, release, base_release))
            else:
                continue

        elif product == 'esm-infra':
            if cve_lib.is_supported(pkgs, src, base_release):
                state = base_state
                notes = base_notes

                print('%s/%s: %s is supported in %s. The state will be copied from %s.' % (cvedir, cve, src, release, base_release))
            else:
                continue

        elif cve_lib.is_supported(pkgs, src, release):
            state = base_state
            notes = base_notes

            print('%s/%s: %s is supported in %s. The state will be copied from %s.' % (cvedir, cve, src, release, base_release))

        else:
            state = 'DNE'
            notes = None

            # Only add notes when the base_state was not DNE or if base_state
            # was DNE with a note
            if state != base_state or base_notes:
                notes = '%s was %s' % (base_release, base_state)
                if base_notes:
                    notes += ' [%s]' % (base_notes)

            print('%s/%s: %s is unsupported in %s. The state will be set to "%s (%s)"' % (cvedir, cve, src, release, state, notes))

        if opt.update:
            cve_lib.add_state(filename, src, release, state, notes, base_release)
