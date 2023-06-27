#!/usr/bin/env python3

# Author: Kees Cook <kees@ubuntu.com>
# Author: Jamie Strandboge <jamie@ubuntu.com>
# Author: Marc Deslauriers <marc.deslauriers@canonical.com>
# Copyright (C) 2005-2010 Canonical Ltd.
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
parser.add_option("-r", "--release", dest="release", default=None, help="release to modify")
parser.add_option("-W", "--whole", dest="whole", help="End of life the whole release", action='store_true')
parser.add_option("-U", "--universe", dest="universe", help="Modify packages in universe and multiverse", action='store_true')
parser.add_option("-u", "--update", dest="update", help="Update CVEs with released package versions", action='store_true')
(opt, args) = parser.parse_args()

if not opt.release:
    print("ERROR: must specify release", file=sys.stderr)
    sys.exit(1)

if opt.universe:
    component = ['universe', 'multiverse']
else:
    component = ['main', 'restricted']

if opt.whole:
    component = ['main', 'restricted', 'universe', 'multiverse']

pkgs = source_map.load(releases=[opt.release], skip_eol_releases=False)

cves = glob.glob('%s/CVE-*' % cve_lib.active_dir)
cves += glob.glob('%s/*' % cve_lib.boilerplates_dir)

if os.path.islink('embargoed'):
    cves += glob.glob('embargoed/CVE-*')
    cves += glob.glob('embargoed/EMB-*')

for filename in cves:
    # we don't want to edit symlinks as that will cause them to become
    # unsymlinked
    if os.path.islink(filename):
        continue

    cve = os.path.basename(filename)
    try:
        data = cve_lib.load_cve(filename)
    except ValueError as e:
        if not cve.startswith('EMB'):
            print(e, file=sys.stderr)
        continue
    for src in data['pkgs']:
        if opt.release in data['pkgs'][src] and \
           src in pkgs[opt.release] and \
           pkgs[opt.release][src]['section'] in component and \
           data['pkgs'][src][opt.release][0] in ['needed', 'needs-triage', 'deferred']:

            if opt.universe or opt.whole or not cve_lib.is_supported(pkgs, src, opt.release):

                print('%s: %s reached end of standard support (%s)' % (cve, src, opt.release))

                if opt.update:
                    if (
                        cve_lib.get_orig_rel_name(opt.release) != opt.release
                        and cve_lib.is_active_esm_release(cve_lib.get_orig_rel_name(opt.release))
                    ):
                        status = data['pkgs'][src][opt.release]
                        if status[1] != '':
                            cve_lib.update_state(filename, src, opt.release, 'ignored', 'end of ESM support, was %s [%s]' % (status[0], status[1]))
                        else:
                            cve_lib.update_state(filename, src, opt.release, 'ignored', 'end of ESM support, was %s' % (status[0]))
                    elif 'LTS' in cve_lib.release_name(opt.release):
                        status = data['pkgs'][src][opt.release]
                        if status[1] != '':
                            cve_lib.update_state(filename, src, opt.release, 'ignored', 'end of standard support, was %s [%s]' % (status[0], status[1]))
                        else:
                            cve_lib.update_state(filename, src, opt.release, 'ignored', 'end of standard support, was %s' % (status[0]))
                    else:
                        cve_lib.update_state(filename, src, opt.release, 'ignored', 'end of life')
