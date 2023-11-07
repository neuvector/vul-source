#!/usr/bin/env python2
# Copyright 2008 Canonical, Ltd.
# Author: Kees Cook <kees@ubuntu.com>
# License: GPL
#
# This script will dup existing "devel" entries to the named release.
#
from __future__ import print_function

import sys, os, os.path
import optparse, glob
import cve_lib

devel = cve_lib.devel_release

parser = optparse.OptionParser()
parser.add_option("-u", "--update", dest="update", help="Update CVEs with new release", action='store_true')
(opt, args) = parser.parse_args()

release_name = args.pop(0)

if len(args):
    cves = glob.glob(args.pop(0))
else:
    cves = glob.glob('active/CVE-*')
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

    for src in data['pkgs']:
        if 'devel' in data['pkgs'][src] and release_name not in data['pkgs'][src]:
            print('%s %s' % (cve, src))
            if opt.update:
                cve_lib.clone_release(filename, src, 'devel', release_name)
