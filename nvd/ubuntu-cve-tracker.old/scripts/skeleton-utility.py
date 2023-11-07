#!/usr/bin/env python2
# Copyright 2008 Canonical, Ltd.
# Author: Kees Cook <kees@ubuntu.com>
# License: GPLv3
#
# This script is an example on how to call an arbitrary cve_lib function
# on a set of CVE files.
#
from __future__ import print_function

import glob
import optparse
import os
import os.path
import sys

import cve_lib

devel = cve_lib.devel_release

parser = optparse.OptionParser()
parser.add_option("-u", "--update", dest="update", help="Update CVEs with ...", action='store_true')
(opt, args) = parser.parse_args()

release_name = args.pop(0)
print(release_name)

if len(args):
    cves = glob.glob(args.pop(0))
else:
    cves = glob.glob('%s/CVE-*' % cve_lib.active_dir)
    if os.path.islink('embargoed'):
        cves += glob.glob('embargoed/CVE-*')
        cves += glob.glob('embargoed/EMB-*')

for filename in cves:
    cve = os.path.basename(filename)
    try:
        data = cve_lib.load_cve(filename)
    except ValueError as e:
        print(e, file=sys.stderr)
        continue

    if opt.update:
        print(cve)
        # cve_lib.drop_dup_release(filename,release_name)
