#!/bin/python3

# Author: Mike Salvatore <mike.salvatore@canonical.com>
# Copyright (C) 2005-2019 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 2 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# This script takes a list of binary packages and determines what source
# packages produce those binaries.

import argparse
import source_map
import sys

def which_source(srcmap, pkg, release):
    source = ("", "")
    if pkg in srcmap[release]:
        try:
            tmp_source = (srcmap[release][pkg]['source'], srcmap[release][pkg]['section'])
        except KeyError: # package was in list for the release but there was no source
            # so most likely the source name is the same as the package name
            tmp_source = (pkg, srcmap[release][pkg]['section'])

        if not source[0] or tmp_source[1] == "universe":
            source = tmp_source

    if source[0]:
        return source

    # this package wasn't in any source map most likely because it is
    # packaged only for an EOL'd release such as precise
    return ('unknown', 'unknown')

parser = argparse.ArgumentParser(description="Takes a list of binary packages "\
        "and determines what source packages produce those binaries.")
parser.add_argument("release" , action="store", help="An Ubuntu release")
parser.add_argument("bin_list_path" , action="store", help="Path to a file containing a list of binaries")

opt = parser.parse_args()

try:
    srcmap = source_map.load('packages', releases=[opt.release])
    source_packages = set()
    with open(opt.bin_list_path) as fp:
        binary_package = fp.readline().strip()
        while binary_package:
            source = which_source(srcmap, binary_package, opt.release)
            source_packages.add(source)
            binary_package = fp.readline().strip()

    for sp in sorted(source_packages):
        print(sp[0])
except KeyError as ke:
    print("KeyError detected. It's possible that the specified Ubuntu release" \
            " is nonexistant or has reached end-of-life. Key=%s" % str(ke),
           file=sys.stderr)
