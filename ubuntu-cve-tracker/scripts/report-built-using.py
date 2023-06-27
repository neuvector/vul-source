#!/usr/bin/env python3
#  Copyright (C) 2015 Canonical Ltd.
#  Authors: Jamie Strandboge <jamie@ubuntu.com>
#
#  This script is distributed under the terms and conditions of the GNU General
#  Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
#  for details.

import cve_lib
import optparse
import source_map
import sys

class MyParser(optparse.OptionParser):
    def format_epilog(self, formatter):
        return self.epilog

usage = "Usage: %prog [options] SRC[/[-]VERSION] ..."
epilog = '''
Examples:
  # List all packages that are built using glibc for all releases:
  $ ./scripts/%(prog)s glibc
  ...
  glibc (2.19-10ubuntu2)             vivid          main       aide
  glibc (2.19-10ubuntu2)             wily           main       aide

  # List all packages that are built using glibc in vivid
  $ ./scripts/%(prog)s --release=vivid glibc
  ...
  glibc (2.19-10ubuntu2)             vivid          main       aide
  glibc (2.21-0ubuntu4)              vivid-updates  universe   qemu-user-static

  # List all packages that are built using golang 2:1.2-2ubuntu3
  $ ./scripts/%(prog)s golang/2:1.2-2ubuntu3
  ...
  golang (2:1.2-2ubuntu3)            trusty         universe   golang-metrics-dev
  golang (2:1.2-2ubuntu3)            vivid          universe   golang-metrics-dev

  # List all packages that are built using golang before 2:1.2-2ubuntu3
  $ ./scripts/%(prog)s golang/-2:1.2-2ubuntu3
  ...
  golang (2:1.1.2-2ubuntu1)          trusty         universe   golang-codesearch-dev
  golang (2:1.1.2-2ubuntu1)          vivid          universe   codesearch
''' % ({'prog': 'report-built-using.py'})

parser = MyParser(usage=usage, epilog=epilog)
parser.add_option("--release",
                  help="Show packages for specified release",
                  metavar="RELEASE")
parser.add_option("--component",
                  help="Show packages for specified component",
                  metavar="COMPONENT")
parser.add_option("--all",
                  help="Show all packages that use Built-Using",
                  default=False,
                  action='store_true')
(opt, args) = parser.parse_args()

if len(args) == 0 and not opt.all:
    print("ERROR: must supply source package name(s)", file=sys.stderr)
    sys.exit(1)

if opt.all and len(args) > 0:
    print("ERROR: do not specify packages with --all", file=sys.stderr)
    sys.exit(1)


if opt.release:
    releases = [opt.release]
else:
    releases = set(cve_lib.releases) - set(cve_lib.eol_releases)
    releases.update(cve_lib.get_active_esm_releases())
    releases.update(cve_lib.get_active_releases_with_esm())

pmap = source_map.load(releases=releases, skip_eol_releases=False, data_type='packages')

built_using = source_map.load_built_using_collection(pmap,
                                                     releases=releases,
                                                     component=opt.component)

out = ""

packages = args
if opt.all:
    packages = sorted(built_using.keys())

for src in packages:
    out += source_map.get_built_using(built_using, src)

if out != '':
    print(source_map.get_built_using_header())
    print(out, end=None)
