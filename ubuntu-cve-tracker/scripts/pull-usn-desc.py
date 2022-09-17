#!/usr/bin/env python3
# Dumps the Ubuntu-Descriptions in a form suitable for a USN announcement
# Copyright (C) 2008-2011 Canonical, Ltd.
# Author: Kees Cook <kees@ubuntu.com>
# License: GPLv3
from __future__ import print_function

import functools
import optparse
import os
import sys
import textwrap
import cve_lib


def build_absolute_or_relative_path(path, cve):
    filename = ""

    if path.startswith('/'):
        filename = os.path.join(path, cve)
    else:
        basedir = os.path.join(os.path.dirname(sys.argv[0]), '..')
        filename = os.path.join(basedir, path, cve)

    return filename


def get_filename(cve, use_embargoed=False):
    filename = build_absolute_or_relative_path(cve_lib.active_dir, cve)
    if not os.path.exists(filename):
        filename = build_absolute_or_relative_path(cve_lib.retired_dir, cve)
    if not os.path.exists(filename) and use_embargoed:
        filename = build_absolute_or_relative_path(cve_lib.embargoed_dir, cve)

    return filename


opter = optparse.OptionParser()
opter.add_option("--prioritize", help="Display 'critical' and 'high' first, negligible last", action='store_true')
opter.add_option("--cve", metavar="CVE-YYYY-NNNN", help="Request a given CVE's description or template", action='append', default=[])
opter.add_option("--releases", help="List of releases CVEs affect to be filter used in description", action='append', default=[])
opter.add_option("--this-only-affected", help="Makes this only affected feature optional", action='store_true')
opter.add_option("--src", help="The package source to be check through if --this-only-affected is used", action='append', default=[])
opter.add_option("--embargoed", help="Use the embargoed tree to look for desctiptions in addition", action='store_true')
(opt, args) = opter.parse_args()

cves = dict()
descriptions = dict()
found = []

# This function cross the provided releases info with CVE files info
# in order to find 'This only affected <releases>' info and returns it
# to creates the CVE description.
def only_affected(cve_data, cve_number, releases, srcs):
    pkgs = cve_data[cve_number]['pkgs']
    affects = {}

    # TODO: find a better way to handle trusty esm.
    if 'esm-infra/trusty' in releases:
        releases.remove('esm-infra/trusty')
        releases.append('trusty/esm')

    for pkg in srcs:
        has_releases = pkgs[pkg].keys() & set(releases)
        for release in has_releases:
            pkg_release = pkgs[pkg][release][0]
            if pkg_release == 'needed' or pkg_release == 'needs-triage':
                rel_num = cve_lib.release_name(release)

                if release not in affects.keys():
                    affects[release] = rel_num

    diff = set(affects.keys()) & set(releases)
    if diff != set(releases):
        if diff:
            if len(diff) > 1:
                affects_values = list(affects.values())
                affects_values.sort()
                txt = ", ".join(affects_values[:-1])
                txt += ', and {}'.format(affects_values[-1:][0])
                return " This issue only affected {}.".format(txt)
            else:
                return " This issue only affected {}.".format(list(affects.values())[0])

    return ""


rc = 0
empty = set()
affected_txt = ""
for cve in opt.cve + args:
    if cve.endswith(','):
        cve = cve[:-1]
    # CVE references can be bug numbers like https://launchpad.net/bugs/XXXXXX.
    # These obviously don't exist on the filesystem, so silently ignore URLs
    # but report other malformed CVEs
    if not cve.startswith('CVE'):
        if not cve.startswith('http'):
            print("Skipping invalid CVE identifier '%s'" % cve, file=sys.stderr)
        continue
    filename = get_filename(cve, use_embargoed=(opt.embargoed == True))
    if os.path.exists(filename):
        cves[cve] = cve_lib.load_cve(filename)
        if opt.this_only_affected and opt.releases and opt.src:
            affected_txt = only_affected(cves, cve, opt.releases, opt.src)
        chunks = cves[cve]

        desc = chunks['Ubuntu-Description'].strip()
        if len(desc) == 0:
            rc = 1
            disc = chunks.get('Discovered-by', '').strip()
            if len(disc) > 0:
                disc += ':'
            desc = 'XXX-FIXME-XXX %s[%s]' % (disc, chunks['Description'].strip())
        desc = desc.replace('\n', ' ').replace('   ', ' ').replace('  ', ' ')
        if len(desc) == 0:
            rc = 1
            desc = "XXX-FIXME-%s-HAS-EMPTY-DESCRIPTION-XXX" % (cve)
    else:
        rc = 1
        desc = "XXX-FIXME-%s-NOT-KNOWN-TO-TRACKER-XXX" % (cve)

    # some descriptions has a period others don't, so, check for it.
    if not desc.endswith('.') and affected_txt:
        affected_txt = '.' + affected_txt

    descriptions[cve] = desc + affected_txt
    found.append(cve)


def _cve_sort(a, b):
    if opt.prioritize:
        a_priority = cves.get(a, {'Priority': 'unknown'})['Priority']
        b_priority = cves.get(b, {'Priority': 'unknown'})['Priority']
        if a_priority == 'critical':
            return -1
        if b_priority == 'critical':
            return 1
        if a_priority == 'high':
            return -1
        if b_priority == 'high':
            return 1
        if a_priority == 'negligible':
            return 1  # b is higher
        if b_priority == 'negligible':
            return -1  # a is higher pri
    return (a > b) - (a < b)


reported = set()
for cve in sorted(found, key=functools.cmp_to_key(_cve_sort)):
    if cve in reported:
        continue

    # Merge identical descriptions
    identical = []
    desc = descriptions[cve]
    for seen in sorted(descriptions):
        if descriptions[seen] == desc:
            identical.append(seen)
            reported.add(seen)

    if len(identical) != len(found):
        desc += " (%s)" % (", ".join(identical))

    print()
    print(textwrap.fill(desc, 75))
