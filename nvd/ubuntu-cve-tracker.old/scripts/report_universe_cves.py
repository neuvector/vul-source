#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# Author: Emilia Torino <emilia.torino@canonical.com>
# Copyright (C) 2008 Canonical Ltd.
#
# Reports which CVEs were fixed for a given private release
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# Fetch embargoed repository first
# Call this script indicating the release to get reports from as well as the time period for filtering results:
# scripts/report_universe_cves.py trusty
# scripts/report_universe_cves.py trusty --since 1556593200

import argparse
import os
import glob
import sys
import subprocess
import time

arg_parser = argparse.ArgumentParser(description='Counts CVEs for trusty/esm')
arg_parser.add_argument('-s', '--since', action='store', help="Report only CVEs fixed after this date (in seconds "
                                                               "from UTC)", default=0)
arg_parser.add_argument('-b', '--before', action='store', help="Report only CVEs fixed before this date (in seconds "
                                                               "from UTC)", default=time.time())
args, extra_arg = arg_parser.parse_known_args()
release = extra_arg[0]

private_esm_dir = "experimental/subprojects/private-esm"

if 'UCT' in os.environ:
    private_esm_dir = os.environ['UCT'] + "/experimental/subprojects/private-esm"
else:
    print >> sys.stderr, 'Please setup UCT before running this script'
    sys.exit(1)

if not os.path.isdir(private_esm_dir):
    print >> sys.stderr, 'Private ESM directory not found'
    sys.exit(1)

os.chdir(private_esm_dir)
private_cves = [f for f in glob.glob1(".", "CVE-*")]
report_cves=[]

for cve in private_cves:
    if os.path.isfile('../esm-universe/' + cve):
        if release in open('../esm-universe/' + cve).read():
            cmd_args = ['git', 'log', '-1', '--format=%at', '../esm-universe/' + cve]
        else:
            cmd_args = ['git', 'log', '-1', '--format=%at', cve]
    else:
        cmd_args = ['git', 'log', '-1', '--format=%at', cve]
    cve_creation_timestamp = float(subprocess.check_output(cmd_args))
    if float(args.since) <= cve_creation_timestamp <= float(args.before):
        report_cves.append(cve)

print "Total CVEs fixed for %s ESM universe: %d" % (release, len(report_cves))
print "CVEs: %s" % " ".join(report_cves)
