#!/usr/bin/env python2
# Author: Kees Cook <kees@ubuntu.com>
# Copyright (C) 2008 Canonical Ltd.
#
# Reports any unused USNs.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# Fetch the USN database first. Override location with --database
#  wget http://people.canonical.com/~ubuntu-security/usn/database-all.pickle.bz2
#
import cPickle, sys, os, os.path, optparse, usn_lib
from source_map import version_compare

parser = optparse.OptionParser()
#parser.add_option("-v", "--verbose", dest="verbose", help="Report logic while processing USNs", action='store_true')
parser.add_option("-s", "--start", help="Specify first USN to check against (default is '-' for autodetection)", action='store', metavar='USN', default="-")
parser.add_option("-D", "--database", help="Specify location of USN data (default 'database-all.pickle')", default="database-all.pickle")
parser.add_option("-d", "--debug", dest="debug", help="Report additional debugging while processing USNs", action='store_true')
(opt, args) = parser.parse_args()

db       = usn_lib.load_database(opt.database)

usns = sorted(db, cmp=version_compare)
seen = set()
for usn in usns:
    num = int(usn.split('-')[0])
    seen.add(num)

if opt.start == "-":
    least = int(usns[0].split('-')[0])
else:
    least = int(opt.start.split('-')[0])

highest = int(usns[-1].split('-')[0])
current = least
while current <= highest:
    if current not in seen:
        print "%d-1" % (current)
    current += 1
