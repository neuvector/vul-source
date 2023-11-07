#!/usr/bin/env python2

# Author: Jamie Strandboge <jamie@ubuntu.com>
# Copyright (C) 2012 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 2 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

import codecs
import cPickle
import json
import optparse
import os
import sys

# TODO: move these to usn_lib.py
def save_database_json(database, db_filename):
    '''Save usn database'''
    filename = os.path.expanduser(db_filename)
    json.dump(database, open(filename, 'w'), -1, encoding="utf-8")

def convert_pickle_to_json(indb, outdb, prefix=None):
    '''Convert a pickle database into a json'''
    filename = os.path.expanduser(indb)
    if not os.path.isfile(filename):
        return False

    print >>sys.stderr, "INFO: Loading %s..." % (indb)
    db = cPickle.load(open(indb))

    # Older python pickle's have a bug that stores utf-8 data incorrectly.
    # Account for that in our top level keys (db[k]['description'] is known to
    # have this)
    new_db = dict()
    count = 0
    for k in db.keys():
        new_db[k] = dict()
        for j in db[k].keys():
            if prefix and j == 'id':
                db[k][j] = "{}{}".format(prefix, db[k][j])
            try:
                json.dumps(db[k][j]) # if this fails, so will json.dump later
                new_db[k][j] = db[k][j]
            except:
                count += 1
                new_db[k][j] = db[k][j].decode("utf-8", "replace")

    if count > 0:
        print >>sys.stderr, "WARN: performed %d pickle decode conversions" % count

    print >>sys.stderr, "INFO: Saving %s..." % (outdb)
    save_database_json(new_db, outdb)

#
# main
#
if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-i", "--input-file", dest="infile", help="pickle data file", metavar="FILE")
    parser.add_option("-o", "--output-file", dest="outfile", help="target json data file", metavar="FILE")
    parser.add_option("-p", "--prefix", dest="prefix",
        help="prefix for value of id field. eg: 'USN-'", default=None)
    (opt, args) = parser.parse_args()

    if not opt.infile:
        print >>sys.stderr, "Must specify --input-file"
        sys.exit(1)
    elif not opt.outfile:
        print >>sys.stderr, "Must specify --output-file"
        sys.exit(1)
    elif not os.path.isfile(opt.infile):
        print >>sys.stderr, "'%s' does not exist" % (opt.infile)
        sys.exit(1)
    elif os.path.exists(opt.outfile):
        print >>sys.stderr, "'%s' already exists" % (opt.outfile)
        sys.exit(1)

    convert_pickle_to_json(opt.infile, opt.outfile, opt.prefix)
    sys.exit(0)
