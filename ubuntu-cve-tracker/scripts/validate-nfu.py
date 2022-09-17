#!/usr/bin/env python3
# Author: Alex Murray <alex.murray@canonical.com>
# Copyright (C) 2020 Canonical Ltd.
import argparse
import os
import sys
parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", dest="verbose",
                  help="Report additional details", action='store_true')
parser.add_argument("-n", "--not-for-us", dest="nfufile",
                  help="Path to the not-for-us.txt file",
                  default=os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                       os.path.pardir,
                                       "ignored", "not-for-us.txt"))
args = parser.parse_args()
err = 0
with open(args.nfufile) as f:
    linenum = 1
    for line in f.readlines():
        try:
            # check is valid ascii
            line.encode(encoding='ascii')
        except UnicodeEncodeError as e:
            # extract column number from error message like:
            # 'ascii' codec can't encode characters in position 59-60: ordinal not in range(128)
            msg = str(e)
            colnum = int(msg.split(":")[0].split(" ")[-1].split("-")[0])
            print("%s:%d:%d: error: %s" % (args.nfufile, linenum, colnum, msg))
            err += 1
        linenum += 1
sys.exit(err)
