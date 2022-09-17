#!/usr/bin/env python2
#
# This script produces HTML output for a specific package, using CVE details
# from the command-line.
#
# Copyright 2009-2011 Canonical, Ltd.
# Author: Kees Cook <kees@ubuntu.com>
# License: GPLv3
import codecs
import optparse
import os
import sys
import html_export

parser = optparse.OptionParser()
parser.add_option("--cveless", help="Directory to write CVE-less argument list of packages out to", action="store")
parser.add_option("--commit", help="Include commit # in HTML output", action='store')
(opt, args) = parser.parse_args()

outfd = codecs.getwriter("utf-8")(sys.stdout)

if not opt.cveless:
    html_export.htmlize_package(outfd, args[0], args[1:], commit=opt.commit)
else:
    for pkg in args:
        pkg = os.path.basename(pkg)
        if pkg.endswith('.html'):
            pkg = pkg[:-5]
        destination = os.path.join(opt.cveless, pkg)
        if not destination.endswith('.html'):
            destination = destination + '.html'
        with open(destination+'.new', 'w') as htmlfd:
            html_export.htmlize_package(htmlfd, pkg, [], commit=opt.commit)
        os.rename(destination+'.new', destination)
