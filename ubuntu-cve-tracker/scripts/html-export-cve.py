#!/usr/bin/env python2
#
# Author: Kees Cook <kees@ubuntu.com>
# Author: Jamie Strandboge <jamie@ubuntu.com>
# Copyright (C) 2005-2011 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

import sys
import optparse
import html_export
import codecs

parser = optparse.OptionParser()
parser.add_option("--commit", help="Include commit # in HTML output", action='store')
(opt, args) = parser.parse_args()

cvefile = args[0]
outfd = codecs.getwriter("utf-8")(sys.stdout)

html_export.htmlize_cve(cvefile, outfd, commit=opt.commit)
