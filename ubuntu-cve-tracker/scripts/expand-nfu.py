#!/usr/bin/env python2
# Parses the not-for-us.txt file to extract CVEs
# Copyright (C) 2008 Canonical, Ltd.
# Author: Kees Cook <kees@ubuntu.com>
# License: GPLv3
import sys, os
import optparse, tempfile
import html_export

parser = optparse.OptionParser()
parser.add_option("--list", help="Generate list of CVEs in the NFU file", action='store_true')
parser.add_option("--html", help="Directory to generate HTML CVE output", action='store')
parser.add_option("--commit", help="Include commit # in HTML output", action='store')
(opt, args) = parser.parse_args()

if not opt.html and not opt.list:
    print >>sys.stderr, "Must select either --list or --html"
    sys.exit(1)

nfulist = args.pop(0)

def write_cve(cve, note):
    tempcve = tempfile.NamedTemporaryFile(prefix='cve-')
    #print >>sys.stderr, tempcve.name
    note = note.strip()
    tempcve.write('''Candidate: {cve}
PublicDate: unknown
References:
 https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}
Description:
Priority: not-for-us
Notes:
 ubuntu-security> Does not apply to software found in Ubuntu.
'''.format(cve=cve))
    if len(note) > 0:
        for line in note.splitlines():
            tempcve.write('  "%s"\n' % line)
    tempcve.flush()
    year = cve.split('-')[1]
    outdir = os.path.join(opt.html, year)
    if not os.path.exists(outdir):
        os.mkdir(outdir)
    outfile = os.path.join(outdir,cve+'.html')
    with open(outfile+'.new', 'w') as outfd:
        try:
            html_export.htmlize_cve(tempcve.name, outfd, commit=opt.commit)
        except Exception as e:
            print("Failed to export NFU entry %s '%s': %s\n" % (cve, note, e))
    os.rename(outfile+'.new',outfile)


with open(nfulist) as f:
    for line in f.readlines():
        remaining = line.strip()
        while len(remaining) > 0:
            if ' ' in remaining:
                cve, remaining = remaining.split(' ',1)
            else:
                cve = remaining
                remaining = ''
            #print '[%s][%s]' % (cve,remaining)
            if cve.startswith("CVE"):
                note = ""
                if remaining.startswith('#') and len(remaining)>2:
                    note = remaining[2:]
                    remaining = ''
                if len(args)==0 or cve in args:
                    if opt.html:
                        write_cve(cve, note)
                    if opt.list:
                        print("%s %s" % (cve, note))
            if cve.startswith('#'):
                remaining = ''
