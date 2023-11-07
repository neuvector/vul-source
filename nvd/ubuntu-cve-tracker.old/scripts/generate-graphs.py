#!/usr/bin/env python3
#
# This script generates graphs and raw number data (read from a USN database).
# By default, it expects to use the "-all" database to produce full historical
# information. Note that source package data before source-package tracking
# was done in the USN database is inaccurate (before July 2007), and is
# approximated.
#
# Files are generated in a given target directory, one file per
# combination:
#  - per-release, all time
#  - per-release, last 12 months
#  - all releases, all time
#  - all releases, last 12 months
# The data is summed per-month, and built using the following data sources:
#  - USNs published
#  - unique CVEs fixed
#  - unique source packages fixed
#  - regressions fixed
#  - CVEs across srcpkgs (if CVE applied to multiple source packages, count it
#    multiple times)
#  - CVEs across srcpkgs across USNs (each distinct fix counted)
# File naming convention is DATASRCS_RELEASE_TIMESPAN.dat
# For example:
#  - CVE-srcpkg-USN_lucid_12.dat
#  - CVE_all_all.dat
#
# Plot files are named with the .plot extension, and include merged views
# for the per-release plots, named "merged". For example:
#  - CVE-srcpkg_merged_12.plot
#
# Graph images (.png) follow the same naming convention as the plot files.
# Additionally, an index.html is generated as an overview file for available
# graphs.
#
# Copyright (C) 2008-2018 Canonical, Ltd
# Author: Kees Cook <kees@ubuntu.com>
# Author: Jamie Strandboge <jamie@canonical.com>
# Author: Steve Beattie <sbeattie@ubuntu.com>
# License: GPLv3
import os, sys, time, usn_lib, cve_lib
import optparse
import subprocess

import pprint
pp = pprint.PrettyPrinter(indent=4)

def check_requirements():
    for b in ["/usr/bin/gnuplot"]:
        if not os.path.exists(b):
            print("Cannot find '%s'" % b, file=sys.stderr)
            sys.exit(1)

parser = optparse.OptionParser()
parser.add_option("--target", help="Into which directory to write the data files", metavar="DIR", action='store')
parser.add_option("-D", "--database", help="Specify location of USN data (default 'database-all.pickle')", default="database-all.pickle")
parser.add_option("--skip-new-cves", help="Skip new CVE additions. Useful for script development, but lose part of the report.", action="store_true")
(opt, args) = parser.parse_args()

if opt.target == None:
    print("Must specify --target", file=sys.stderr)
    sys.exit(1)

config = cve_lib.read_config()

if not os.path.exists(opt.database):
    print("Cannot find '%s'" % opt.database, file=sys.stderr)
    sys.exit(1)

check_requirements()

db = usn_lib.load_database(opt.database)
# info is: [release][datasrc][month] = set() of unique datasrc items,
# where month is int(YYYYMM). See "establish_release()" for initialization.
info = dict()
details = {
    'USN': "USNs published per month",
    'CVE': "unique CVEs fixed per month",
    'srcpkg': "unique Source Packages fixed per month",
    'regression': "Regressions fixed per month",
    'CVE-srcpkg': "distinct CVE fixes published (regardless of USN) per month",
    'CVE-srcpkg-USN': "distinct CVE fixes published per month",
}
datasrcs = details.keys()

def establish_release(rel, when):
    if rel not in info:
        info.setdefault(rel, dict())
    for datasrc in datasrcs:
        info[rel].setdefault(datasrc, dict())
        info[rel][datasrc].setdefault(when, set())

def rel_path(source, release, span, ext=""):
    return '%s_%s_%s.%s' % (source, release, span, ext)

def base_path(source, release, span, ext=""):
    return '%s/%s' % (opt.target, rel_path(source, release, span, ext))

# collect file descriptors instead of open/closing on every line
fds = dict()
def write_report(release, source, month, span, count):
    # File naming convention is DATASRCS_RELEASE_TIME.dat
    filepath = base_path(source, release, span, 'dat')
    if not filepath in fds:
        fds[filepath] = open(filepath, 'w')
    fds[filepath].write('%d %d\n' % (month, count))

def build_plot(release, source, span):
    basepath = base_path(source, release, span)
    datpath = basepath + 'dat'
    cmdpath = basepath + 'plot'
    imgpath = basepath + 'png'
    if not os.path.exists(datpath): # Can't build plot without data
        #print "DEBUG: skipping %s" % cmdpath
        return
    output = open(cmdpath, 'w')
    print('set term png small size 800,600', file=output)
    print('set output "%s"' % (imgpath), file=output)
    print('set xdata time', file=output)
    print('set timefmt "%Y%m"', file=output)
    print('set format x "  %b %Y"', file=output)
    print('set xtics out rotate', file=output)
    print('set key top right', file=output)
    title = details[source] + ' ('
    if release == 'all':
        title += "all releases"
    else:
        title += release
    if span == 'all':
        pass
    elif span == '12':
        title += ', last 12 months'
    else:
        raise ValueError("Unknown span '%s'" % (span))
    title += ')'
    print('set title "%s"' % (title), file=output)
    color = "blue"
    if source == "regression":
        color = "red"
    elif source == "srcpkg":
        color = "green"
    elif source == "USN":
        color = "purple"
    elif source.startswith("CVE"):
        color = "orange"
    print('plot "%s" using 1:2 with filledcurve x1 lc rgb "%s" title "%s"' % (datpath, color, 'count'), file=output)
    output.close()
    #print "DEBUG: gnuplot %s" % cmdpath
    subprocess.call(['gnuplot',cmdpath])

def build_merged_plot(releases, source, span):
    basepath = base_path(source, 'merged', span)
    cmdpath = basepath + 'plot'
    imgpath = basepath + 'png'
    output = open(cmdpath, 'w')
    print('set term png small size 800,600', file=output)
    print('set output "%s"' % (imgpath), file=output)
    print('set xdata time', file=output)
    print('set timefmt "%Y%m"', file=output)
    print('set format x "  %b %Y"', file=output)
    print('set xtics out rotate', file=output)
    print('set key top left', file=output)
    title = details[source] + ' (all releases'
    if span == 'all':
        pass
    elif span == '12':
        title += ', last 12 months'
    else:
        raise ValueError("Unknown span '%s'" % (span))
    title += ')'
    print('set title "%s"' % (title), file=output)
    plots = []
    for rel in releases:
        datpath = base_path(source, rel, span, 'dat')
        if not os.path.exists(datpath): # Can't build plot with data
            #print "DEBUG: skipping %s" % cmdpath
            return
        plots.append(' "%s" using 1:2 with line title "%s"' % (datpath, rel),)
    print('plot %s' % (', '.join(plots)), file=output)
    output.close()
    subprocess.call(['gnuplot',cmdpath])

def generate_cve_additions():
    # This is insanely slow because 'bzr log -v' is slow. See the man page :(
    datpath = "%s/%s" % (opt.target, 'new-cves.dat')
    imgpath = "%s/%s" % (opt.target, 'new-cves.png')
    cmdpath = "%s/%s" % (opt.target, 'new-cves.plot')

    # simple caching... if imgpath is missing or >24 hours old,
    # regenerate everything, otherwise skip this very slow routine.
    if os.path.exists(imgpath) and \
       os.stat(imgpath).st_mtime + (24*3600) > time.time():
        return

    # We may need to change to UCT for our data (eg running under reviewed/).
    # Use cve_lib.set_cve_dir() which helps us find the active/ directory,
    # then go to its parent.
    prev_dir = os.getcwd()
    active_dir = os.path.dirname(cve_lib.set_cve_dir("active"))
    if active_dir != '':
        os.chdir(active_dir)

    # Example 'git log  --full-history --name-status --diff-filter=A -l65000 --pretty=format:"commit %H%ntimestamp: %cI%n"' output
    #commit a03449612e0ed4842d668b6f0ebdfb2fd69e6d7e
    #timestamp: 2018-06-22T09:34:50-07:00
    #
    #A       active/CVE-2018-12617
    #A       active/CVE-2018-12633
    #A       active/CVE-2018-12648
    #
    # - lines beginning with A are additions
    # - the -l65000 argument is because git whinges if too many possible renames
    #   occurred
    date = None
    count = dict()
    # FIXME: precise version of git does not support %cI format
    for line in subprocess.Popen(['git', 'log', '--full-history', '--name-status', '--diff-filter=A', '-l65000', '--pretty=format:commit %H%ntimestamp: %ci%n'],
                                 stdout=subprocess.PIPE).communicate()[0].decode().splitlines():
        #if line.startswith('commit '):
        #    print line.strip()
        if line.startswith('timestamp: '):
            # snag the year/month
            date = int(line.split(' ')[1].replace('-','')[:6])
            count.setdefault(date, 0)
        elif line.startswith('A'):
            name = line[1:].strip()
            if 'active/CVE-' in name:
                # print date, name
                count[date] += 1

    output = open(datpath,'w')
    for date in sorted(count.keys()):
        # sanity in active/CVE-* additions should start after 2007-09
        if date > 200709:
            print(count[date], date, file=output)
    output.close()

    output = open(cmdpath,'w')
    print('set term png small size 800,600', file=output)
    print('set output "%s"' % (imgpath), file=output)
    print('set xdata time', file=output)
    print('set timefmt "%Y%m"', file=output)
    print('set format x "  %b %Y"', file=output)
    print('set xtics out rotate', file=output)
    print('set key top right', file=output)
    print('set title "%s"' % ('New CVEs per month'), file=output)
    print('plot "%s" using 1:2 with filledcurve x1 lc rgb "orange" title "%s"' % (datpath, 'count'), file=output)
    output.close()
    subprocess.call(['gnuplot',cmdpath])

    # Go back
    os.chdir(prev_dir)

def write_html_cell(datasrc, rel, span):
    # Don't linkify non-existant plots
    if not os.path.exists(base_path(datasrc, rel, span, "plot")):
        return "n/a"
    base = rel_path(datasrc, rel, span)
    dat = base + 'dat'
    plot = base + 'plot'
    png = base + 'png'
    return '<a href="%s">Graph</a> (<a href="%s">r</a>, <a href="%s">p</a>)' % (png, dat, plot)

def release_name(rel):
    if cve_lib.release_name(rel):
        return str(cve_lib.release_name(rel)).capitalize()
    else:
        return rel.capitalize()

def generate_table(output, show="all"):
    '''Generate an HTML table. show can be one of:
         supported
         eol
         all
    '''
    shown_releases = set(info.keys())
    eol_releases = cve_lib.eol_releases + ['warty', 'hoary', 'breezy']
    merged_offset = 1
    if show == "eol":
        # only show eol releases, not 'all' and 'merged'
        shown_releases = set(info.keys()) & set(eol_releases)
        merged_offset = 0
    elif show == "supported":
        shown_releases = set(info.keys()) - set(eol_releases)

    print('''<p class='note'>Graphs with raw data ('r') and plot
commands ('p'). 'n/a' used when not enough data is available (eg, first month
of release or zeros for each month).</p>
<table>
<tr><th>Metric</th><th>Release</th><th>All Months</th><th>Last 12 Months</th></tr>
''', file=output)

    for datasrc in datasrcs:
        count = len(shown_releases) + merged_offset # add "merged"
        print('<tr><td rowspan="%d">%s</td>' % (count, details[datasrc]), file=output)
        releases = cve_lib.release_sort(shown_releases)
        releases.reverse()
        for rel in releases:
            print('<td>%s</td>' % (release_name(rel)), file=output)
            for span in ['all','12']:
                cell = write_html_cell(datasrc, rel, span)
                print('<td>%s</td>' % (cell), file=output)
            print('</tr>', file=output)

        if show != "eol":
            rel = 'merged'
            print('<td>%s</td>' % (release_name(rel)), file=output)
            for span in ['all','12']:
                cell = write_html_cell(datasrc, rel, span)
                print('<td>%s</td>' % (cell), file=output)
        print('</tr>', file=output)

    if show != "eol" and not opt.skip_new_cves:
        # new-cves row
        print('<tr><td>New CVEs</td><td>All</td><td><a href="new-cves.png">Graph</a> (<a href="new-cves.dat">r</a>, <a href="new-cves.plot">p</a>)</td></tr>', file=output)

    print('</table>', file=output)

def generate_highlights(outout):
    img_width = "100%"
    img_height = img_width
    print('''<table>
<tr>
  <td><p>USNs published per month</p><img src="USN_all_12.png" height="%s" width="%s"></td>
  <td><p>CVE fixes per month</p><img src="CVE-srcpkg-USN_all_12.png" height="%s" width="%s"></td>
</tr>
<tr>
  <td><p>Source packages fixed per month</p><img src="srcpkg_all_12.png" height="%s" width="%s"></td>
  <td><p>Regressions per month</p><img src="regression_all_12.png" height="%s" width="%s"></td>
</tr>
</table>
''' % (img_height, img_width, img_height, img_width, img_height, img_width, img_height, img_width),
          file=output)

# collect data sets
for usn in sorted(db.keys()):
    when = int(time.strftime('%Y%m', time.gmtime(int(db[usn]['timestamp']))))

    cves = set()

    regressions = set()
    if 'egression' in db[usn]['title']:
        regressions.add(usn)

    if len(regressions) == 0 and 'cves' in db[usn]:
        for cve in db[usn]['cves']:
            # Skip non-CVEs
            if cve.startswith('CVE-') or cve.startswith('CAN-'):
                cves.add(cve)

    srcs = set()
    for rel in db[usn]['releases']:
        if 'sources' in db[usn]['releases'][rel]:
            for src in db[usn]['releases'][rel]['sources']:
                srcs.add(src)
        else:
            # Assume that the early USNs updated a single srcpkg, so assume
            # that each USN was a unique src package.
            srcs.add('unknown-srcpkg_%s' % (usn))

    for rel in list(db[usn]['releases'].keys()) + ['all']:
        establish_release(rel, when)
        info[rel]['USN'][when].add(usn)
        info[rel]['CVE'][when].update(cves)
        info[rel]['srcpkg'][when].update(srcs)
        info[rel]['regression'][when].update(regressions)
        for src in srcs:
            for cve in cves:
                info[rel]['CVE-srcpkg'][when].add('%s_%s' % (cve, src))
                info[rel]['CVE-srcpkg-USN'][when].add('%s_%s_%s' % (cve, src, usn))

# Do a first pass on the data set sums, flagging anything that is all zeros.
# This can happen when there are no regressions in a release over several
# months (for example). Graphs default to [-1:1], which is weird
skip_graphs = []
for rel in info:
    for datasrc in datasrcs:
        has_valid_counts = False
        for when in info[rel][datasrc]:
            if len(info[rel][datasrc][when]) > 0:
                has_valid_counts = True
                break
        if not has_valid_counts:
            g = "%s:%s" % (rel, datasrc)
            skip_graphs.append(g)

# write out data set sums
for rel in info:
    for datasrc in datasrcs:
        g = "%s:%s" % (rel, datasrc)
        if g in skip_graphs:
            continue

        months = sorted(info[rel][datasrc])
        past = months[-1] - 100

        if len(months) == 1: # Skip first month of release (nothing to plot)
            continue

        for when in months:
            # Handle raw data
            count = len(info[rel][datasrc][when])
            write_report(rel, datasrc, when, 'all', count)
            if when > past:
                write_report(rel, datasrc, when, '12', count)

# explicitly close all raw data fds
for name in fds:
    fds[name].close()


# plot the data
for datasrc in datasrcs:
    releases = cve_lib.release_sort(info.keys())
    releases.reverse()
    for rel in releases:
        for span in ['all','12']:
            build_plot(rel, datasrc, span)
    releases.remove('all')
    for span in ['all','12']:
        build_merged_plot(releases, datasrc, span)

# generate CVE data and graphs
if not opt.skip_new_cves:
    generate_cve_additions()

# generate an index file to help guide navigation
output = open('%s/index.html' % (opt.target), 'w')
print('''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<title>Ubuntu Security Update Metrics</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="author" content="Canonical Ltd, Kees Cook and Jamie Strandboge" />
<meta name="description" content="Ubuntu Security Update Metrics" />
<meta name="copyright" content="Canonical Ltd" />
<link rel="StyleSheet" href="toplevel.css" type="text/css" />
</head>

<body>
<div id="container">
<h2>Ubuntu Security Update Metrics</h2>
<p class="intro">
This is a collection of metrics on security updates published in Ubuntu,
summarized from several perspectives. These metrics are regularly calculated
from the <a href="http://www.ubuntu.com/usn/">Ubuntu Security Notices</a> list.
</p>

<h3>Summary</h3>
''',
      file=output)
generate_highlights(output)

print('''<h3>Supported releases</h3>''', file=output)
generate_table(output, show="supported")

print('''<h3>End-of-life releases</h3>''', file=output)
generate_table(output, show="eol")

print('''
<p class='note'><a href="https://code.launchpad.net/~ubuntu-security/ubuntu-cve-tracker/master">Updated</a>: %s</p>
</div>
<div id="footer">
&copy; Canonical Ltd. 2007-%s
</div>

</body>
</html>
''' % (time.strftime('%Y-%m-%d %H:%M:%S %Z'), time.strftime('%Y')),
      file=output)
output.close()
