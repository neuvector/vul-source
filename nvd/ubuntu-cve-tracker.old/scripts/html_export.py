#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: Kees Cook <kees@ubuntu.com>
# Author: Jamie Strandboge <jamie@ubuntu.com>
# Copyright (C) 2005-2020 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
from __future__ import print_function

import re
import sys
import cve_lib
if sys.version_info[0] < 3:
    from urllib import quote
    from cgi import escape
else:
    from urllib.parse import quote
    from html import escape
from time import gmtime, strftime

# FIXME: detect and safely quote URLs

# on-demand initialized during pkg exports
map = None

all_releases = cve_lib.all_releases
releases = [] + all_releases

for eol in cve_lib.eol_releases:
    if eol in releases:
        releases.remove(eol)

def html_header(title, description, outfd):
    print('''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<!-- Global site tag (gtag.js) - Google Analytics -->
<script async src="https://www.googletagmanager.com/gtag/js?id=UA-96529618-15"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());

  gtag('config', 'UA-96529618-15');
</script>
<title>%s</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="author" content="Canonical Ltd, and others" />
<meta name="description" content="%s" />
<meta name="copyright" content="Canonical Ltd, and others" />

<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
<link rel="stylesheet" href="../css/starter-template.css">
<link rel="stylesheet" href="../css/cve_tracker.css" type="text/css" />
<link rel="stylesheet" href="../css/cve.css" type="text/css" />
</head>

<body>
<nav class="navbar navbar-expand navbar-dark bg-dark navbar-fixed-top cve-tracker-navbar">
    <a class="navbar-brand" href="https://launchpad.net/ubuntu-cve-tracker">Ubuntu CVE Tracker</a>
    <div id="cve-tracker-navbar" class="collapse navbar-collapse">
      <ul class="navbar-nav">
        <li class="nav-item"><a class="nav-link" href="..">Home</a></li>
        <li class="nav-item"><a class="nav-link" href="../main.html">Main</a></li>
        <li class="nav-item"><a class="nav-link" href="../universe.html">Universe</a></li>
      </ul>
    </div><!--/.nav-collapse -->
</nav>

<div id="container" class="container">

<div class="starter-template">
<div class="card" id="body-card">
''' % (escape(title), escape(description, quote=True)), file=outfd)

def html_footer(outfd, commit=None):
    print('<p class="note commit"><a href="https://code.launchpad.net/ubuntu-cve-tracker/+git">Updated</a>: %s' % (strftime("%F %T UTC", gmtime())), end=' ', file=outfd)
    if commit:
        print(' (commit <a href="https://git.launchpad.net/ubuntu-cve-tracker/commit/?id=%s">%s</a>)' % (commit, commit), end=' ', file=outfd)
    print('</p>', file=outfd)

    print('<div id="footer">', file=outfd)
    print('&copy; Canonical Ltd. 2007-%s' % (strftime("%Y", gmtime())), file=outfd)
    print('</div><!-- footer -->', file=outfd)
    print('</div><!-- card-body -->', file=outfd)
    print('</div><!-- card -->', file=outfd)
    print('</div><!-- starter-template -->', file=outfd)
    print('</div> <!-- container -->', file=outfd)
    print('<!-- Bootstrap core JavaScript', file=outfd)
    print('================================================== -->', file=outfd)
    print('<!-- Placed at the end of the document so the pages load faster -->', file=outfd)
    print('<script src="https://code.jquery.com/jquery-3.2.1.slim.min.js" integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/GpGFF93hXpG5KkN" crossorigin="anonymous"></script>', file=outfd)
    print('<script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js" integrity="sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q" crossorigin="anonymous"></script>', file=outfd)
    print('</body>', file=outfd)
    print('</html>', file=outfd)


def lookup_priority_class(priority):
    '''Takes priority string, converts to html div class'''

    canon_pri = escape(priority).lower()
    value_class = "value"
    if canon_pri == "negligible":
        value_class = "negligible-value"
    elif canon_pri == "low":
        value_class = "low-value"
    elif canon_pri == "medium":
        value_class = "medium-value"
    elif canon_pri == "high":
        value_class = "high-value"
    elif canon_pri == "critical":
        value_class = "critical-value"

    return value_class

def htmlize_field(field, text):
    escaped_body = ""
    pre_block = False
    for line in text.split('\n'):
        if ((field == "References" or field == "Bugs") and
            re.match('^http[s]?://', line)):
            # Drop trailing information from URL
            url = line.split()[0]
            escaped_body += ('<a href="%s">%s</a><br />' %
                             (quote(escape(url), ':/?&;=#'), escape(line)))
        else:
            # ensure line is escaped
            line = escape(line)
            if line[0] == ' ' and line[1] == ' ':
                # lines starting with double spaces get pre-formatted
                if pre_block:
                    escaped_body += '\n' + line[2:]
                else:
                    pre_block = True
                    escaped_body += '\n<pre>%s' % line[2:]
            else:
                if pre_block:
                    escaped_body += '</pre>\n'
                escaped_body += '%s<br />' % line
                pre_block = False
    return escaped_body


def htmlize_cve(cvefile, outfd, commit=None):
    data = cve_lib.load_cve(cvefile)

    #import pprint
    #pp = pprint.PrettyPrinter(indent=4)
    #pp.pprint(data)

    cve = data['Candidate']

    html_header('%s in Ubuntu' % cve, 'Ubuntu %s Entry' % cve, outfd)

    # CVE cross links
    heading = quote(cve)
    print('<h3 class="card-header">%s</h3>' % (heading), file=outfd)
    print('<div class="card-body text-left">', file=outfd)

    # Handle "free-form" text
    for field in ['Priority', 'Description', 'Ubuntu-Description', 'References', 'Bugs', 'Mitigation', 'Assigned-to']:
        if field not in data:
            continue
        text = data[field].strip()
        if len(text) == 0:
            continue
        escaped_body = htmlize_field(field, text)
        if field == "Priority":
            # CVEs that are marked not-for-us should not display priority.
            if text == 'not-for-us':
                continue
            escaped_body = '<a href="../priority.html">' + escaped_body.capitalize() + '</a>'

        print('<div class="item"><div class="field">%s</div> <div>%s</div></div>' % (escape(field), escaped_body), file=outfd)

    # Notes are special
    if 'Notes' in data:
        print('<div class="item"><div class="field">Notes</div><div>', file=outfd)
        print('<table class="table table-responsive">', file=outfd)
        for (user, note) in data['Notes']:
            print(('<tr><td class="user">%s</td><td class="note">%s</td></tr>' %
                            # preserve line breaks
                            (escape(user), escape(note).replace("\n", "<br />\n"))), file=outfd)
        print('</table>', file=outfd)
        print('</div></div>', file=outfd)

    # Handle package logic
    for pkg in sorted(data['pkgs']):
        print('<div class="pkg">', file=outfd)
        if 'product' in data['pkgs'][pkg].keys():
            print('<div class="field">Product</div><div class="value">Source tree: ' + \
                '<a href="%s">%s</a>' % (escape(cve_lib.supported_products[pkg][0]), escape(cve_lib.supported_products[pkg][0])) + \
                '</div>', file=outfd)
        elif 'snap' in data['pkgs'][pkg].keys():
            print('<div class="field">Snap</div><div class="value">Store: ' + \
                '<a href="https://snapcraft.io/%s">%s</a>' % (escape(pkg), escape(pkg)) + \
                '</div>', file=outfd)
        else:
            print('<div class="field">Package</div><div>Source: ' + \
                '<a href="../pkg/%s.html">%s</a> ' % (quote(pkg), escape(pkg)) + \
                '(' + \
                '<a href="https://launchpad.net/distros/ubuntu/+source/%s">LP</a> ' % (quote(pkg)) + \
                '<a href="https://packages.ubuntu.com/search?suite=all&amp;section=all&amp;arch=any&amp;searchon=sourcenames&amp;keywords=%s">Ubuntu</a> ' % (quote(pkg)) + \
                '<a href="https://tracker.debian.org/%s">Debian</a>' % (quote(pkg)) + \
                ')</div>', file=outfd)

        if 'Priority_%s' % pkg in data:
            # per package priority override exists
            priority_override = escape(data['Priority_%s' % pkg]).capitalize()
            #value_class = lookup_priority_class(priority_override)
            print('<div>Priority: %s</div>' % (priority_override), file=outfd)
            #print('<div class="item"><div class="value">Priority:</div> <div class="%s">%s</div></div>' % (value_class, priority_override), file=outfd)

        print('<table class="table table-responsive">', file=outfd)

        # figure out what the development release was based on the releases
        # in the CVE
        # Bah, this should just be a separate function to determine the
        # devel release given a list of releases.
        cve_devel_release = cve_lib.devel_release
        cve_releases = data['pkgs'][pkg].keys()
        for skip_release in ['upstream', 'devel', 'product', 'snap']:
            if skip_release  in cve_releases:
                cve_releases.remove(skip_release)

        if len(cve_releases) > 0:
            cve_releases = cve_lib.release_sort(cve_releases)
            try:
                index = all_releases.index(cve_releases[-1]) + 1
                if index < len(all_releases) and all_releases[index]:
                    cve_devel_release = all_releases[index]
            except:
                pass
        if cve_devel_release not in releases:
            cve_devel_release = 'EOL ' + cve_devel_release

        release_list = ['upstream', 'product', 'snap'] + releases
        for release in release_list:
            relname = release

            if relname == cve_devel_release:
                release = 'devel'

            if release not in data['pkgs'][pkg]:
                continue

            status = data['pkgs'][pkg][release][0]
            notes  = data['pkgs'][pkg][release][1]

            release_title = cve_lib.release_name(relname)
            if not release_title:
                release_title = relname.capitalize()
                if relname == 'product' or relname == 'snap':
                    release_title = quote(pkg)
            name = '%s' % (escape(release_title))
            if status != 'DNE' and relname != 'upstream' and relname != 'product' and relname != 'snap' and '/' not in relname:
                name = '<a href="https://launchpad.net/ubuntu/%s/+source/%s">%s</a>' % (quote(relname), quote(pkg), escape(release_title))

            status_class = "default"
            if status in ['needed', 'active', 'deferred']:
                status_class = "vuln"
            elif status in cve_lib.status_closed:
                status_class = "safe"
            elif status == 'pending':
                status_class = "pending"

            print('<tr><td>%s:</td><td><span class="%s">%s</span>' % (name, status_class, status), file=outfd)
            if len(notes):
                print('(%s)' % (escape(notes)), file=outfd)
            print('</td></tr>', file=outfd)
        print('</table>', file=outfd)

        if pkg in data['patches']:
            print('<div class="patches">Patches:</div>', file=outfd)
            print('<table class="table table-responsive patches">', file=outfd)
            for source, url in data['patches'][pkg]:
                # We need to handle the line info first, since it may have
                # additional info as (master) or something else after the patch
                # url.
                url_line_info = url.split(' ')[1:]
                url_additional_info = ''
                if len(url_line_info) > 1:
                    url = url_line_info[0]
                    url_additional_info = url_line_info[1]
                    url_additional_info.strip()

                url = url.strip()
                if source == "break-fix" and " " in url:
                    introduced, fixed = url.split(' ', 1)
                    if introduced == '-':
                        # First commit to Linux git tree
                        introduced = '1da177e4c3f41524e886b7f1b8a0c1fc7321cac2'
                    print('<tr><td>Introduced by <pre><a href="https://git.kernel.org/linus/%s">%s</a></pre></td><td>Fixed by <pre><a href="https://git.kernel.org/linus/%s">%s</a></pre></td></tr>' % (introduced, introduced, fixed, fixed), file=outfd)
                else:
                    if re.match('^(ftp|http)[s]?://', url):
                        print('<tr><td>%s:</td><td><a href="%s">%s %s</a></td></tr>' % (escape(source).capitalize(), url.replace('"', '%22'), escape(url), url_additional_info), file=outfd)
                    else:
                        print('<tr><td>%s:</td><td>%s</td></tr>' % (escape(source).capitalize(), escape(url)), file=outfd)
            print('</table>', file=outfd)

        # tags
        urlregex = re.compile(r"(http[^\s]+)")
        if pkg in data['tags']:
            tags = data['tags'][pkg]
            for tag in tags:
                # linkify any url in description
                description = cve_lib.valid_tags[tag]
                description = re.sub(urlregex, '<a href="\\1">\\1</a>',
                                     description)
                print('<div>%s</div>' % (description), file=outfd)

        print('</div>', file=outfd)

    print('<div class="item">', file=outfd)
    print('<div class="field">More Information</div>', file=outfd)
    print('<ul class="links"><li><a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s">Mitre</a></li><li><a href="https://nvd.nist.gov/nvd.cfm?cvename=%s">NVD</a></li><li><a href="https://launchpad.net/bugs/cve/%s">Launchpad</a></li><li><a href="https://security-tracker.debian.org/tracker/%s">Debian</a></li></ul>' % (quote(cve), quote(cve), quote(cve), quote(cve)), file=outfd)
    print('</div>', file=outfd)

    html_footer(outfd, commit)

def htmlTableHeader(headings):
    header = '<thead class="thead-dark"><tr><th>CVE</th>'
    for heading in headings:
        name = heading
        header += "<th>%s</th>" % (name.capitalize())
    #header += '<th>Links</th><th>Notes</th>'
    header += '</tr></thead>'
    return header

# Produces HTML for a given source package.
def htmlize_package(outfd, pkg, cvefiles, commit=None):
    html_header('%s CVEs in Ubuntu' % pkg, 'Ubuntu Package CVE Entry for %s' % pkg, outfd)
    print('<h2 class="card-header">Package: %s</h2>' % (quote(pkg)), file=outfd)
    print('<div class="card-body text-left">', file=outfd)

    notes = set()

    # Loading the source map is expensive, which is unfortunate.  We will
    # do it only for pkg html output, since the generate-pkg-makefile script
    # is already trying to minimize how much we run this function.
    global map
    if not map:
        import source_map
        map = source_map.load()

    # Merged package reports (linux-source-2.6.15 should appear in
    # linux) only work when a package (linux) does not exist in a given
    # release (dapper) but the replacement does (linux-source-2.6.15).
    # So, figure out which pkg should be used for lookups in each in release:
    pkgname = dict()
    for rel in releases:
        rel_orig = rel
        if rel == cve_lib.devel_release:
            rel = 'devel'
        pkgname[rel_orig] = pkg
        if pkg not in map[rel_orig] and pkg in cve_lib.pkg_aliases:
            # Aliases: 'linux-source-2.6.15' should appear in 'linux' output
            for alias in cve_lib.pkg_aliases[pkg]:
                if alias in map[rel_orig]:
                    #print >>sys.stderr, "\tfound alias '%s' for '%s'" % (alias, pkg)
                    pkgname[rel_orig] = alias
                    notes.add('CVEs from <a href="%s.html">%s</a> in %s have been merged into this report' % (quote(alias), escape(alias), escape(rel_orig)))
                    break

    # For a given source package, if it is supported for a release, but
    # there is a CVE that is marked as affecting a universe binary only,
    # we need to mark it as "community supported".  Start by building up
    # a map of supportability per-release for the source package.
    starred = False
    src_supported = dict()
    headings = []
    entire_release_starred = set()
    for rel in releases:
        heading = rel
        if '/' in rel:
            (base, ppa) = rel.split('/')
            heading = "%s/" % (base)
            if ppa == "ubuntu-core":
                heading += "Core"
            elif ppa == "stable-phone-overlay":
                heading += "Touch"
            else:  # abbreviate the ppa name if we don't know about it
                for i in ppa.split('-'):
                    heading += i[0]

        src_supported[rel] = False
        if pkgname[rel] and pkgname[rel] in map[rel]:
            src_supported[rel] = cve_lib.is_supported(map, pkgname[rel], rel)
            if not src_supported[rel]:
                starred = True
                entire_release_starred.add(rel)
                heading += "*"
        headings.append(heading)

    if len(cvefiles) == 0:
        print('<div class="item text-center"><h3>Status</h3> <div class="value">No known vulnerable public CVEs</div></div>', file=outfd)
    else:
        cvefiles.sort(cve_lib.cve_sort)
        print('<div class="item text-center"><h3>Status</h3> <div class="value">%d known public CVEs</div></div>' % (len(cvefiles)), file=outfd)

        if len(notes) > 0:
            print('<div class="item text-center"><h3>Notes</h3>', file=outfd)
            for note in sorted(notes):
                print('<div class="value">%s</div>' % (note), file=outfd)
            print('</div>', file=outfd)

        print('<h3 class="text-center">CVEs</h3>', file=outfd)
        print('<table id="cves" class="table table-bordered table-hover text-center">' + htmlTableHeader(headings), file=outfd)
        for cvefile in cvefiles:
            data = cve_lib.load_cve(cvefile)

            # Sort out priority
            priority = cve_lib.contextual_priority(data)[1]
            print('<tr class="%s">' % (quote(priority)), end=' ', file=outfd)

            # fields...
            # 'pkgs' -> dict(  pkg -> dict(  release ->  (state, notes)   ) )
            cve = data['Candidate']
            #print >>sys.stderr, 'cve: %s' % (cve)
            print('<td class="cve"><a href="../%s">%s</a></td>' % (quote(cve), escape(cve)), end=' ', file=outfd)
            for rel in releases:
                rel_orig = rel
                if rel == cve_lib.devel_release:
                    rel = 'devel'

                report_pkg = pkgname[rel_orig]

                # Sort out priority override
                priority_override = cve_lib.contextual_priority(data, pkg=report_pkg, rel=rel)[1]
                #print >>sys.stderr, '\tlooking for %s' % (report_pkg)
                if report_pkg in data['pkgs'] and rel in data['pkgs'][report_pkg]:
                    pkgstatus = data['pkgs'][report_pkg][rel][0]
                    pkgnotes = data['pkgs'][report_pkg][rel][1]
                    pkgclass = pkgstatus
                    #print >>sys.stderr, '\t\tstatus for %s is %s' % (report_pkg, pkgclass)

                    if pkgclass == 'DNE':
                        pkgstatus = "--"
                    if pkgstatus == 'pending' and pkgnotes != '':
                        pkgclass = 'pendingversion'
                    priority_class = ""
                    priority_start = ""
                    priority_end = ""
                    if priority_override != priority:
                        priority_class = " override"
                        priority_start = '<div class="%s">' % (quote(priority_override))
                        priority_end = '</div>'

                    # Sort out supportability override
                    if pkgstatus not in ["--", "not-affected"] and \
                       src_supported[rel_orig] and \
                       not cve_lib.is_supported(map, report_pkg, rel_orig, data):
                        starred = True
                        pkgstatus += "*"

                    print('<td class="%s%s">%s%s%s</td>' % (quote(pkgclass), priority_class, priority_start, escape(pkgstatus), priority_end), end=' ', file=outfd)
                else:
                    print('<td class="DNE">--</td>', end=' ', file=outfd)
            print('</tr>', file=outfd)
        print('</table>', file=outfd)
        if starred:
            print('<p class="note text-right">* community supported</p>', file=outfd)

    html_footer(outfd, commit)
