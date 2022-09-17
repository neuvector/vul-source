#!/usr/bin/env python2
# Copyright 2008-2009 Canonical, Ltd.
# Author: Jamie Strandboge <jamie@canonical.com>
# License: GPLv3
#
#
import sys, os, os.path, re, urllib, tempfile
import optparse, glob
import cve_lib

from launchpadlib.launchpad import Launchpad, EDGE_SERVICE_ROOT
from launchpadlib.credentials import Credentials
from launchpadlib.errors import HTTPError

print "DEPRECATED: please use:"
print "$ report-todo-sponsoring --status 'In Progress' --team ubuntu-security --has-patch"
sys.exit(0)

# Stolen from lpl_common.py from ubuntu-qa-tools
def connect():
    cachedir = os.path.expanduser('~/.launchpadlib/cache')
    if not os.path.exists(cachedir):
        os.makedirs(cachedir,0700)

    credfile = os.path.expanduser('~/.launchpadlib/credentials')
    try:
        credentials = Credentials()
        credentials.load(open(credfile))
        launchpad = Launchpad(credentials, EDGE_SERVICE_ROOT, cachedir)
    except:
        launchpad = Launchpad.get_token_and_login(sys.argv[0], EDGE_SERVICE_ROOT, cachedir)
        credfd = tempfile.NamedTemporaryFile(dir=os.path.dirname(credfile))
        launchpad.credentials.save(credfd)
        os.link(credfd.name, credfile)
        credfd.close()
    return launchpad

lp = connect()

parser = optparse.OptionParser()
parser.add_option("-u", "--update", dest="update", help="Update CVEs with released package versions", action='store_true')
parser.add_option("-v", "--verbose", dest="verbose", help="Report logic while processing USNs", action='store_true')
parser.add_option("-a", "--any", dest="any", help="Show any bugs with status NEW, CONFIRMED, TRIAGED, INPROGRESS, FIXCOMMITTED with a patch attached", action='store_true')
(opt, args) = parser.parse_args()

def get_cves(bug):
    cves = []
    if bug.cves != None:
        for c in bug.cves:
            cves.append("CVE-" + c.sequence)

    return cves

#
# This should be api-ified
# Need to figure out a way to get a list of bugs via an API query
#
from launchpadbugs.connector import ConnectBugList
BugList = ConnectBugList()
cve_lib.read_config()
BugList.authentication = cve_lib.config["plb_authentication"]

url="https://bugs.launchpad.net/~ubuntu-security/+bugs?field.searchtext=&orderby=-importance&field.status%3Alist=INPROGRESS&assignee_option=any&field.assignee=&field.bug_reporter=&field.bug_supervisor=&field.bug_commenter=&field.subscriber=&field.status_upstream-empty-marker=1&field.omit_dupes.used=&field.has_patch.used=&field.has_patch=on&field.has_cve.used=&field.tag=&field.tags_combinator=ANY&search=Search"
if opt.any:
    url="https://bugs.launchpad.net/~ubuntu-security/+bugs?field.searchtext=&orderby=-importance&field.status%3Alist=NEW&field.status%3Alist=CONFIRMED&field.status%3Alist=TRIAGED&field.status%3Alist=INPROGRESS&field.status%3Alist=FIXCOMMITTED&assignee_option=any&field.assignee=&field.bug_reporter=&field.bug_supervisor=&field.bug_commenter=&field.subscriber=ubuntu-security&field.status_upstream-empty-marker=1&field.omit_dupes.used=&field.omit_dupes=on&field.has_patch.used=&field.has_patch=on&field.has_cve.used=&field.tag=&field.tags_combinator=ANY&search=Search"
#
# end should be api-ified section
#

for info in BugList(url):
    num = info.bugnumber
    bug = lp.bugs[num]

    bug_url = "http://launchpad.net/bugs/%s" % (num)
    bug_cves = get_cves(bug)

    #print "Checking: %s" % (num)
    for task in bug.bug_tasks:
        #if task.status != "In Progress":
        #    continue

        if not ' (' in task.bug_target_name:
            #print "Skipping target name=%s" % (task.bug_target_name)
            continue
        pkg, target = task.bug_target_name.split(' (',1)
        target = target.split(')')[0]
        if ' ' in target:
            target, targeted_to = target.split(' ',1)

        if target and target.lower() != 'ubuntu':
            #print 'skipping target "%s" (%s)' % (target, pkg)
            continue
        if task.status in ['Fix Released', 'Invalid', "Won't Fix"]:
            #print 'skipping (pkg:%s status:%s)' % (pkg, task.status)
            continue

        if not re.match(r'^[a-z0-9][a-z0-9+\.\-]+$', pkg):
            print >>sys.stderr, "Bad package name '%s'" % (pkg)
            continue

        has_patch = False
        for a in bug.attachments:
            if a.type.lower() == "patch":
                has_patch = True
                break

        if has_patch:
            print "%s:\n  %s" % (pkg, bug_url)
            if opt.verbose:
                print "  %s" % (bug.title)

            if len(bug_cves) > 0:
                print "  CVES:",
                for c in bug_cves:
                    print "%s" % (c),
                    filename = "%s/%s" % (cve_lib.active_dir, c)
                    if opt.update and os.path.exists(filename):
                        cve_lib.add_patch(filename, pkg, bug_url, type)
                print ""
            print ""
            break

