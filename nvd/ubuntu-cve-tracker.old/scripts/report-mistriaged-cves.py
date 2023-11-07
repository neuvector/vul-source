#!/usr/bin/env python3
# Author: Alex Murray <alex.murray@canonical.com>
# Copyright (C) 2019 Canonical Ltd.
#
# Reports CVEs that we have classified as not-for-us but which Debian
# has not ignored
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
import sys, os, os.path, optparse, cve_lib, re, subprocess, signal

def subprocess_setup():
    # Python installs a SIGPIPE handler by default. This is usually not what
    # non-Python subprocesses expect.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def runcmd(command, input=None,
           stderr=subprocess.STDOUT, stdout=subprocess.PIPE, stdin=None,
           shell=False):
    '''Try to execute given command (array) and return its stdout, or return
    a textual error if it failed.'''

    try:
        sp = subprocess.Popen(command,
                              stdin=stdin, stdout=stdout, stderr=stderr,
                              close_fds=True, shell=shell,
                              preexec_fn=subprocess_setup)
    except OSError as e:
        return [127, str(e)]

    out = sp.communicate(input)[0]
    if out:
        out = out.decode()
    return [sp.returncode, out]


def check_apt_cache(package):
    # try and determine if we can ignore pkgs if not in Ubuntu anymore
    (rc, madison) = runcmd(['/usr/bin/apt-cache', 'madison', package])
    if rc != 0:
        print("Could not spawn apt-cache madison. Result is: %s." % madison)
        sys.exit(1)

    results = []

    for l in madison.splitlines():
        # Make sure we don't get a substring match
        if (l.split('|')[0].strip() != package):
            continue
        # only want sources
        pkg_type = l.split('|')[2].strip().split(' ')[2]
        if (pkg_type != 'Sources'):
            continue
        # only want Ubuntu releases
        release_pocket_component = l.split('|')[2].strip().split(' ')[1]
        for release in cve_lib.all_releases:
            # we found a version in a matching Ubuntu release
            if release_pocket_component.find(release) >= 0:
                results.append(release_pocket_component)
    return results


# get base config for path to debian security tracker etc
config = cve_lib.read_config()

parser = optparse.OptionParser()
parser.add_option("-v", "--verbose", dest="verbose",
                  help="Report additional details", action='store_true')
parser.add_option("-n", "--not-for-us", dest="nfufile",
                  help="Path to the not-for-us.txt file",
                  default=os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                       os.path.pardir,
                                       "ignored", "not-for-us.txt"))
parser.add_option("-i", "--ignore", dest="ignorefile",
                  help="Path to the ignore-mistriaged.txt file",
                  default=os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                       os.path.pardir,
                                       "ignored", "ignore-mistriaged.txt"))
parser.add_option("-s", "--security-tracker", dest="securitytracker",
                  help="Path to the repo containing the Debian security tracker",
                  default=config['secure_testing_path'])
parser.add_option("-b", "--blame", dest="blame", help="Annotate output with git blame",
                  action='store_true')
(opt, args) = parser.parse_args()

cve_re = re.compile('CVE-\d{4}-\d{4,7}')

# get the list of CVEs which we have previously marked as ignored for
# reclassification
ignored = {}
with open(opt.ignorefile) as f:
    for line in f.readlines():
        # keep comments for later...
        bits = line.split('#', 1)
        comment = ''
        if len(bits) > 1:
            line = bits[0].strip()
            comment = '# ' + bits[1].strip()
        # extract each CVE out of the line since could have more than one in
        # a single line
        for cve in cve_re.findall(line):
            ignored[cve] = comment

dups = set()
# get the list of CVEs which we have classified as not-for-us
not_for_us = {}
lines = []
if opt.blame:
    (rc, blame) = runcmd(["git", "blame", "--show-email", opt.nfufile])
    if rc == 0:
        lines = blame.splitlines()
else:
    with open(opt.nfufile) as f:
        lines = f.readlines()
for line in lines:
    # keep comments for later...
    bits = line.split('#', 1)
    comment = ''
    email = None
    if len(bits) > 1:
        line = bits[0].strip()
        comment = bits[1].strip()
    if opt.blame:
        # we have blame info to parse as well
        email = line.split('<')[1].split('>')[0]
        line = line.split(')')[1].strip()
    # extract each CVE out of the line since could have more than one in
    # a single line
    for cve in cve_re.findall(line):
        if cve in not_for_us:
            dups.add(cve)
            not_for_us[cve][1] += ', ' + comment
        else:
            not_for_us[cve] = (email, comment)

if len(dups) > 0:
    print('Duplicate entries in not-for-us.txt: ' + ' '.join(dups))

# get the list of CVEs which Debian knows about
debian = cve_lib.load_debian_cves(cve_lib.config['secure_testing_path'] +
                                  '/data/CVE/list')

cache = {}
# show newest CVEs first
for cve in sorted(not_for_us.keys(), reverse=True):
    # allow to override check by adding IGNORE-MISTRIAGE in the comment
    # for the CVE in ignored/not-for-us.txt
    email = not_for_us[cve][0]
    comment = not_for_us[cve][1]
    if (cve not in ignored and
        comment.find('REJECT') == -1 and
        cve in debian and
        debian[cve]['state'] is not None and
        # ignore ones which debian is not sure about or is certain they
        # don't care about
        not (debian[cve]['state'].startswith('NOT-FOR-US') or
             debian[cve]['state'] == 'RESERVED' or
             debian[cve]['state'] == 'REJECTED')):
        # we only care if was FOUND in debian
        if debian[cve]['state'] == 'FOUND':
            pkgs = {}
            for pkg in debian[cve]['pkgs'].keys():
                # # ignore package if debian says is not affected
                if debian[cve]['pkgs'][pkg]['state'] == '<not-affected>':
                    continue
                if pkg not in cache:
                    result = check_apt_cache(pkg)
                    cache[pkg] = result
                result = cache[pkg]
                if len(result) > 0:
                    pkgs[pkg] = result
            if len(pkgs) > 0:
                print('%s %s # %s%s' % (cve, list(pkgs.keys()), comment, ''
                                        if email is None else ' [%s]' %
                                        email))
        else:
            print ("%s is in an unknown state %s " +
                   "in Debian security-tracker") % (cve, debian[cve]['state'])
