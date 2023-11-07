#!/usr/bin/env python2

# Author: Kees Cook <kees@ubuntu.com>
# Author: Jamie Strandboge <jamie@ubuntu.com>
# Author: Marc Deslauriers <marc.deslauriers@canonical.com>
# Copyright (C) 2005-2016 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 2 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
from __future__ import print_function

import functools
import os
import subprocess
import sys
import urllib
from source_map import version_compare
import cve_lib

try:
    import cPickle
except ImportError:
    import pickle as cPickle



def load_database(db_filename='database.pickle'):
    '''Load usn database'''
    filename = os.path.expanduser(db_filename)
    if not os.path.isfile(filename):
        return {}
    with open(filename, 'rb') as f:
        if sys.version_info[0] == 3:
            db = cPickle.load(f, encoding='utf-8')
        else:
            db = cPickle.load(f)
    return db


# sync this with the operations in lp:usn-tool/usn.py
# XXX usn.py should move to UCT and make use of usn_lib.py
def save_database(database, db_filename='database.pickle'):
    '''Save usn database'''
    # Make sure we don't destroy the existing database when saving the
    # new one and we run out of disk space or hit some other error.
    orig = os.path.expanduser(db_filename)
    name = orig + ".saving"
    with open(name, "wb") as f:
        # Dump in pickle protocol version 2 so we remain compatible with
        # python 2
        cPickle.dump(database, f, 2)
    os.rename(name, orig)


def get_meta_list_contents(filename):
    # extract meta list info
    # format of meta list file is
    #   USN   CVE-ID
    meta_list = dict()
    if os.path.exists(filename):
        for line in open(filename):
            elements = line.rstrip().split(' ')
            usn = elements.pop(0)
            meta_list.setdefault(usn, set())
            for cve in elements:
                meta_list[usn].add(cve)

    return meta_list


def get_reverted(filename='meta_lists/reverted-CVEs.txt'):
    '''Get reverted USNs'''
    return get_meta_list_contents(filename)


def get_ignored_description(filename='meta_lists/ignored-modified-USN-descriptions.txt'):
    '''Get USNs to ignore description changes'''
    return get_meta_list_contents(filename)


# opt is expected to be an optarg generated data structure that may or
# may not contain the debug attribute
def debug(opt, msg):
    if (hasattr(opt, 'debug') and opt.debug):
        print("%s" % msg, file=sys.stderr)

def packages_dict(db, packages, releases=None, opt=object):
    '''Produce a list of packages that refer back to USNs'''
    pkgs = dict()

    for usn in sorted(db, key=functools.cmp_to_key(version_compare)):
        # This USN is ancient and lacks any CVE information
        if 'cves' not in db[usn]:
            debug(opt, "%s lacks CVEs" % (usn))
            continue

        for rel in db[usn]['releases']:
            # Ignore old USNs
            if 'sources' not in db[usn]['releases'][rel]:
                debug(opt, 'USN %s: skipping release %s' % (usn, rel))
                continue

            if releases and rel not in releases:
                continue

            # Look at fixed packages
            for pkg in packages:
                if pkg not in db[usn]['releases'][rel]['sources']:
                    continue

                pkgs.setdefault(pkg, dict())
                pkgs[pkg].setdefault(rel, dict())

                version = db[usn]['releases'][rel]['sources'][pkg]['version']
                if version in pkgs[pkg][rel]:
                    raise IndexError("Saw %s %s %s twice!" % (rel, pkg, version))
                pkgs[pkg][rel][version] = usn
    return pkgs


def _update_usn_description(db, usn):
    db[usn]['description'] = subprocess.check_output(['%s/pull-usn-desc.py' % (os.path.dirname(sys.argv[0])), '--prioritize'] + db[usn]['cves'])
    if 'XXX' in db[usn]['description']:
        raise ValueError("Missing descriptions in USN %s:\n%s" % (usn, db[usn]['description']))


def del_cves(db, usn, rm_cves=[]):
    cves = set(db[usn]['cves'])
    cves.difference_update(rm_cves)
    db[usn]['cves'] = sorted(cves)
    _update_usn_description(db, usn)


def add_cves(db, usn, new_cves=[]):
    db[usn]['cves'] = sorted(set(db[usn]['cves'] + new_cves))
    _update_usn_description(db, usn)


class USNdb(object):
    '''Class for encapsulating the USN database'''

    # XXX need to fix this to get the location of this from the uct
    # config if available
    db = None
    releases = None
    pkgs = None
    debug = False

    def __init__(self, packages, db=None, releases=None, opt=None):
        if db is not None:
            self.db_name = db
        if releases is not None:
            self.releases = releases
        if hasattr(opt, 'debug') and opt.debug:
            self.debug = True

        self.opt = opt
        self._load_db(db)
        self.pkgs = packages_dict(self.db, packages, self.releases, self.opt)

    def _load_db(self, db):
        db_name = "database.pickle"
        if db:
            db_name = db
        else:
            config = cve_lib.read_config()
            if config['usn_db_copy']:
                db_name = config['usn_db_copy']

        self.db_name = db_name
        self.db = load_database(self.db_name)

    def get_usns(self, pkg, release):
        if pkg not in self.pkgs:
            add_pkg = packages_dict(self.db, [pkg], [release], self.opt)
            if pkg in add_pkg:
                self.pkgs[pkg] = add_pkg[pkg]
        elif release not in self.pkgs[pkg]:
            add_pkg = packages_dict(self.db, [pkg], [release], self.opt)
            if pkg in add_pkg and release in add_pkg[pkg]:
                self.pkgs[pkg][release] = add_pkg[pkg][release]
        if pkg not in self.pkgs or release not in self.pkgs[pkg]:
            return None
        return sorted(self.pkgs[pkg][release], key=functools.cmp_to_key(version_compare), reverse=True)


# split_deb_package -> pkg_name, version, arch
# version DOES NOT INCLUDE EPOCH so possibly not accurate
def split_deb_package(pkg):
    tmp = pkg.split('_')
    pkg_name = tmp[0]
    version = tmp[1]
    arch = tmp[2].split('.')[0]
    return (pkg_name, version, arch)


# Not sure where this should belong, placing it here for the time being
#
# given an ubuntu archive package URL, return a tuple of:
#  (component, source package, binary package, version, arch)
# where:
#   pocket in [main, restricted, universe, multiverse]
#   source pkg
#   binary pkg
#   version -> pkg version DOES NOT INCLUDE EPOCH IF IT EXISTS
#   arch
def parse_archive_url(url):
    deb_path = urllib.parse.urlparse(url).path
    if deb_path.endswith('/pool/'):
        # bogus urls that sometimes show up
        return None

    prefix, deb = os.path.split(deb_path)
    bin_pkg, version, arch = split_deb_package(deb)

    prefix, src_pkg = os.path.split(prefix)

    component = os.path.basename(os.path.dirname(prefix))
    return (component, src_pkg, bin_pkg, version, arch)
