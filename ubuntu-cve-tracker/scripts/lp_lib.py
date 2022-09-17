#!/usr/bin/env python2

# Author: Kees Cook <kees@ubuntu.com>
# Author: Marc Deslauriers <marc.deslauriers@ubuntu.com>
# Copyright (C) 2011-2012 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 2 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# Lazy-loading LP interface.
from __future__ import print_function, absolute_import

import sys
try:
    import lpl_common
except:
    print("lpl_common.py seems to be missing. Please create a symlink from $UQT/common/lpl_common.py to $UCT/scripts/", file=sys.stderr)
    sys.exit(1)

class UCTLaunchpad(object):
    def __init__(self, opt):
        # Global LP connections/links
        self.link = dict()
        self.link['lp'] = None
        self.link['ubuntu'] = None
        self.link['archive'] = None
        self.link['people'] = None

        # Cached dictionaries
        self.cache = dict()
        self.cache['series'] = dict()

        # For get_release_version
        self.release_pkg_cache = dict()

        # Toggles
        self.debug = hasattr(opt, 'debug') and opt.debug

        self.lp_version = "1.0"

    def extract_task(self, task):
        return lpl_common.extract_task(task)

    def save(self, thing):
        return lpl_common.save(thing)

    def cached(self, field, name):
        if field not in self.cache:
            raise AttributeError("UCTLaunchpad has no cache named '%s'" % (field))
        if name in self.cache[field]:
            return self.cache[field][name]
        if field == 'series':
            if self.debug:
                print("API: getSeries(%s) ..." % (name), file=sys.stderr)
            self.cache[field][name] = self.ubuntu.getSeries(name_or_version=name)
        return self.cache[field][name]

    def __getattr__(self, name):
        if name not in self.link:
            raise AttributeError("UCTLaunchpad has no attr named '%s'" % (name))
        if self.link[name] != None:
            return self.link[name]
        if name == 'lp':
            if self.debug:
                print("Starting LP API ...", file=sys.stderr)
            self.link['lp'] = lpl_common.connect(version=self.lp_version)
            if self.debug:
                print("\tauthenticated to LP.", file=sys.stderr)
        elif name == 'ubuntu':
            if self.debug:
                print("Looking up Ubuntu distribution ...", file=sys.stderr)
            self.link['ubuntu'] = self.lp.distributions['ubuntu']
            if self.debug:
                print("\tUbuntu distribution found.", file=sys.stderr)
        elif name =='archive':
            if self.debug:
                print("Looking up Ubuntu archive ...", file=sys.stderr)
            self.link['archive'] = self.ubuntu.archives[0]
            if self.debug:
                print("\tUbuntu archive found.", file=sys.stderr)
        elif name =='people':
            if self.debug:
                print("Looking up Ubuntu people ...", file=sys.stderr)
            self.link['people'] = self.lp.people
            if self.debug:
                print("\tUbuntu people found.", file=sys.stderr)
        return self.link[name]

    # Searches all pockets for the first known version of a package. (Since
    # packages can be added to -updates post-release, we need to check all
    # pockets.) To find a version for a specific pocket, just override the list.
    def get_earliest_version(self, rel, pkg, key='earliest', pockets=['Release','Updates','Security','Proposed']):
      if rel not in self.release_pkg_cache or pkg not in self.release_pkg_cache[rel] or key not in self.release_pkg_cache[rel][pkg]:
        self.release_pkg_cache.setdefault(rel, dict())
        self.release_pkg_cache[rel].setdefault(pkg, dict())
        for pocket in pockets:
            if self.debug:
                print("get_earliest_version: getPublishedSources(%s, %s, %s) ..." % (rel, pocket, pkg), file=sys.stderr)
            # When looking at the release pocket, make sure to only look at the "Published"
            # status, so we don't get stuff from when the release was in development
            if pocket == 'Release':
                pkgs = self.archive.getPublishedSources(source_name=pkg, distro_series=self.cached('series',rel), pocket=pocket, status='Published', exact_match=True)
            else:
                pkgs = self.archive.getPublishedSources(source_name=pkg, distro_series=self.cached('series',rel), pocket=pocket, exact_match=True)
            if len(pkgs) < 1:
                if self.debug:
                    print("\tDNE", file=sys.stderr)
                continue
            # Oldest is last
            self.release_pkg_cache[rel][pkg][key] = pkgs[len(pkgs)-1].source_package_version
            if self.debug:
                print("\t%s" % (self.release_pkg_cache[rel][pkg][key]), file=sys.stderr)
            break
      # Recent dpkg doesn't consider "~" to be a valid version number
      self.release_pkg_cache[rel][pkg].setdefault(key, "0~")
      return self.release_pkg_cache[rel][pkg][key]

    # Searches all pockets for the latest version of a package.
    # To find a version for a specific pocket, just override the list.
    def get_latest_version(self, rel, pkg, key='latest', pockets=['Proposed', 'Updates', 'Security','Release']):
      if rel not in self.release_pkg_cache or pkg not in self.release_pkg_cache[rel] or key not in self.release_pkg_cache[rel][pkg]:
        self.release_pkg_cache.setdefault(rel, dict())
        self.release_pkg_cache[rel].setdefault(pkg, dict())
        for pocket in pockets:
            if self.debug:
                print("get_latest_version: getPublishedSources(%s, %s, %s) ..." % (rel, pocket, pkg), file=sys.stderr)
            pkgs = self.archive.getPublishedSources(source_name=pkg, distro_series=self.cached('series',rel), pocket=pocket, exact_match=True)
            if len(pkgs) < 1:
                if self.debug:
                    print("\tDNE", file=sys.stderr)
                continue
            # Newest is first
            self.release_pkg_cache[rel][pkg][key] = pkgs[0].source_package_version
            if self.debug:
                print("\t%s" % (self.release_pkg_cache[rel][pkg][key]), file=sys.stderr)
            break
      # Recent dpkg doesn't consider "~" to be a valid version number
      self.release_pkg_cache[rel][pkg].setdefault(key, "0~")
      return self.release_pkg_cache[rel][pkg][key]
