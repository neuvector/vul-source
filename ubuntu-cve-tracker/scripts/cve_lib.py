#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: Kees Cook <kees@ubuntu.com>
# Author: Jamie Strandboge <jamie@ubuntu.com>
# Copyright (C) 2005-2017 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
from __future__ import print_function

import codecs
import datetime
import glob
import math
import os
import re
import signal
import subprocess
import sys
import time
import cache_urllib
import json
import yaml

from functools import reduce

def set_cve_dir(path):
    '''Return a path with CVEs in it. Specifically:
       - if 'path' has CVEs in it, return path
       - if 'path' is a relative directory with no CVEs, see if UCT is defined
         and if so, see if 'UCT/path' has CVEs in it and return path
    '''
    p = path
    found = False
    if len(glob.glob("%s/CVE-*" % path)) > 0:
        found = True
    elif not path.startswith('/') and 'UCT' in os.environ:
        tmp = os.path.join(os.environ['UCT'], path)
        if len(glob.glob("%s/CVE-*" % tmp)) > 0:
            found = True
            p = tmp
            #print("INFO: using '%s'" % p, file=sys.stderr)

    if not found:
        print("WARN: could not find CVEs in '%s' (or relative to UCT)" % path, file=sys.stderr)
    return p

if 'UCT' in os.environ:
    active_dir = set_cve_dir(os.environ['UCT'] + "/active")
    retired_dir = set_cve_dir(os.environ['UCT'] + "/retired")
    ignored_dir = set_cve_dir(os.environ['UCT'] + "/ignored")
    embargoed_dir = os.environ['UCT'] + "/embargoed"
    meta_dir = os.path.join(os.environ['UCT'], 'meta_lists')
    subprojects_dir = os.environ['UCT'] + "/subprojects"
    boilerplates_dir = os.environ['UCT'] + "/boilerplates"
else:
    active_dir = set_cve_dir("active")
    retired_dir = set_cve_dir("retired")
    ignored_dir = set_cve_dir("ignored")
    embargoed_dir = "embargoed"     # Intentionally not using set_cve_dir()
    meta_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'meta_lists')
    subprojects_dir = "subprojects"
    boilerplates_dir = "boilerplates"

PRODUCT_UBUNTU = "ubuntu"
PRIORITY_REASON_REQUIRED = ["low", "high", "critical"]
PRIORITY_REASON_DATE_START = "2023-07-11"

# common to all scripts
# these get populated by the contents of subprojects defined below
all_releases = []
eol_releases = []
external_releases = []
releases = []
devel_release = ""

# known subprojects which are supported by cve_lib - in general each
# subproject is defined by the combination of a product and series as
# <product/series>.
#
# For each subproject, it is either internal (ie is part of this static
# dict) or external (found dynamically at runtime by
# load_external_subprojects()).
#
# eol specifies whether the subproject is now end-of-life.  packages
# specifies list of files containing the names of supported packages for the
# subproject. alias defines an alternate preferred name for the subproject
# (this is often used to support historical names for projects etc).
subprojects = {
    "stable-phone-overlay/vivid": {
        "eol": True,
        "packages": ["vivid-stable-phone-overlay-supported.txt"],
        "name": "Ubuntu Touch 15.04",
        "alias": "vivid/stable-phone-overlay",
    },
    "ubuntu-core/vivid": {
        "eol": True,
        "packages": ["vivid-ubuntu-core-supported.txt"],
        "name": "Ubuntu Core 15.04",
        "alias": "vivid/ubuntu-core",
    },
    "esm/precise": {
        "eol": True,
        "packages": ["precise-esm-supported.txt"],
        "name": "Ubuntu 12.04 ESM",
        "codename": "Precise Pangolin",
        "alias": "precise/esm",
        "ppa": "ubuntu-esm/esm/ubuntu",
        "parent": "ubuntu/precise",
        "description": "Available with UA Infra or UA Desktop: https://ubuntu.com/advantage",
        "stamp": 1493521200,
    },
    "esm/trusty": {
        "eol": False,
        "oval": True,
        "packages": ["trusty-esm-supported.txt"],
        "name": "Ubuntu 14.04 ESM",
        "codename": "Trusty Tahr",
        "alias": "trusty/esm",
        "ppa": "ubuntu-esm/esm-infra-security/ubuntu",
        "parent": "ubuntu/trusty",
        "description": "Available with Ubuntu Pro (Infra-only): https://ubuntu.com/pro",
        "stamp": 1556593200,
    },
    "esm-infra/xenial": {
        "eol": False,
        "oval": True,
        "components": ["main", "restricted"],
        "packages": ["esm-infra-xenial-supported.txt"],
        "name": "Ubuntu 16.04 ESM",
        "codename": "Xenial Xerus",
        "ppa": "ubuntu-esm/esm-infra-security/ubuntu",
        "parent": "ubuntu/xenial",
        "description": "Available with Ubuntu Pro (Infra-only): https://ubuntu.com/pro",
        "stamp": 1618963200,
    },
    "esm-infra/bionic": {
        "eol": False,
        "oval": True,
        "components": ["main", "restricted"],
        "packages": ["esm-infra-bionic-supported.txt"],
        "name": "Ubuntu 18.04 ESM",
        "codename": "Bionic Beaver",
        "ppa": "ubuntu-esm/esm-infra-security/ubuntu",
        "parent": "ubuntu/bionic",
        "description": "Available with Ubuntu Pro (Infra-only): https://ubuntu.com/pro",
        "stamp": 1685539024,
    },
    "esm-apps/xenial": {
        "eol": False,
        "oval": True,
        "components": ["universe", "multiverse"],
        "packages": ["esm-apps-xenial-supported.txt"],
        "name": "Ubuntu 16.04 ESM",
        "codename": "Xenial Xerus",
        "ppa": "ubuntu-esm/esm-apps-security/ubuntu",
        "parent": "esm-infra/xenial",
        "description": "Available with Ubuntu Pro: https://ubuntu.com/pro",
        "stamp": 1618963200,
    },
    "esm-apps/bionic": {
        "eol": False,
        "oval": True,
        "components": ["universe", "multiverse"],
        "packages": ["esm-apps-bionic-supported.txt"],
        "name": "Ubuntu 18.04 ESM",
        "codename": "Bionic Beaver",
        "ppa": "ubuntu-esm/esm-apps-security/ubuntu",
        "parent": "esm-infra/bionic",
        "description": "Available with Ubuntu Pro: https://ubuntu.com/pro",
        "stamp": 1524870000,
    },
    "esm-apps/focal": {
        "eol": False,
        "oval": True,
        "components": ["universe", "multiverse"],
        "packages": ["esm-apps-focal-supported.txt"],
        "name": "Ubuntu 20.04 ESM",
        "codename": "Focal Fossa",
        "ppa": "ubuntu-esm/esm-apps-security/ubuntu",
        "parent": "ubuntu/focal",
        "description": "Available with Ubuntu Pro: https://ubuntu.com/pro",
        "stamp": 1587567600,
    },
    "esm-apps/jammy": {
        "eol": False,
        "oval": True,
        "components": ["universe", "multiverse"],
        "packages": ["esm-apps-jammy-supported.txt"],
        "name": "Ubuntu 22.04 ESM",
        "codename": "Jammy Jellyfish",
        "ppa": "ubuntu-esm/esm-apps-security/ubuntu",
        "parent": "ubuntu/jammy",
        "description": "Available with Ubuntu Pro: https://ubuntu.com/pro",
        "stamp": 1650693600,
    },
    "fips/xenial": {
        "eol": False,
        "oval": True,
        "packages": ["fips-xenial-supported.txt"],
        "name": "Ubuntu 16.04 FIPS Certified",
        "codename": "Xenial Xerus",
        "ppa": "ubuntu-advantage/fips/ubuntu",
        "parent": "ubuntu/xenial",
        "description": "Available with Ubuntu Pro: https://ubuntu.com/pro",
    },
    "fips/bionic": {
        "eol": False,
        "oval": True,
        "packages": ["fips-bionic-supported.txt"],
        "name": "Ubuntu 18.04 FIPS Certified",
        "codename": "Bionic Beaver",
        "ppa": "ubuntu-advantage/fips/ubuntu",
        "parent": "ubuntu/bionic",
        "description": "Available with Ubuntu Pro: https://ubuntu.com/pro",
    },
    "fips/focal": {
        "eol": False,
        "oval": True,
        "packages": ["fips-focal-supported.txt"],
        "name": "Ubuntu 20.04 FIPS Certified",
        "codename": "Focal Fossa",
        "ppa": "ubuntu-advantage/fips/ubuntu",
        "parent": "ubuntu/bionic",
        "description": "Available with Ubuntu Pro: https://ubuntu.com/pro",
    },
    "fips-updates/xenial": {
        "eol": False,
        "oval": True,
        "packages": ["fips-updates-xenial-supported.txt"],
        "name": "Ubuntu 16.04 FIPS Compliant",
        "codename": "Xenial Xerus",
        "ppa": "ubuntu-advantage/fips-updates/ubuntu",
        "parent": "ubuntu/xenial",
        "description": "Available with Ubuntu Pro: https://ubuntu.com/pro",
    },
    "fips-updates/bionic": {
        "eol": False,
        "oval": True,
        "packages": ["fips-updates-bionic-supported.txt"],
        "name": "Ubuntu 18.04 FIPS Compliant",
        "codename": "Bionic Beaver",
        "ppa": "ubuntu-advantage/fips-updates/ubuntu",
        "parent": "ubuntu/bionic",
        "description": "Available with Ubuntu Pro: https://ubuntu.com/pro",
    },
    "fips-updates/focal": {
        "eol": False,
        "oval": True,
        "packages": ["fips-updates-focal-supported.txt"],
        "name": "Ubuntu 20.04 FIPS Compliant",
        "codename": "Focal Fossa",
        "ppa": "ubuntu-advantage/fips-updates/ubuntu",
        "parent": "ubuntu/bionic",
        "description": "Available with Ubuntu Pro: https://ubuntu.com/pro",
    },
    "ros-esm/kinetic": {
        "eol": False,
        "oval": False,
        "packages": ["ros-esm-xenial-kinetic-supported.txt"],
        "name": "Ubuntu 16.04 ROS ESM",
        "codename": "Xenial Xerus",
        "alias": "ros-esm/xenial",
        "ppa": "ubuntu-robotics-packagers/ros-security/ubuntu",
        "parent": "ubuntu/xenial",
        "description": "Available with Ubuntu Advantage: https://ubuntu.com/advantage",
    },
    "ros-esm/melodic": {
        "eol": False,
        "oval": False,
        "packages": ["ros-esm-bionic-melodic-supported.txt"],
        "name": "Ubuntu 18.04 ROS ESM",
        "codename": "Bionic Beaver",
        "alias": "ros-esm/bionic",
        "ppa": "ubuntu-robotics-packagers/ros-security/ubuntu",
        "parent": "ubuntu/bionic",
        "description": "Available with Ubuntu Advantage: https://ubuntu.com/advantage",
    },
    "ubuntu/warty": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 4.10",
        "version": 4.10,
        "codename": "Warty Warthog",
        "alias": "warty",
        "description": "Interim Release",
        "stamp": 1098748800,
    },
    "ubuntu/hoary": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 5.04",
        "version": 5.04,
        "codename": "Hoary Hedgehog",
        "alias": "hoary",
        "description": "Interim Release",
        "stamp": 1112918400,
    },
    "ubuntu/breezy": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 5.10",
        "version": 5.10,
        "codename": "Breezy Badger",
        "alias": "breezy",
        "description": "Interim Release",
        "stamp": 1129075200,
    },
    "ubuntu/dapper": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 6.06 LTS",
        "version": 6.06,
        "codename": "Dapper Drake",
        "alias": "dapper",
        "description": "Long Term Support",
        "stamp": 1149120000,
    },
    "ubuntu/edgy": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 6.10",
        "version": 6.10,
        "codename": "Edgy Eft",
        "alias": "edgy",
        "description": "Interim Release",
        "stamp": 1161864000,
    },
    "ubuntu/feisty": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 7.04",
        "version": 7.04,
        "codename": "Feisty Fawn",
        "alias": "feisty",
        "description": "Interim Release",
        "stamp": 1176984000,
    },
    "ubuntu/gutsy": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 7.10",
        "version": 7.10,
        "codename": "Gutsy Gibbon",
        "alias": "gutsy",
        "description": "Interim Release",
        "stamp": 1192708800,
    },
    "ubuntu/hardy": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 8.04 LTS",
        "version": 8.04,
        "codename": "Hardy Heron",
        "alias": "hardy",
        "description": "Long Term Support",
        "stamp": 1209038400,
    },
    "ubuntu/intrepid": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 8.10",
        "version": 8.10,
        "codename": "Intrepid Ibex",
        "alias": "intrepid",
        "description": "Interim Release",
        "stamp": 1225368000,
    },
    "ubuntu/jaunty": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 9.04",
        "version": 9.04,
        "codename": "Jaunty Jackalope",
        "alias": "jaunty",
        "description": "Interim Release",
        "stamp": 1240488000,
    },
    "ubuntu/karmic": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 9.10",
        "version": 9.10,
        "codename": "Karmic Koala",
        "alias": "karmic",
        "description": "Interim Release",
        "stamp": 1256817600,
    },
    "ubuntu/lucid": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 10.04 LTS",
        "version": 10.04,
        "codename": "Lucid Lynx",
        "alias": "lucid",
        "description": "Long Term Support",
        "stamp": 1272565800,
    },
    "ubuntu/maverick": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 10.10",
        "version": 10.10,
        "codename": "Maverick Meerkat",
        "alias": "maverick",
        "description": "Interim Release",
        "stamp": 1286706600,
    },
    "ubuntu/natty": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 11.04",
        "version": 11.04,
        "codename": "Natty Narwhal",
        "alias": "natty",
        "description": "Interim Release",
        "stamp": 1303822800,
    },
    "ubuntu/oneiric": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 11.10",
        "version": 11.10,
        "codename": "Oneiric Ocelot",
        "alias": "oneiric",
        "description": "Interim Release",
        "stamp": 1318446000,
    },
    "ubuntu/precise": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 12.04 LTS",
        "version": 12.04,
        "codename": "Precise Pangolin",
        "alias": "precise",
        "description": "Long Term Support",
        "stamp": 1335423600,
    },
    "ubuntu/quantal": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 12.10",
        "version": 12.10,
        "codename": "Quantal Quetzal",
        "alias": "quantal",
        "description": "Interim Release",
        "stamp": 1350547200,
    },
    "ubuntu/raring": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 13.04",
        "version": 13.04,
        "codename": "Raring Ringtail",
        "alias": "raring",
        "description": "Interim Release",
        "stamp": 1366891200,
    },
    "ubuntu/saucy": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 13.10",
        "version": 13.10,
        "codename": "Saucy Salamander",
        "alias": "saucy",
        "description": "Interim Release",
        "stamp": 1381993200,
    },
    "ubuntu/trusty": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 14.04 LTS",
        "version": 14.04,
        "codename": "Trusty Tahr",
        "alias": "trusty",
        "description": "Long Term Support",
        "stamp": 1397826000,
    },
    "ubuntu/utopic": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 14.10",
        "version": 14.10,
        "codename": "Utopic Unicorn",
        "alias": "utopic",
        "description": "Interim Release",
        "stamp": 1414083600,
    },
    "ubuntu/vivid": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 15.04",
        "version": 15.04,
        "codename": "Vivid Vervet",
        "alias": "vivid",
        "description": "Interim Release",
        "stamp": 1429027200,
    },
    "ubuntu/wily": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 15.10",
        "version": 15.10,
        "codename": "Wily Werewolf",
        "alias": "wily",
        "description": "Interim Release",
        "stamp": 1445518800,
    },
    "ubuntu/xenial": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 16.04 LTS",
        "version": 16.04,
        "codename": "Xenial Xerus",
        "alias": "xenial",
        "description": "Long Term Support",
        "stamp": 1461279600,
    },
    "ubuntu/yakkety": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 16.10",
        "version": 16.10,
        "codename": "Yakkety Yak",
        "alias": "yakkety",
        "description": "Interim Release",
        "stamp": 1476518400,
    },
    "ubuntu/zesty": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 17.04",
        "version": 17.04,
        "codename": "Zesty Zapus",
        "alias": "zesty",
        "description": "Interim Release",
        "stamp": 1492153200,
    },
    "ubuntu/artful": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 17.10",
        "version": 17.10,
        "codename": "Artful Aardvark",
        "alias": "artful",
        "description": "Interim Release",
        "stamp": 1508418000,
    },
    "ubuntu/bionic": {
        "eol": True,
        "oval": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 18.04 LTS",
        "version": 18.04,
        "codename": "Bionic Beaver",
        "alias": "bionic",
        "description": "Long Term Support",
        "stamp": 1524870000,
    },
    "ubuntu/cosmic": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 18.10",
        "version": 18.10,
        "codename": "Cosmic Cuttlefish",
        "alias": "cosmic",
        "description": "Interim Release",
        "stamp": 1540040400,
    },
    "ubuntu/disco": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 19.04",
        "version": 19.04,
        "codename": "Disco Dingo",
        "alias": "disco",
        "description": "Interim Release",
        "stamp": 1555581600,
    },
    "ubuntu/eoan": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 19.10",
        "version": 19.10,
        "codename": "Eoan Ermine",
        "alias": "eoan",
        "description": "Interim Release",
        "stamp": 1571234400,
    },
    "ubuntu/focal": {
        "eol": False,
        "oval": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 20.04 LTS",
        "version": 20.04,
        "codename": "Focal Fossa",
        "alias": "focal",
        "description": "Long Term Support",
        "stamp": 1587567600,
    },
    "ubuntu/groovy": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 20.10",
        "version": 20.10,
        "codename": "Groovy Gorilla",
        "alias": "groovy",
        "description": "Interim Release",
        "stamp": 1603288800,
    },
    "ubuntu/hirsute": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 21.04",
        "version": 21.04,
        "codename": "Hirsute Hippo",
        "alias": "hirsute",
        "description": "Interim Release",
        "stamp": 1619049600,
    },
    "ubuntu/impish": {
        "eol": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 21.10",
        "version": 21.10,
        "codename": "Impish Indri",
        "alias": "impish",
        "description": "Interim Release",
        "stamp": 1634220000,
    },
    "ubuntu/jammy": {
        "eol": False,
        "oval": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 22.04 LTS",
        "version": 22.04,
        "codename": "Jammy Jellyfish",
        "alias": "jammy",
        "description": "Long Term Support",
        "stamp": 1650693600,
    },
    "ubuntu/kinetic": {
        "eol": True,
        "oval": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 22.10",
        "version": 22.10,
        "codename": "Kinetic Kudu",
        "alias": "kinetic",
        "devel": False,
        "description": "Interim Release",
        "stamp": 1666461600,
    },
    "ubuntu/lunar": {
        "eol": False,
        "oval": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 23.04",
        "version": 23.04,
        "codename": "Lunar Lobster",
        "alias": "lunar",
        "devel": False,
        "description": "Interim Release",
        "stamp": 1682431200,
    },
    "ubuntu/mantic": {
        "eol": False,
        "oval": True,
        "components": ["main", "restricted", "universe", "multiverse"],
        "name": "Ubuntu 23.10",
        "version": 23.10,
        "codename": "Mantic Minotaur",
        "alias": "mantic",
        "devel": True,  # there can be only one ⚔
        "description": "Interim Release",
    },
    "snap": {
        "eol": False,
        "oval": False,
        "packages": ["snap-supported.txt"],
    }
}


def product_series(rel):
    """Return the product,series tuple for rel."""
    series = ""
    parts = rel.split('/', 1)
    if len(parts) == 2:
        product = parts[0]
        series = parts[1]
        # handle trusty/esm case
        if product in releases:
            product, series = series, product
    elif parts[0] in releases:
        # by default ubuntu releases have an omitted ubuntu product
        # this avoids cases like snaps
        product = PRODUCT_UBUNTU
        series = parts[0]
    else:
        product = parts[0]
    return product, series

# get the subproject details for rel along with it's canonical name, product and series
def get_subproject_details(rel):
    """Return the canonical name,product,series,details tuple for rel."""
    canon, product, series, details, release = None, None, None, None, None
    if rel in subprojects:
        details = subprojects[rel]
        release = rel
    else:
        for r in subprojects:
            try:
                if subprojects[r]["alias"] == rel \
                  or (rel == "devel" and subprojects[r]["devel"]):
                    details = subprojects[r]
                    release = r
                    break
            except KeyError:
                pass

    if release:
        product, series = product_series(release)
        canon = product + "/" + series
    return canon, product, series, details

def get_subproject_details_by_ppa_url_and_series(url, series):
    """Return the canonical_name,product,series,details subproject tuple matching url and series.

    Searches for a known subproject that defines series and which has a ppa
    property defined that is a substring of url.

    """
    canon = None
    product = None
    details = None
    for rel in subprojects:
        prod, ser = product_series(rel)
        if ser == series:
            try:
                if subprojects[rel]["ppa"] in url:
                    product = prod
                    canon = product + "/" + series
                    details = subprojects[rel]
                    break
            except KeyError:
                pass
            if details is not None:
                break
    return canon, product, series, details

def release_name(rel):
    name = None
    _, _, _, details = get_subproject_details(rel)
    try:
        name = details["name"]
    except (KeyError, TypeError):
        pass
    return name

def release_alias(rel):
    """Return the alias for rel or just rel if no alias is defined."""
    alias = rel
    _, _, _, details = get_subproject_details(rel)
    try:
        alias = details["alias"]
    except (KeyError, TypeError):
        pass
    return alias

def release_parent(rel):
    """Return the parent for rel or None if no parent is defined."""
    parent = None
    _, _, _, details = get_subproject_details(rel)
    try:
        parent = release_alias(details["parent"])
    except (KeyError, TypeError):
        pass
    return parent

def release_progenitor(rel):
    parent = release_parent(rel)
    while release_parent(parent):
        parent = release_parent(parent)

    return parent

def release_stamp(rel):
    """Return the time stamp for rel or its parent if it doesn't define one."""
    stamp = -1
    _, _, _, details = get_subproject_details(rel)
    if details:
        # devel is special and so is assumed to be released in the future
        if "devel" in details and details["devel"]:
            stamp = sys.maxsize
        try:
            stamp = details["stamp"]
        except KeyError:
            rel = release_progenitor(rel)
            _, _, _, details = get_subproject_details(rel)
            if details:
                stamp = details["stamp"]
    return stamp

def release_version(rel):
    """Return the version for rel or its parent if it doesn't have one."""
    version = 0.0
    _, _, _, details = get_subproject_details(rel)
    if details:
        try:
            version = details["version"]
        except KeyError:
            rel = release_progenitor(rel)
            _, _, _, details = get_subproject_details(rel)
            if details:
                version = details["version"]
    return version

def release_ppa(rel):
    """Return the ppa for a given subproject."""
    ppa = None
    _, _, _, details = get_subproject_details(rel)
    try:
        # remove '/ubuntu' from ppa as this function
        # is mainly used for lp to find ppas and it
        # fails otherwise.
        ppa = details["ppa"].split('/ubuntu')[0]
    except (KeyError, TypeError):
        pass
    return ppa

def needs_oval(rel):
    """Return if OVAL should be generated for a given subproject"""
    oval_type = None
    _, product, series, details = get_subproject_details(rel)
    try:
        oval_type = details["oval"]
    except (KeyError, TypeError):
        pass
    return oval_type

def get_subproject_description(rel):
    """Return the description for a given release."""
    description = "?"
    _, _, _, details = get_subproject_details(rel)
    try:
        description = details["description"]
    except (KeyError, TypeError):
        pass

    return description


def get_external_subproject_cve_dir(subproject):
    """Get the directory where CVE files are stored for the subproject.

    Get the directory where CVE files are stored for a subproject. In
    general this is within the higher level project directory, not within
    the specific subdirectory for the particular series that defines this
    subproject.

    """
    rel, product, _, _ = get_subproject_details(subproject)
    if rel not in external_releases:
        raise ValueError("%s is not an external subproject" % rel)
    # CVEs live in the product dir
    return os.path.join(subprojects_dir, product)

def get_external_subproject_dir(subproject):
    """Get the directory for the given external subproject."""
    rel, _, _, _ = get_subproject_details(subproject)
    if rel not in external_releases:
        raise ValueError("%s is not an external subproject" % rel)
    return os.path.join(subprojects_dir, rel)

def read_external_subproject_config(subproject_dir):
    """Read and return the configuration for the given subproject directory."""
    config_yaml = os.path.join(subproject_dir, "config.yml")
    with open(config_yaml) as cfg:
        return yaml.safe_load(cfg)


def read_external_subproject_details(subproject):
    """Read and return the project details for the given subproject."""
    sp_dir = get_external_subproject_dir(subproject)
    # project.yml is located in the top level folder for the subproject
    project_dir = sp_dir[:sp_dir.rfind("/")]
    project_yaml = os.path.join(project_dir, "project.yml")
    if os.path.isfile(project_yaml):
        with open(project_yaml) as cfg:
            return yaml.safe_load(cfg)

def find_files_recursive(path, name):
    """Return a list of all files under path with name."""
    matches = []
    for root, _, files in os.walk(path, followlinks=True):
        for f in files:
            if f == name:
                filepath = os.path.join(root, f)
                matches.append(filepath)
    return matches

def find_external_subproject_cves(cve):
    """Return the list of external subproject CVE snippets for the given CVE."""
    cves = []
    for rel in external_releases:
        # fallback to the series specific subdir rather than just the
        # top-level project directory even though this is preferred
        for d in [get_external_subproject_cve_dir(rel),
                  get_external_subproject_dir(rel)]:
            path = os.path.join(d, cve)
            if os.path.exists(path):
                cves.append(path)
    return cves

# Keys in config.yml for a external subproject
# should follow the same as any other subproject
# except for the extra 'product' and 'release' keys.
MANDATORY_EXTERNAL_SUBPROJECT_KEYS = ['cve_triage', 'cve_patching', 'cve_notification', 'security_updates_notification', 'binary_copies_only', 'seg_support', 'owners']
MANDATORY_EXTERNAL_SUBPROJECT_PPA_KEYS = ['ppa', 'oval', 'product', 'release', 'supported_packages']
OPTIONAL_EXTERNAL_SUBPROJECT_PPA_KEYS =  ['parent', 'name', 'codename', 'description', 'aliases', 'archs']

def load_external_subprojects():
    """Search for and load subprojects into the global subprojects dict.

    Search for and load subprojects into the global subprojects dict.

    A subproject is defined as a directory which resides within
    subprojects_dir and references a supported.txt file and a PPA.
    This information is stored in config.yml, which contains all the
    information in regards the subproject. It can also contain
    a project.yml file which specifies metadata for the project as well
    as snippet CVE files. By convention, a subproject is usually defined
    as the combination of a product and series, ie:

    esm-apps/focal

    as such in this case there would expect to be within subprojects_dir a
    directory called esm-apps/ and within that, in the config.yml, an entry
    of type 'esm-apps/focal'. Inside this entry, a reference to the designated
    supported.txt file, which would list the packages which are supported by
    the esm-apps/focal subproject. By convention, snippet CVE files should
    reside within the esm-apps/ project directory.
    """
    for config_yaml in find_files_recursive(subprojects_dir, "config.yml"):
        subproject_path = config_yaml[:-len("config.yml")-1]
        # use config to populate other parts of the
        # subproject settings
        main_config = read_external_subproject_config(subproject_path)
        support_metadata = {}

        # Disable this check until we have the information available
        # for key in MANDATORY_EXTERNAL_SUBPROJECT_KEYS:
        #     if key not in main_config:
        #         print('%s missing "%s" field.' % (subproject_path, key))
        #         raise ValueError
        #     else:
        #         support_metadata[key] = main_config[key]

        for ppa in main_config['ppas']:
            config = main_config['ppas'][ppa]
            if 'product' not in config or 'release' not in config:
                print('%s: missing "product" or "release".' % (subproject_path))
                raise ValueError

            subproject_name = '%s/%s' % (config["product"], config["release"])
            external_releases.append(subproject_name)
            subprojects.setdefault(subproject_name, {"packages": [],
                                        "eol": False})
            # an external subproject can append to an internal one
            subprojects[subproject_name]["packages"].append(\
                os.path.join(subproject_path, config['supported_packages']))

            # check if aliases for packages exist
            if 'aliases' in config:
                subprojects[subproject_name].setdefault("aliases", \
                    os.path.join(subproject_path, config['aliases']))

            for key in MANDATORY_EXTERNAL_SUBPROJECT_PPA_KEYS + OPTIONAL_EXTERNAL_SUBPROJECT_PPA_KEYS:
                if key in config:
                    subprojects[subproject_name].setdefault(key, config[key])
                elif key in OPTIONAL_EXTERNAL_SUBPROJECT_PPA_KEYS:
                    _, _, _, original_release_details = get_subproject_details(subprojects[subproject_name]['release'])
                    if original_release_details and key in original_release_details:
                        subprojects[subproject_name].setdefault(key, original_release_details[key])
                else:
                    print('%s missing "%s" field.' % (subproject_path, key))
                    del subprojects[subproject_name]
                    external_releases.remove(subproject_name)
                    raise ValueError

            subprojects[subproject_name].setdefault("support_metadata", support_metadata)
            project = read_external_subproject_details(subproject_name)
            if project:
                subprojects[subproject_name].setdefault("customer", project)

load_external_subprojects()

for release in subprojects:
    details = subprojects[release]
    rel = release_alias(release)
    # prefer the alias name
    all_releases.append(rel)
    if details["eol"]:
        eol_releases.append(rel)
    if "devel" in details and details["devel"]:
        if devel_release != "":
            raise ValueError("there can be only one ⚔ devel")
        devel_release = rel
    # ubuntu specific releases
    product, series = product_series(release)
    if product == PRODUCT_UBUNTU:
        releases.append(rel)


def release_sort(release_list):
    '''takes a list of release names and sorts them in release order

    This is not a strict ordering based on when the release was made but a logic
    ordering used for human consumption.
    '''

    # turn list into a tuples of (name, version) - we want sub-releases to sort
    # later than their parent, so introduce a hack to add one month to their
    # release version so they sort after their parent
    rels = [(x, release_version(x) + 0.01 if "/" in x else release_version(x))
            for x in release_list]
    # sort by release version but also append the release name so releases that
    # have the same stamp sort in alphabetical order by name, then pull out just
    # the names
    return [x[0] for x in sorted(rels, key=lambda x: ("%05.2f" % x[1]) + x[0])]


def release_is_older_than(release_a, release_b):
    '''return True if release_a appeared before release_b'''

    # NOTE: foo/esm will be considered older than foo+1, even if the
    # actual esm event occurred far later than foo+1's release
    return all_releases.index(release_a) < all_releases.index(release_b)


# releases to display for flavors
flavor_releases = [
    'lucid', 'precise', 'trusty', 'utopic', 'vivid', 'wily', 'xenial',
    'yakkety', 'zesty', 'artful', 'bionic', 'cosmic', 'disco', 'eoan',
    'focal', 'groovy', 'hirsute', 'impish', 'jammy', 'kinetic', "lunar",
    'mantic',
]

all_releases = release_sort(all_releases)
flavor_releases = release_sort(flavor_releases)
releases = release_sort(releases)

# primary name of extended support maintenance (esm) releases
esm_releases = [x.split('/esm')[0] for x in all_releases if x.endswith('/esm')]

esm_apps_releases = [x.split('esm-apps/')[1] for x in all_releases if x.startswith('esm-apps/')]

esm_infra_releases = [x.split('esm-infra/')[1] for x in all_releases if x.startswith('esm-infra/')]

ros_esm_releases = [x.split('ros-esm/')[1] for x in all_releases if x.startswith('ros-esm/')]

valid_tags = {
    'universe-binary': 'Binaries built from this source package are in universe and so are supported by the community. For more details see https://wiki.ubuntu.com/SecurityTeam/FAQ#Official_Support',
    'not-ue': 'This package is not directly supported by the Ubuntu Security Team',
    'apparmor': 'This vulnerability is mitigated in part by an AppArmor profile. For more details see https://wiki.ubuntu.com/Security/Features#apparmor',
    'stack-protector': 'This vulnerability is mitigated in part by the use of gcc\'s stack protector in Ubuntu. For more details see https://wiki.ubuntu.com/Security/Features#stack-protector',
    'fortify-source': 'This vulnerability is mitigated in part by the use of -D_FORTIFY_SOURCE=2 in Ubuntu. For more details see https://wiki.ubuntu.com/Security/Features#fortify-source',
    'symlink-restriction': 'This vulnerability is mitigated in part by the use of symlink restrictions in Ubuntu. For more details see https://wiki.ubuntu.com/Security/Features#symlink',
    'hardlink-restriction': 'This vulnerability is mitigated in part by the use of hardlink restrictions in Ubuntu. For more details see https://wiki.ubuntu.com/Security/Features#hardlink',
    'heap-protector': 'This vulnerability is mitigated in part by the use of GNU C Library heap protector in Ubuntu. For more details see https://wiki.ubuntu.com/Security/Features#heap-protector',
    'pie': 'This vulnerability is mitigated in part by the use of Position Independent Executables in Ubuntu. For more details see https://wiki.ubuntu.com/Security/Features#pie',
}

# eol and unsupported kernel_srcs
#                   'linux-source-2.6.15',
#                   'linux-ti-omap',
#                   'linux-linaro',
#                   'linux-qcm-msm',
#                   'linux-ec2',
#                   'linux-fsl-imx51',
#                   'linux-mvl-dove',
#                    'linux-lts-backport-maverick',
#                    'linux-lts-backport-natty',
#                    'linux-lts-backport-oneiric',
kernel_srcs = set(['linux',
                   'linux-ti-omap4',
                   'linux-armadaxp',
                   'linux-mako',
                   'linux-manta',
                   'linux-flo',
                   'linux-goldfish',
                   'linux-joule',
                   'linux-raspi',
                   'linux-raspi-5.4',
                   'linux-raspi2',
                   'linux-raspi2-5.3',
                   'linux-snapdragon',
                   'linux-allwinner',
                   'linux-allwinner-5.19',
                   'linux-aws',
                   'linux-aws-5.0',
                   'linux-aws-5.3',
                   'linux-aws-5.4',
                   'linux-aws-5.8',
                   'linux-aws-5.11',
                   'linux-aws-5.13',
                   'linux-aws-5.15',
                   'linux-aws-5.19',
                   'linux-aws-6.2',
                   'linux-aws-hwe',
                   'linux-aws-edge',
                   'linux-azure',
                   'linux-azure-4.15',
                   'linux-azure-5.3',
                   'linux-azure-5.4',
                   'linux-azure-5.8',
                   'linux-azure-5.11',
                   'linux-azure-5.13',
                   'linux-azure-5.15',
                   'linux-azure-5.19',
                   'linux-azure-fde',
                   'linux-azure-fde-5.15',
                   'linux-azure-fde-5.19',
                   'linux-azure-edge',
                   'linux-bluefield',
                   'linux-dell300x',
                   'linux-gcp',
                   'linux-gcp-4.15',
                   'linux-gcp-5.3',
                   'linux-gcp-5.4',
                   'linux-gcp-5.8',
                   'linux-gcp-5.11',
                   'linux-gcp-5.13',
                   'linux-gcp-5.15',
                   'linux-gcp-5.19',
                   'linux-gcp-edge',
                   'linux-gke',
                   'linux-gke-4.15',
                   'linux-gke-5.0',
                   'linux-gke-5.3',
                   'linux-gke-5.4',
                   'linux-gke-5.15',
                   'linux-gkeop',
                   'linux-gkeop-5.4',
                   'linux-gkeop-5.15',
                   'linux-ibm',
                   'linux-ibm-5.4',
                   'linux-intel-5.13',
                   'linux-intel-iotg',
                   'linux-intel-iotg-5.15',
                   'linux-iot',
                   'linux-lowlatency',
                   'linux-lowlatency-hwe-5.15',
                   'linux-lowlatency-hwe-5.19',
                   'linux-lowlatency-hwe-6.2',
                   'linux-kvm',
                   'linux-nvidia',
                   'linux-oem',
                   'linux-oem-5.4',
                   'linux-oem-5.6',
                   'linux-oem-5.10',
                   'linux-oem-5.13',
                   'linux-oem-5.14',
                   'linux-oem-5.17',
                   'linux-oem-6.0',
                   'linux-oem-6.1',
                   'linux-oem-osp1',
                   'linux-oracle',
                   'linux-oracle-4.15',
                   'linux-oracle-5.0',
                   'linux-oracle-5.3',
                   'linux-oracle-5.4',
                   'linux-oracle-5.8',
                   'linux-oracle-5.11',
                   'linux-oracle-5.13',
                   'linux-oracle-5.15',
                   'linux-euclid',
                   'linux-lts-xenial',
                   'linux-hwe',
                   'linux-hwe-5.4',
                   'linux-hwe-5.8',
                   'linux-hwe-5.11',
                   'linux-hwe-5.13',
                   'linux-hwe-5.15',
                   'linux-hwe-5.19',
                   'linux-hwe-6.2',
                   'linux-hwe-edge',
                   'linux-riscv',
                   'linux-riscv-5.8',
                   'linux-riscv-5.11',
                   'linux-riscv-5.15',
                   'linux-riscv-5.19',
                   'linux-starfive',
                   'linux-starfive-5.19',
                   'linux-xilinx-zynqmp',
                   'linux-5.9'])
kernel_topic_branches = kernel_srcs.difference(['linux'])



# "arch_list" is all the physical architectures buildable
# "official_architectures" includes everything that should be reported on
official_architectures = ['amd64', 'armel', 'armhf', 'arm64', 'i386', 'lpia', 'powerpc', 'ppc64el', 'riscv64', 's390x', 'sparc']
# ports_architectures are architectures that are hosted on ports.ubuntu.com
ports_architectures = ['armel', 'armhf', 'arm64', 'lpia', 'powerpc', 'ppc64el', 'riscv64', 's390x', 'sparc']
arch_list = official_architectures + ['hppa', 'ia64']
official_architectures = ['source', 'all'] + official_architectures

# The build expectations per release, per arch
release_expectations = {
    'dapper': {
        'required': ['amd64', 'i386', 'sparc', 'powerpc'],
        'expected': ['ia64', 'hppa'],
        'bonus': [],
        'arch_all': 'i386',
    },
    'edgy': {
        'required': ['amd64', 'i386', 'sparc', 'powerpc'],
        'expected': [],
        'bonus': ['ia64', 'hppa'],
        'arch_all': 'i386',
    },
    'feisty': {
        'required': ['amd64', 'i386', 'sparc'],
        'expected': ['powerpc'],
        'bonus': ['hppa'],
        'arch_all': 'i386',
    },
    'gutsy': {
        'required': ['amd64', 'i386', 'sparc'],
        'expected': ['powerpc', 'hppa', 'lpia'],
        'bonus': [],
        'arch_all': 'i386',
    },
    'hardy': {
        'required': ['amd64', 'i386', 'lpia'],
        'expected': ['powerpc', 'hppa', 'sparc'],
        'bonus': ['ia64'],
        'arch_all': 'i386',
    },
    'intrepid': {
        'required': ['amd64', 'i386', 'lpia'],
        'expected': ['powerpc', 'hppa', 'sparc'],
        'bonus': ['ia64'],
        'arch_all': 'i386',
    },
    'jaunty': {
        'required': ['amd64', 'i386'],
        'expected': ['lpia', 'powerpc', 'hppa', 'sparc', 'armel'],
        'bonus': ['ia64'],
        'arch_all': 'i386',
    },
    'karmic': {
        'required': ['amd64', 'i386', 'armel'],
        'expected': ['lpia', 'powerpc', 'sparc'],
        'bonus': ['ia64'],
        'arch_all': 'i386',
    },
    'lucid': {
        'required': ['amd64', 'i386', 'armel'],
        'expected': ['powerpc', 'sparc'],
        'bonus': ['ia64'],
        'arch_all': 'i386',
    },
    'maverick': {
        'required': ['amd64', 'i386', 'armel'],
        'expected': ['powerpc'],
        'bonus': [],
        'arch_all': 'i386',
    },
    'natty': {
        'required': ['amd64', 'i386', 'armel'],
        'expected': ['powerpc'],
        'bonus': [],
        'arch_all': 'i386',
    },
    'oneiric': {
        'required': ['amd64', 'i386', 'armel'],
        'expected': ['powerpc'],
        'bonus': [],
        'arch_all': 'i386',
    },
    'precise': {
        'required': ['amd64', 'i386', 'armhf'],
        'expected': ['armel', 'powerpc'],
        'bonus': [],
        'arch_all': 'i386',
    },
    'quantal': {
        'required': ['amd64', 'i386', 'armhf'],
        'expected': ['armel', 'powerpc'],
        'bonus': [],
        'arch_all': 'i386',
    },
    'raring': {
        'required': ['amd64', 'i386', 'armhf'],
        'expected': ['powerpc'],
        'bonus': [],
        'arch_all': 'i386',
    },
    'saucy': {
        'required': ['amd64', 'i386', 'armhf'],
        'expected': ['powerpc'],
        'bonus': ['arm64'],
        'arch_all': 'i386',
    },
    'trusty': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el'],
        'expected': ['powerpc'],
        'bonus': [],
        'arch_all': 'i386',
    },
    'utopic': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el'],
        'expected': ['powerpc'],
        'bonus': [],
        'arch_all': 'i386',
    },
    'vivid': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el'],
        'expected': ['powerpc'],
        'bonus': [],
        'arch_all': 'amd64',
    },
    'wily': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el'],
        'expected': ['powerpc'],
        'bonus': [],
        'arch_all': 'amd64',
    },
    'xenial': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el', 's390x'],
        'expected': ['powerpc'],
        'bonus': [],
        'arch_all': 'amd64',
    },
    'yakkety': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el', 's390x'],
        'expected': ['powerpc'],
        'bonus': [],
        'arch_all': 'amd64',
    },
    'zesty': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el', 's390x'],
        'expected': [],
        'bonus': [],
        'arch_all': 'amd64',
    },
    'artful': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el', 's390x'],
        'expected': [],
        'bonus': [],
        'arch_all': 'amd64',
    },
    'bionic': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el', 's390x'],
        'expected': [],
        'bonus': [],
        'arch_all': 'amd64',
    },
    'cosmic': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el', 's390x'],
        'expected': [],
        'bonus': [],
        'arch_all': 'amd64',
    },
    'disco': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el', 's390x'],
        'expected': [],
        'bonus': [],
        'arch_all': 'amd64',
    },
    'eoan': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el', 's390x'],
        'expected': [],
        'bonus': [],
        'arch_all': 'amd64',
    },
    'focal': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el', 's390x'],
        'expected': ['riscv64'],
        'bonus': [],
        'arch_all': 'amd64',
    },
    'groovy': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el', 's390x'],
        'expected': ['riscv64'],
        'bonus': [],
        'arch_all': 'amd64',
    },
    'hirsute': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el', 's390x'],
        'expected': ['riscv64'],
        'bonus': [],
        'arch_all': 'amd64',
    },
    'impish': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el', 's390x'],
        'expected': ['riscv64'],
        'bonus': [],
        'arch_all': 'amd64',
    },
    'jammy': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el', 's390x'],
        'expected': ['riscv64'],
        'bonus': [],
        'arch_all': 'amd64',
    },
    'kinetic': {
        'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el', 's390x'],
        'expected': ['riscv64'],
        'bonus': [],
        'arch_all': 'amd64',
    },
    'lunar': {
       'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el', 's390x'],
       'expected': ['riscv64'],
       'bonus': [],
       'arch_all': 'amd64',
    },
    'mantic': {
       'required': ['amd64', 'i386', 'armhf', 'arm64', 'ppc64el', 's390x'],
       'expected': ['riscv64'],
       'bonus': [],
       'arch_all': 'amd64',
    },
}

# components in the archive
components = ['main', 'restricted', 'universe', 'multiverse']

# non-overlapping release package name changes, first-match wins
pkg_aliases = {
    'linux': ['linux-source-2.6.15'],
    'xen': ['xen-3.3', 'xen-3.2', 'xen-3.1'],
    'eglibc': ['glibc'],
    'qemu-kvm': ['kvm'],
}

# alternate names for packages in graphs
pkg_alternates = {
    'linux-source-2.6.15': 'linux',
    'linux-source-2.6.17': 'linux',
    'linux-source-2.6.20': 'linux',
    'linux-source-2.6.22': 'linux',
    'linux-restricted-modules-2.6.15': 'linux',
    'linux-backports-modules-2.6.15': 'linux',
    'linux-restricted-modules-2.6.17': 'linux',
    'linux-restricted-modules-2.6.20': 'linux',
    'linux-backports-modules-2.6.20': 'linux',
    'linux-restricted-modules-2.6.22': 'linux',
    'linux-backports-modules-2.6.22': 'linux',
    'linux-ubuntu-modules-2.6.22': 'linux',
    'linux-restricted-modules-2.6.24': 'linux',
    'linux-backports-modules-2.6.24': 'linux',
    'linux-ubuntu-modules-2.6.24': 'linux',
    'linux-restricted-modules': 'linux',
    'linux-backports-modules-2.6.27': 'linux',
    'linux-backports-modules-2.6.28': 'linux',
    'linux-backports-modules-2.6.31': 'linux',
    'xen-3.1': 'xen',
    'xen-3.2': 'xen',
    'xen-3.3': 'xen',
    'firefox-3.0': 'firefox',
    'firefox-3.5': 'firefox',
    'xulrunner-1.9': 'firefox',
    'xulrunner-1.9.1': 'firefox',
    'xulrunner-1.9.2': 'firefox',
    'ruby1.8': 'ruby',
    'ruby1.9': 'ruby',
    'python2.4': 'python',
    'python2.5': 'python',
    'python2.6': 'python',
    'openoffice.org-amd64': 'openoffice.org',
    'gnutls12': 'gnutls',
    'gnutls13': 'gnutls',
    'gnutls26': 'gnutls',
    'postgresql-8.1': 'postgresql',
    'postgresql-8.2': 'postgresql',
    'postgresql-8.3': 'postgresql',
    'compiz-fusion-plugins-main': 'compiz',
    'mysql-dfsg-5.0': 'mysql',
    'mysql-dfsg-5.1': 'mysql',
    'mysql-5.1': 'mysql',
    'gst-plugins-base0.10': 'gstreamer',
    'gst-plugins-good0.10': 'gstreamer',
    'mozilla-thunderbird': 'thunderbird',
    'openjdk-6b18': 'openjdk-6',
}


# The CVE states considered "closed"
status_closed = set(['released', 'not-affected', 'ignored', 'DNE'])
# Possible CVE priorities
priorities = ['negligible', 'low', 'medium', 'high', 'critical']

# For LTS releases going into ESM -> ignored (end of standard support, was xxxxxx)
# For interim releases or releases after the 10-year period -> ignored (end of life, was xxxxxxx)
EOL_ESM_STATUS = "ignored (end of standard support, was {state})"
EOL_STATUS = "ignored (end of life, was {state})"

CVE_RE = re.compile(r'^CVE-\d\d\d\d-[N\d]{4,7}$')

NOTE_RE = re.compile(r'^\s+([A-Za-z0-9-]+)([>|]) *(.*)$')



cve_dirs = [active_dir, retired_dir, ignored_dir]
if os.path.islink(embargoed_dir):
    cve_dirs.append(embargoed_dir)

EXIT_FAIL = 1
EXIT_OKAY = 0

config = {}


def parse_CVEs_from_uri(url):
    """Return a list of all CVE numbers mentioned in the given URL."""

    list = []
    cvere = re.compile("((?:CAN|can|CVE|cve)-\d\d\d\d-(\d|N){3,6}\d)")
    try:
        text = cache_urllib.urlopen(url).read().splitlines()
        for line in text:
            comment = line.find('#')
            if comment != -1:
                line = line[:comment]
            for cve in cvere.finditer(line):
                list.append(cve.group().upper().replace('CAN', 'CVE', 1))
    except IOError:
        print("Could not open", url, file=sys.stderr)

    return list


def read_config_file(config_file):
    '''Read in and do basic validation on config file'''
    try:
        from configobj import ConfigObj
    except ImportError:
        # Dapper lacks this class, so reimplement it quickly
        class ConfigObj(dict):
            def __init__(self, filepath):
                with open(filepath) as inF:
                    lines = inF.readlines()
                for line in lines:
                    line = line.strip()
                    if line.startswith('#') or len(line) == 0:
                        continue
                    name, stuff = line.strip().split('=', 1)
                    self[name] = eval(stuff)

            def __attr__(self, name):
                return self.stuff[name]

    return ConfigObj(config_file)

def read_config():
    config_file = os.path.join(os.path.expanduser("~"), ".ubuntu-cve-tracker.conf")

    if not os.path.exists(config_file):
        raise ValueError("Could not find '%s'" % (config_file))

    # FIXME: Why does this need to be defined as "global" when other globals
    # like "releases" and "EXIT_OKAY" don't need it??
    global config
    config = read_config_file(config_file)

    # Validate required arguments
    if "plb_authentication" not in config:
        raise ValueError(("Could not find 'plb_authentication' entry in %s." % (config_file)))
    if not os.path.exists(config["plb_authentication"]):
        raise ValueError(("Could not find file specified by 'plb_authentication' in %s." % (config_file)))
    return config

def drop_dup_release(cve, rel):
    output = codecs.open(cve + ".new", 'w', encoding="utf-8")
    saw = set()
    with codecs.open(cve, encoding="utf-8") as inF:
        lines = inF.readlines()
    for line in lines:
        if line.startswith('%s_' % (rel)):
            pkg = line.split('_')[1].split(':')[0]
            if pkg not in saw:
                output.write(line)
                saw.add(pkg)
        else:
            output.write(line)
    output.close()
    os.rename(cve + '.new', cve)


def clone_release(cve, pkg, oldrel, newrel):
    output = codecs.open(cve + ".new", 'w', encoding="utf-8")
    with codecs.open(cve, encoding="utf-8") as inF:
        lines = inF.readlines()
    for line in lines:
        if line.startswith('%s_%s:' % (oldrel, pkg)):
            newline = line.replace('%s_%s:' % (oldrel, pkg), '%s_%s:' % (newrel, pkg), 1)
            output.write(newline)
        output.write(line)
    output.close()
    os.rename(cve + '.new', cve)


def update_state(cve, pkg, rel, state, details):
    output = codecs.open(cve + ".new", 'w', encoding="utf-8")
    with codecs.open(cve, encoding="utf-8") as inF:
        lines = inF.readlines()
    for line in lines:
        if line.startswith('%s_%s:' % (rel, pkg)):
            line = '%s_%s: %s' % (rel, pkg, state)
            if details:
                line += ' (%s)' % (details)
            line += '\n'
        output.write(line)
    output.close()
    os.rename(cve + '.new', cve)


def add_state(cve, pkg, rel, state, details, after_rel):
    output = codecs.open(cve + ".new", 'w', encoding="utf-8")
    with codecs.open(cve, encoding="utf-8") as inF:
        lines = inF.readlines()
    for line in lines:
        if line.startswith('%s_%s:' % (after_rel, pkg)):
            output.write(line)
            line = '%s_%s: %s' % (rel, pkg, state)
            if details:
                line += ' (%s)' % (details)
            line += '\n'
        output.write(line)
    output.close()
    os.rename(cve + '.new', cve)


def prepend_field(cve, field, value):
    output = codecs.open(cve + ".new", 'w', encoding="utf-8")
    output.write('%s: %s\n' % (field, value))
    output.write(codecs.open(cve, encoding="utf-8").read())
    output.close()
    os.rename(cve + '.new', cve)


def update_field(cve, field, value=None):
    found = False
    output = codecs.open(cve + ".new", 'w', encoding="utf-8")
    with codecs.open(cve, encoding="utf-8") as inF:
        lines = inF.readlines()
    for line in lines:
        if line.startswith('%s:' % (field)):
            found = True
            if value is None:
                continue
            else:
                output.write('%s: %s\n' % (field, value))
        else:
            output.write(line)
    output.close()
    os.rename(cve + '.new', cve)
    # Do we actually need to add it instead?
    if not found and value:
        prepend_field(cve, field, value)


def drop_field(cve, field):
    update_field(cve, field)


def add_reference(cve, url):
    output = codecs.open(cve + ".new", 'w', encoding="utf-8")
    in_references = False
    with codecs.open(cve, encoding="utf-8") as inF:
        lines = inF.readlines()
    for line in lines:
        if in_references and not line.startswith(' '):
            output.write(' ' + url + '\n')
            in_references = False
        elif in_references and url in line:
            # skip if already there
            print("Skipped adding reference for '%s' (already present)" % (cve), file=sys.stderr)
            output.close()
            os.unlink(cve + '.new')
            return False
        elif not in_references and line.startswith('References:'):
            in_references = True
        output.write(line)
    output.close()
    os.rename(cve + '.new', cve)

    return True

def output_cvss(filehandler, source, vector, score, severity):
    filehandler.write(' ' + source + ': ' + vector + ' [' + score + ' ' + severity + ']\n')

def add_cvss(cve, source, cvss):
    try:
        js = parse_cvss(cvss)
        score = str(js['baseMetricV3']['cvssV3']['baseScore'])
        severity = js['baseMetricV3']['cvssV3']['baseSeverity']
    except ValueError as e:
        print("Not adding invalid CVSS entry: %s" % e)
        return False
    output = codecs.open(cve + ".new", 'w', encoding="utf-8")
    in_cvss = False
    found_cvss = False
    updated = False
    with codecs.open(cve, encoding="utf-8") as inF:
        lines = inF.readlines()
    for line in lines:
        if not line.startswith('CVSS:') and not in_cvss:
            output.write(line)
            continue
        elif line.startswith('CVSS:'):
            output.write('CVSS:\n')
            in_cvss = True
            found_cvss = True
            continue

        # we have reached the end of the CVSS: block but haven't yet
        # updated it so append it by writing it here
        if not updated and in_cvss and not line.startswith(' '):
            output_cvss(output, source, cvss, score, severity)
            output.write('\n')
            updated = True
            in_cvss = False
        # we have found a CVSS vector
        elif in_cvss and 'CVSS' in line:
            # we have a cvss from another source in the CVE file, so keep it there
            if source not in line:
                result = re.search(' (.+)\: (\S+)( \[(.*) (.*)\])?', line)
                other_source = result.group(1)
                other_cvss = result.group(2)
                other_js = parse_cvss(other_cvss)
                other_score = str(other_js['baseMetricV3']['cvssV3']['baseScore'])
                other_severity = other_js['baseMetricV3']['cvssV3']['baseSeverity']
                output_cvss(output, other_source, other_cvss, other_score, other_severity)
                # if we didn't write the new cvss already
                if not updated:
                    output_cvss(output, source, cvss, score, severity)
                updated = True
            # we have a cvss from same source, but a different CVSS vector
            elif cvss not in line:
                # if we didn't write the cvss already
                if not updated:
                    output_cvss(output, source, cvss, score, severity)
                    updated = True
                # we want to make sure to store all versions of CVSS which
                # we know about and so for a given source, replace it only
                # if it has the same version - otherwise we will add it at
                # the end
                result = re.search(' (.+)\: (\S+)( \[(.*) (.*)\])?', line)
                other_source = result.group(1)
                other_cvss = result.group(2)
                other_js = parse_cvss(other_cvss)
                v1 = other_js["baseMetricV3"]["cvssV3"]["version"]
                v2 = js["baseMetricV3"]["cvssV3"]["version"]
                if v2 != v1:
                    other_score = str(other_js['baseMetricV3']['cvssV3']['baseScore'])
                    other_severity = other_js['baseMetricV3']['cvssV3']['baseSeverity']
                    output_cvss(output, other_source, other_cvss, other_score, other_severity)
            # if source and cvss are already in the CVE file and we didn't
            # write it down
            elif not updated:
                output_cvss(output, source, cvss, score, severity)
                updated = True
        elif line.startswith('\n'):
            output.write(line)
            in_cvss = False

    output.close()
    if updated:
        os.rename(cve + '.new', cve)
    else:
        os.unlink(cve + '.new')
    if not found_cvss:
        prepend_field(cve, 'CVSS', '')
        updated = add_cvss(cve, source, cvss)

    return updated


def add_patch(cve, pkg, url, type="patch"):
    patch_header = "Patches_%s:" % (pkg)
    in_patch = False

    output = codecs.open(cve + ".new", 'w', encoding="utf-8")
    with codecs.open(cve, encoding="utf-8") as inF:
        lines = inF.readlines()
    for line in lines:
        if in_patch and not line.startswith(' '):
            output.write(' ' + type + ': ' + url + '\n')
            in_patch = False
        elif in_patch and url in line:
            # skip if already there
            print("Skipped adding debdiff for '%s' (already present)" % (cve), file=sys.stderr)
            output.close()
            os.unlink(cve + '.new')
            return False
        elif not in_patch and line.startswith(patch_header):
            in_patch = True
        output.write(line)
    output.close()
    os.rename(cve + '.new', cve)

    return True


def update_multiline_field(cve, field, text):
    update = ""
    text = text.rstrip()
    # this is a multi-line entry -- it must start with a newline
    if not text.startswith('\n'):
        text = '\n' + text
    output = codecs.open(cve + ".new", 'w', encoding="utf-8")
    skip = 0
    with codecs.open(cve, encoding="utf-8") as inF:
        lines = inF.readlines()
    for line in lines:
        if skip and line.startswith(' '):
            continue
        skip = 0
        if line.startswith('%s:' % (field)):
            prefix = '%s:' % (field)
            for textline in text.split('\n'):
                wanted = '%s%s\n' % (prefix, textline)
                output.write(wanted)
                prefix = ' '
                update += wanted
            skip = 1
            continue
        output.write(line)
    output.close()
    os.rename(cve + '.new', cve)
    return update


# This returns the list of open CVEs and embargoed CVEs (which are included
# in the first list).
def get_cve_list():
    cves = [elem for elem in os.listdir(active_dir)
            if re.match('^CVE-\d+-(\d|N)+$', elem)]

    uems = []
    if os.path.islink(embargoed_dir):
        uems = [elem for elem in os.listdir(embargoed_dir)
                if re.match('^CVE-\d{4}-\w+$', elem)]
        for cve in uems:
            if cve in cves:
                print("Duplicated CVE (in embargoed): %s" % (cve), file=sys.stderr)
        cves = cves + uems

    return (cves, uems)


# This returns the list of embargoed CVEs only
def get_embargoed_cve_list():
    uems = []
    if os.path.islink(embargoed_dir):
        uems = [elem for elem in os.listdir(embargoed_dir)
                if CVE_RE.match(elem)]

    return uems


def get_cve_list_and_retired():
    cves, uems = get_cve_list()
    rcves = [elem for elem in os.listdir(retired_dir)
             if re.match('^CVE-\d+-(\d|N)+$', elem)]
    return (cves + rcves, uems, rcves)


def get_all_cve_list():
    cves, uems, rcves = get_cve_list_and_retired()
    icves = [elem for elem in os.listdir(ignored_dir)
             if re.match('^CVE-\d+-(\d|N)+$', elem)]
    return (cves + icves, uems, rcves, icves)


def contextual_priority(cveinfo, pkg=None, rel=None):
    '''Return the priority based on release, then package, then global'''
    if pkg:
        pkg_p = 'Priority_%s' % (pkg)
        if rel:
            rel_p = '%s_%s' % (pkg_p, rel)
            if rel_p in cveinfo:
                return 2, cveinfo[rel_p]
        if pkg_p in cveinfo:
            return 1, cveinfo[pkg_p][0]
    return 0, cveinfo['Priority'][0] if 'Priority' in cveinfo else 'untriaged'


def find_cve(cve):
    '''Return filepath for a given CVE'''
    for dir in cve_dirs:
        filename = os.path.join(dir, cve)
        if os.path.exists(filename):
            return filename
    raise ValueError("Cannot locate path for '%s'" % (cve))


# New CVE file format for release package field is:
# <product>[/<where or who>]_SOFTWARE[/<modifier>]: <status> [(<when>)]
# <product> is the Canonical product or supporting technology (eg, ‘esm-apps’
# or ‘snap’). ‘ubuntu’ is the implied product when ‘<product>/’ is omitted
# from the ‘<product>[/<where or who>]’ tuple (ie, where we might use
# ‘ubuntu/bionic_DEBSRCPKG’ for consistency, we continue to use
# ‘bionic_DEBSRCPKG’)
# <where or who> indicates where the software lives or in the case of snaps or
# other technologies with a concept of publishers, who the publisher is
# SOFTWARE is the name of the software as dictated by the product (eg, the deb
# source package, the name of the snap or the name of the software project
# <modifier> is an optional key for grouping collections of packages (eg,
# ‘melodic’ for the ROS Melodic release or ‘rocky’ for the OpenStack Rocky
# release)
# <status> indicates the statuses as defined in UCT (eg, needs-triage, needed,
# pending, released, etc)
# <when> indicates ‘when’ the software will be/was fixed when used with the
# ‘pending’ or ‘released’ status (eg, the source package version, snap
# revision, etc)
# e.g.: esm-apps/xenial_jackson-databind: released (2.4.2-3ubuntu0.1~esm2)
# e.g.: git/github.com/gogo/protobuf_gogoprotobuf: needs-triage
# This method should keep supporting existing current format:
# e.g.: bionic_jackson-databind: needs-triage
def parse_cve_release_package_field(cve, field, data, value, code, msg, linenum):
    package = ""
    release = ""
    state = ""
    details = ""
    try:
        release, package = field.split('_', 1)
    except ValueError:
        msg += "%s: %d: bad field with '_': '%s'\n" % (cve, linenum, field)
        code = EXIT_FAIL
        return False, package, release, state, details, code, msg

    try:
        info = value.split(' ', 1)
    except ValueError:
        msg += "%s: %d: missing state for '%s': '%s'\n" % (cve, linenum, field, value)
        code = EXIT_FAIL
        return False, package, release, state, details, code, msg

    state = info[0]
    if state == '':
        state = 'needs-triage'

    if len(info) < 2:
        details = ""
    else:
        details = info[1].strip()

    if details.startswith("["):
        msg += "%s: %d: %s has details that starts with a bracket: '%s'\n" % (cve, linenum, field, details)
        code = EXIT_FAIL
        return False, package, release, state, details, code, msg

    if details.startswith('('):
        details = details[1:]
    if details.endswith(')'):
        details = details[:-1]

    # Work-around for old-style of only recording released versions
    if details == '' and state[0] in ('0123456789'):
        details = state
        state = 'released'

    valid_states = ['needs-triage', 'needed', 'active', 'pending', 'released', 'deferred', 'DNE', 'ignored', 'not-affected']
    if state not in valid_states:
        msg += "%s: %d: %s has unknown state: '%s' (valid states are: %s)\n" % (cve, linenum, field, state,
                                                                                   ' '.join(valid_states))
        code = EXIT_FAIL
        return False, package, release, state, details, code, msg

    # Verify "released" kernels have version details
    #if state == 'released' and package in kernel_srcs and details == '':
    #    msg += "%s: %s_%s has state '%s' but lacks version note\n" % (cve, package, release, state)
    #    code = EXIT_FAIL

    # Verify "active" states have an Assignee
    if state == 'active' and data['Assigned-to'].strip() == "":
        msg += "%s: %d: %s has state '%s' but lacks 'Assigned-to'\n" % (cve, linenum, field, state)
        code = EXIT_FAIL
        return False, package, release, state, details, code, msg

    return True, package, release, state, details, code, msg


class NotesParser(object):
    def __init__(self):
        self.notes = list()
        self.user = None
        self.separator = None
        self.note = None

    def parse_line(self, cve, line, linenum, code):
        msg = ""
        m = NOTE_RE.match(line)
        if m is not None:
            new_user = m.group(1)
            new_sep = m.group(2)
            new_note = m.group(3)
        else:
            # follow up comments should have 2 space indent and
            # an author
            if self.user is None:
                msg += ("%s: %d: Note entry with no author: '%s'\n" %
                        (cve, linenum, line[1:]))
                code = EXIT_FAIL
            if not line.startswith('  '):
                msg += ("%s: %d: Note continuations should be indented by 2 spaces: '%s'.\n" %
                        (cve, linenum, line))
                code = EXIT_FAIL
            new_user = self.user
            new_sep = self.separator
            new_note = line.strip()
        if self.user and self.separator and self.note:
            # if is different user, start a new note
            if new_user != self.user:
                self.notes.append([self.user, self.note])
                self.user = new_user
                self.note = new_note
                self.separator = new_sep
            elif new_sep != self.separator:
                # finish this note and start a new one since this has new
                # semantics
                self.notes.append([self.user, self.note])
                self.separator = new_sep
                self.note = new_note
            else:
                if self.separator == '|':
                    self.note = self.note + " " + new_note
                else:
                    assert(self.separator == '>')
                    self.note = self.note + "\n" + new_note
        else:
            # this is the first note
            self.user = new_user
            self.separator = new_sep
            self.note = new_note
        return code, msg

    def finalize(self):
        if self.user is not None and self.note is not None:
            # add last Note
            self.notes.append([self.user, self.note])
            self.user = None
            self.note = None
        notes = self.notes
        self.user = None
        self.separator = None
        self.notes = None
        return notes



def amend_external_subproject_pkg(cve, data, srcmap, amendments, code, msg):
    linenum = 0
    for line in amendments.splitlines():
        linenum += 1
        if len(line) == 0 or line.startswith('#') or line.startswith(' '):
            continue
        try:
            field, value = line.split(':', 1)
            field = field.strip()
            value = value.strip()
        except ValueError as e:
            msg += "%s: bad line '%s' (%s)\n" % (cve, line, e)
            code = EXIT_FAIL
            return code, msg

        if '_' in field:
            success, pkg, release, state, details, code, msg = parse_cve_release_package_field(cve, field, data, value, code, msg, linenum)
            if not success:
                return code, msg

            data.setdefault("pkgs", dict())
            data["pkgs"].setdefault(pkg, dict())
            srcmap["pkgs"].setdefault(pkg, dict())
            # override existing release info if it exists
            data["pkgs"][pkg][release] = [state, details]
            srcmap["pkgs"][pkg][release] = (cve, linenum)

    return code, msg


def load_external_subproject_cve_data(cve, data, srcmap, code, msg):
    cve_id = os.path.basename(cve)
    for f in find_external_subproject_cves(cve_id):
        with codecs.open(f, 'r', encoding="utf-8") as fp:
            amendments = fp.read()
            fp.close()
        code, msg = amend_external_subproject_pkg(f, data, srcmap, amendments, code, msg)

    return code, msg

def load_cve(cve, strict=False, srcmap=None):
    '''Loads a given CVE into:
       dict( fields...
             'pkgs' -> dict(  pkg -> dict(  release ->  (state, details)   ) )
           )
    '''

    msg = ''
    code = EXIT_OKAY
    required_fields = ['Candidate', 'PublicDate', 'References', 'Description',
                       'Ubuntu-Description', 'Notes', 'Bugs',
                       'Priority', 'Discovered-by', 'Assigned-to', 'CVSS']
    extra_fields = ['CRD', 'PublicDateAtUSN', 'Mitigation']

    data = dict()
    # maps entries in data to their source line - if didn't supply one
    # create a local one to simplify the code
    if srcmap is None:
        srcmap = dict()
    srcmap.setdefault('pkgs', dict())
    srcmap.setdefault('tags', dict())
    data.setdefault('tags', dict())
    srcmap.setdefault('patches', dict())
    data.setdefault('patches', dict())
    affected = dict()
    lastfield = ""
    fields_seen = []
    if not os.path.exists(cve):
        raise ValueError("File does not exist: '%s'" % (cve))
    linenum = 0
    notes_parser = NotesParser()
    priority_reason = {}
    cvss_entries = []
    with codecs.open(cve, encoding="utf-8") as inF:
        lines = inF.readlines()
    for line in lines:
        line = line.rstrip()
        linenum += 1

        # Ignore blank/commented lines
        if len(line) == 0 or line.startswith('#'):
            continue
        if line.startswith(' '):
            try:
                # parse Notes properly
                if lastfield == 'Notes':
                    code, newmsg = notes_parser.parse_line(cve, line, linenum, code)
                    if code != EXIT_OKAY:
                        msg += newmsg
                elif lastfield.startswith('Priority'):
                    priority_part = lastfield.split('_')[1] if '_' in lastfield else None
                    if priority_part in priority_reason:
                        priority_reason[priority_part].append(line.strip())
                    else:
                        priority_reason[priority_part] = [line.strip()]
                elif 'Patches_' in lastfield:
                    try:
                        _, pkg = lastfield.split('_', 1)
                        patch_type, entry = line.split(':', 1)
                        patch_type = patch_type.strip()
                        entry = entry.strip()
                        data['patches'][pkg].append((patch_type, entry))
                        srcmap['patches'][pkg].append((cve, linenum))
                    except Exception as e:
                        msg += "%s: %d: Failed to parse '%s' entry %s: %s\n" % (cve, linenum, lastfield, line, e)
                        code = EXIT_FAIL
                elif lastfield == 'CVSS':
                    try:
                        cvss = dict()
                        result = re.search(' (.+)\: (\S+)( \[(.*) (.*)\])?', line)
                        if result is None:
                            continue
                        cvss['source'] = result.group(1)
                        cvss['vector'] = result.group(2)
                        entry = parse_cvss(cvss['vector'])
                        if entry is None:
                            raise RuntimeError('Failed to parse_cvss() without raising an exception.')
                        if result.group(3):
                            cvss['baseScore'] = result.group(4)
                            cvss['baseSeverity'] = result.group(5)

                        cvss_entries.append(cvss)
                        # CVSS in srcmap will be a tuple since this is the
                        # line where the CVSS block starts - so convert it
                        # to a dict first if needed
                        if type(srcmap["CVSS"]) is tuple:
                            srcmap["CVSS"] = dict()
                        srcmap["CVSS"].setdefault(cvss['source'], (cve, linenum))
                    except Exception as e:
                        msg += "%s: %d: Failed to parse CVSS: %s\n" % (cve, linenum, e)
                        code = EXIT_FAIL
                else:
                    data[lastfield] += '\n%s' % (line[1:])
            except KeyError as e:
                msg += "%s: %d: bad line '%s' (%s)\n" % (cve, linenum, line, e)
                code = EXIT_FAIL
            continue

        try:
            field, value = line.split(':', 1)
        except ValueError as e:
            msg += "%s: %d: bad line '%s' (%s)\n" % (cve, linenum, line, e)
            code = EXIT_FAIL
            continue

        lastfield = field = field.strip()
        if field in fields_seen:
            msg += "%s: %d: repeated field '%s'\n" % (cve, linenum, field)
            code = EXIT_FAIL
        else:
            fields_seen.append(field)
        value = value.strip()
        if field == 'Candidate':
            data.setdefault(field, value)
            srcmap.setdefault(field, (cve, linenum))
            if value != "" and not value.startswith('CVE-') and not value.startswith('UEM-') and not value.startswith('EMB-'):
                msg += "%s: %d: unknown Candidate '%s' (must be /(CVE|UEM|EMB)-/)\n" % (cve, linenum, value)
                code = EXIT_FAIL
        elif 'Priority' in field:
            # For now, throw away comments on Priority fields
            if ' ' in value:
                value = value.split()[0]
            if 'Priority_' in field:
                try:
                    _, pkg = field.split('_', 1)
                except ValueError:
                    msg += "%s: %d: bad field with 'Priority_': '%s'\n" % (cve, linenum, field)
                    code = EXIT_FAIL
                    continue
            # initially set the priority reason as an empty string - this will
            # be fixed up later with a real value if one is found
            data.setdefault(field, [value, ""])
            srcmap.setdefault(field, (cve, linenum))
            if value not in ['untriaged', 'not-for-us'] + priorities:
                msg += "%s: %d: unknown Priority '%s'\n" % (cve, linenum, value)
                code = EXIT_FAIL
        elif 'Patches_' in field:
            try:
                _, pkg = field.split('_', 1)
            except ValueError:
                msg += "%s: %d: bad field with 'Patches_': '%s'\n" % (cve, linenum, field)
                code = EXIT_FAIL
                continue
            # value should be empty
            if len(value) > 0:
                msg += "%s: %d: '%s' field should have no value\n" % (cve, linenum, field)
                code = EXIT_FAIL
                continue
            data['patches'].setdefault(pkg, list())
            srcmap['patches'].setdefault(pkg, list())
        elif 'Tags_' in field:
            '''These are processed into the "tags" hash'''
            try:
                _, pkg = field.split('_', 1)
            except ValueError:
                msg += "%s: %d: bad field with 'Tags_': '%s'\n" % (cve, linenum, field)
                code = EXIT_FAIL
                continue
            data['tags'].setdefault(pkg, set())
            srcmap['tags'].setdefault(pkg, (cve, linenum))
            for word in value.strip().split(' '):
                if word not in valid_tags:
                    msg += "%s: %d: invalid tag '%s': '%s'\n" % (cve, linenum, word, field)
                    code = EXIT_FAIL
                    continue
                data['tags'][pkg].add(word)
        elif '_' in field:
            success, pkg, rel, state, details, code, msg = parse_cve_release_package_field(cve, field, data, value, code, msg, linenum)
            if not success:
                assert(code == EXIT_FAIL)
                continue
            canon, _, _, _ = get_subproject_details(rel)
            if canon is None and rel not in ['upstream', 'devel']:
                msg += "%s: %d: unknown entry '%s'\n" % (cve, linenum, rel)
                code = EXIT_FAIL
                continue
            affected.setdefault(pkg, dict())
            if rel in affected[pkg]:
                msg += "%s: %d: duplicate entry for '%s': original at line %d\n" % (cve, linenum, rel, srcmap['pkgs'][pkg][rel][1])
                code = EXIT_FAIL
                continue
            affected[pkg].setdefault(rel, [state, details])
            srcmap['pkgs'].setdefault(pkg, dict())
            srcmap['pkgs'][pkg].setdefault(rel, (cve, linenum))
        elif field not in required_fields + extra_fields:
            msg += "%s: %d: unknown field '%s'\n" % (cve, linenum, field)
            code = EXIT_FAIL
        else:
            data.setdefault(field, value)
            srcmap.setdefault(field, (cve, linenum))

    data['Notes'] = notes_parser.finalize()
    data['CVSS'] = cvss_entries

    # Check for required fields
    for field in required_fields:
        # boilerplate files are special and can (should?) be empty
        nonempty = [] if "boilerplate" in cve else ['Candidate']
        if strict:
            nonempty += ['PublicDate']

        if field not in data or field not in fields_seen:
            msg += "%s: %d: missing field '%s'\n" % (cve, linenum, field)
            code = EXIT_FAIL
        elif field in nonempty and data[field].strip() == "":
            msg += "%s: %d: required field '%s' is empty\n" % (cve, linenum, field)
            code = EXIT_FAIL

    # Fill in defaults for missing fields
    if 'Priority' not in data:
        data.setdefault('Priority', ['untriaged'])
        srcmap.setdefault('Priority', (cve, 1))
    # Perform override fields
    if 'PublicDateAtUSN' in data:
        data['PublicDate'] = data['PublicDateAtUSN']
        srcmap['PublicDate'] = srcmap['PublicDateAtUSN']
    if 'CRD' in data and data['CRD'].strip() != '' and data['PublicDate'] != data['CRD']:
        if cve.startswith("embargoed"):
            print("%s: %d: adjusting PublicDate to use CRD: %s" % (cve, linenum, data['CRD']), file=sys.stderr)
        data['PublicDate'] = data['CRD']
        srcmap['PublicDate'] = srcmap['CRD']

    if data["PublicDate"] > PRIORITY_REASON_DATE_START and \
            data["Priority"][0] in PRIORITY_REASON_REQUIRED and not priority_reason:
        linenum = srcmap["Priority"][1]
        msg += "%s: %d: needs a reason for being '%s'\n" % (cve, linenum, data["Priority"][0])
        code = EXIT_FAIL
    for item in priority_reason:
        field = 'Priority' if not item else 'Priority_' + item
        data[field][1] = ' '.join(priority_reason[item])

    # entries need an upstream entry if any entries are from the internal
    # list of subprojects
    for pkg in affected:
        needs_upstream = False
        for rel in affected[pkg]:
            if rel not in external_releases:
                needs_upstream = True
        if needs_upstream and 'upstream' not in affected[pkg]:
            msg += "%s: %d: missing upstream '%s'\n" % (cve, linenum, pkg)
            code = EXIT_FAIL

    data['pkgs'] = affected

    code, msg = load_external_subproject_cve_data(cve, data, srcmap, code, msg)

    if code != EXIT_OKAY:
        raise ValueError(msg.strip())
    return data

def load_all(cves, uems, rcves=[]):
    table = dict()
    priority = dict()
    for cve in cves:
        priority.setdefault(cve, dict())
        cvedir = active_dir
        if cve in uems:
            cvedir = embargoed_dir
        if cve in rcves:
            cvedir = retired_dir
        cvefile = os.path.join(cvedir, cve)
        info = load_cve(cvefile)
        table.setdefault(cve, info)
    return table


# supported options
#  pkgfamily = rename linux-source-* packages to "linux", or "xen-*" to "xen"
#  packages = list of packages to pay attention to
#  debug = bool, display debug information
def load_table(cves, uems, opt=None, rcves=[], icves=[]):
    table = dict()
    priority = dict()
    listcves = []
    cveinfo = dict()
    namemap = dict()
    for cve in cves:
        table.setdefault(cve, dict())
        priority.setdefault(cve, dict())
        cvedir = active_dir
        if cve in uems:
            cvedir = embargoed_dir
        elif cve in rcves:
            cvedir = retired_dir
        elif cve in icves:
            cvedir = ignored_dir
        cvefile = os.path.join(cvedir, cve)
        info = load_cve(cvefile)
        cveinfo[cve] = info

        # Allow for Priority overrides
        priority[cve]['default'] = 'untriaged'
        try:
            priority[cve]['default'] = info['Priority'][0]
        except KeyError:
            priority[cve]['default'] = 'untriaged'

        for package in info['pkgs']:
            pkg = package
            # special-case the kernel, since it is per-release
            if opt and 'linux' in opt.pkgfamily:
                if pkg in ['linux-source-2.6.15', 'linux-source-2.6.20', 'linux-source-2.6.22']:
                    pkg = 'linux'
            # special-case xen, since it is per-release
            if opt and 'xen' in opt.pkgfamily:
                if pkg in ['xen-3.0', 'xen-3.1', 'xen-3.2', 'xen-3.3']:
                    pkg = 'xen'
            if opt and opt.packages and pkg not in opt.packages:
                continue
            table[cve].setdefault(pkg, dict())
            namemap.setdefault(pkg, dict())
            for release in info['pkgs'][package]:
                rel = release
                if rel == 'devel':
                    rel = devel_release
                status = info['pkgs'][package][release][0]

                if opt and 'linux' in opt.pkgfamily and status == 'DNE':
                    continue
                if opt and 'xen' in opt.pkgfamily:
                    if status == 'DNE':
                        continue
                    # Skip xen-3.1 for non-gutsy when using pkgfamily override
                    if package == 'xen-3.1' and rel != 'gutsy':
                        continue
                table[cve][pkg].setdefault(rel, status)
                namemap[pkg].setdefault(rel, package)

                # Add status comments only if they exist
                if len(info['pkgs'][package][release]) > 1:
                    status_comment = " ".join(info['pkgs'][package][release][1:]).strip()
                    if status_comment != "":
                        table[cve][pkg].setdefault("%s_comment" % rel, " ".join(info['pkgs'][package][release][1:]))

            field = 'Priority_' + pkg
            if field in info:
                priority[cve][pkg] = info[field][0]
            if opt and opt.debug:
                print("Loaded '%s'" % (pkg), file=sys.stderr)

        # Ignore CVEs that have no packages we're interested in
        if len(table[cve]) != 0:
            listcves.append(cve)
    updated_cves = listcves
    return (table, priority, updated_cves, namemap, cveinfo)

def parse_boilerplate(filepath):
    cve_data = {}
    try:
        cve_data = load_cve(filepath)
    except ValueError as e:
        print(e, file=sys.stderr)
    # capture tags, Notes, and package relationships
    data = dict()
    data.setdefault("aliases", list())
    data.setdefault("tags", cve_data.get("tags", dict()))
    data.setdefault("notes", cve_data.get("Notes", list()))
    data.setdefault("pkgs", cve_data.get("pkgs", dict()))
    return data


def load_boilerplates():
    data = dict()
    aliases = dict()
    for filepath in glob.glob(os.path.join(boilerplates_dir, "*")):
        name = os.path.basename(filepath)
        # check if is a symlink and if so don't bother loading the file
        # directly but add an entry as this is an alias
        if os.path.islink(filepath):
            orig_name = os.readlink(filepath)
            aliases.setdefault(orig_name, set())
            aliases[orig_name].add(name)
            continue
        bpdata = parse_boilerplate(filepath)
        # having a package reference itself as we have in the boilerplates
        # is redundant - although this is not always the case as we may
        # have a boilerplate filename like openjdk yet there is no openjdk
        # package (just openjdk-8 etc) - so ignore any failures here
        try:
            del bpdata["pkgs"][name]
        except KeyError:
            pass
        data.setdefault(name, bpdata)
    for alias in aliases:
        data[alias]["aliases"] = sorted(list(aliases[alias]))
    return data

# for sanity, try to keep these in alphabetical order in the json file
def load_package_info_overrides():
    with open(os.path.join(meta_dir, "package_info_overrides.json"), "r") as fp:
        data = json.load(fp)
        return data

package_info_overrides = load_package_info_overrides()

def load_package_db():
    pkg_db = load_boilerplates()

    # add lookups based on aliases - we can't iterate over pkg_db and
    # modify it so collect aliases then add them manually
    alias_info = {}
    for p in pkg_db:
        # set a name field for each package entry as the preferred name
        # - this is then used when looking up by alias later
        pkg_db[p]["name"] = p
        try:
            aliases = pkg_db[p]["aliases"]
            if len(aliases) > 0:
                alias_info[p] = aliases
        except KeyError:
            pass
    for p in alias_info.keys():
        for a in alias_info[p]:
            if a not in pkg_db:
                # use original info if already in pkg_db
                pkg_db[a] = pkg_db[p]

    return pkg_db

package_db = load_package_db()

def lookup_package_override_title(source):
    global package_info_overrides
    res = package_info_overrides.get(source)
    if isinstance(res, dict):
        return(res.get("title"))

    return None

def lookup_package_override_description(source):
    global package_info_overrides
    res = package_info_overrides.get(source)
    if isinstance(res, dict):
        return(res.get("description"))

    return None

def is_overlay_ppa(rel):
    return '/' in rel


def split_overlay_ppa_from_release(rel):
    if not is_overlay_ppa(rel):
        return (rel, None)

    return rel.split('/')


def is_active_release(rel):
    return rel not in eol_releases


# takes a standard release name
# XXX should perhaps adjust that
def is_active_esm_release(rel, component='main'):
    if not is_active_release(rel) or \
        component == 'universe' or component == 'multiverse':
        esm_rel = get_esm_name(rel, component)
        if esm_rel:
            return esm_rel not in eol_releases
    return False

def get_active_releases_with_esm():
    """Return Ubuntu releases with, at least, one active ESM release."""
    active_esm_releases = []
    all_esm_releases = set(esm_releases + esm_apps_releases + esm_infra_releases + ros_esm_releases)

    # Get ESM active releases that are EOL
    for esm_rel in all_esm_releases:
        if is_active_esm_release(esm_rel):
            active_esm_releases.append(esm_rel)

    # Get active releases that also have ESM (apps)
    for esm_rel in all_esm_releases:
        if is_active_release(esm_rel):
            active_esm_releases.append(esm_rel)

    return active_esm_releases

def get_active_esm_releases():
    """Return all active ESM releases."""
    active_esm_releases = []
    for rel in get_active_releases_with_esm():
        for component in components:
            if is_active_esm_release(rel, component):
                active_esm_releases.append(get_esm_name(rel, component))

    return set(active_esm_releases)

# Defaults to main for historical reasons
def get_esm_name(rel, component='main'):
    if rel in esm_releases:
        return rel + '/esm'
    elif rel in esm_apps_releases and \
        (component == 'universe' or component == 'multiverse'):
        return 'esm-apps/' + rel
    elif rel in esm_infra_releases and \
        (component == 'main' or component == 'restricted'):
        return 'esm-infra/' + rel
    elif rel in ros_esm_releases:
        return 'ros-esm/' + rel
    return None


# get the original name of an esm release
def get_orig_rel_name(rel):
    if not rel.endswith('/esm') and not rel.startswith('esm-'):
        return rel
    if rel.startswith('esm-'):
        return rel.split('/')[1]
    return rel[0:-len('/esm')]


def is_supported(map, pkg, rel, cvedata=None):
    # Allow for a tagged override to declare a pkg (from the perspective of
    # a given CVE item) to be unsupported.
    if cvedata and pkg in cvedata['tags'] and \
       ('universe-binary' in cvedata['tags'][pkg] or
        'not-ue' in cvedata['tags'][pkg]):
        return False

    # If it's inside a subproject, it's supported
    if (rel in external_releases or rel in get_active_esm_releases()) and rel in map \
        and pkg in map[rel]:
        return True

    # Look for a supported component
    if rel in map and pkg in map[rel] and \
       (map[rel][pkg]['section'] == 'main' or
        map[rel][pkg]['section'] == 'restricted'):
        return True
    return False


def any_supported(map, pkg, releases, cvedata):
    for rel in releases:
        if is_supported(map, pkg, rel, cvedata):
            return True
    return False


def is_universe(map, pkg, rel, cvedata):
    if is_supported(map, pkg, rel, cvedata):
        return False
    return True


def any_universe(map, pkg, releases, cvedata):
    for rel in releases:
        if is_universe(map, pkg, rel, cvedata):
            return True
    return False


def in_universe(map, pkg, rel, cve, cvedata):
    if pkg in map[rel] and map[rel][pkg]['section'] == 'universe':
        return True
    else:
        if not cvedata:
            cvedata = load_cve(find_cve(cve))
        if pkg in cvedata['tags'] and 'universe-binary' in cvedata['tags'][pkg]:
            return True
    return False

def load_debian_dsas(filename, verbose=True):
    dsa = None
    debian = dict()

    dsalist = open(filename)
    if verbose:
        print("Loading %s ..." % (filename))
    count = 0
    for line in dsalist:
        count += 1
        line = line.rstrip()
        try:
            if line == "":
                continue
            if line.startswith('\t'):
                if not dsa:
                    continue
                line = line.lstrip()
                if line.startswith('{'):
                    debian[dsa]['cves'] = line.strip(r'[{}]').split()
                elif line.startswith('['):
                    package = line.split()
                    if len(package) < 4:
                        raise Exception("Expected the released package to have 4 fields, but it only had " + str(len(package)))
                    release = package[0].strip("[]")
                    debian[dsa]["releases"].setdefault(release, dict())
                    debian[dsa]["releases"][release].setdefault("package", package[2])
                    debian[dsa]["releases"][release].setdefault("fixed_version", package[3])
            elif line.startswith('['):
                # [DD Mon YYYY] <dsa> <pkg1> <pkg2> ... - <description>
                dsa = line.split()[3]
                date = datetime.datetime.strptime(line.split(r']')[0].lstrip('['), "%d %b %Y")
                desc = " ".join(" ".join(line.split()[4:]).split(' - ')[1:]).strip()
                debian.setdefault(dsa, {'date': date, 'desc': desc, 'cves': [], 'releases': dict()})
        except:
            print("Error parsing line %d: '%s'" % (count, line), file=sys.stderr)
            raise
    dsalist.close()
    return debian


def load_debian_cves(filename, verbose=True):
    cve = None
    debian = dict()

    cvelist = open(filename)
    if verbose:
        print("Loading %s ..." % (filename))
    count = 0
    for line in cvelist:
        count += 1
        line = line.rstrip()
        try:
            if line == "":
                continue
            if line.startswith('\t'):
                if not cve:
                    continue
                line = line.lstrip()
                if line.startswith('['):
                    continue
                if line.startswith('{'):
                    continue
                if line.startswith('-'):
                    info = line[1:].lstrip().split(' ', 1)
                    pkg = info[0]
                    line = ""
                    if len(info) > 1:
                        line = info[1]

                    info = line.lstrip().split(' ', 1)
                    state = info[0]
                    if state == "":
                        state = "<unfixed>"
                    line = ""
                    if len(info) > 1:
                        line = info[1]

                    priority = "needs-triage"
                    bug = None
                    note = None
                    if '(' in line and ')' in line:
                        info = line.split('(')[1].split(')')[0]
                        bits = info.split(';')
                        for bit in bits:
                            bit = bit.strip()
                            if bit.startswith('#'):
                                bug = bit[1:]
                            elif bit.startswith('bug #'):
                                bug = bit[5:]
                            else:
                                priority = bit
                    else:
                        note = line
                    if priority == 'unimportant':
                        priority = 'negligible'

                    debian[cve]['pkgs'].setdefault(pkg, {'priority': priority, 'bug': bug, 'note': note, 'state': state})

                    debian[cve]['state'] = 'FOUND'
                if line.startswith('RESERVED'):
                    debian[cve]['state'] = 'RESERVED'
                if line.startswith('REJECTED'):
                    debian[cve]['state'] = 'REJECTED'
                if line.startswith('NOT-FOR-US'):
                    debian[cve]['state'] = line
                if line.startswith('NOTE'):
                    debian[cve]['note'] += [line]
                if line.startswith('TODO'):
                    if not line.endswith('TODO: check'):
                        debian[cve]['note'] += [line]
            else:
                #if cve:
                #    print("Previous CVE: %s: %s" % (cve, debian[cve]))
                cve = line.split().pop(0)
                debian.setdefault(cve, {'pkgs': dict(), 'state': None, 'note': [], 'desc': " ".join(line.split()[1:])})
        except:
            print("Error parsing line %d: '%s'" % (count, line), file=sys.stderr)
            raise

    cvelist.close()
    return debian


def load_ignored_reasons(filename):
    '''Load CVEs from a list of form "CVE-YYYY-NNNN # Reason"'''

    ignored = dict()

    with open(filename) as inF:
        lines = inF.readlines()

    for line in lines:
        line = line.strip()
        if len(line) == 0 or line.startswith('#'):
            continue
        reason = "Ignored"
        if line.startswith('CVE') and '#' in line:
            line, reason = line.split('#', 1)
        reason = reason.strip()
        if reason.startswith('DNE -') or reason.startswith('NFU -'):
            reason = reason[5:].lstrip('-')
        reason = reason.strip()
        if ' ' in line:
            cves = line.split(' ')
        else:
            cves = [line]
        for cve in cves:
            if len(cve) == 0:
                continue
            ignored.setdefault(cve, reason)

    return ignored


def debian_truncate(desc):
    i = 0
    while i < len(desc) and (i < 60 or desc[i] != ' '):
        i += 1
    if i == len(desc):
        return desc
    return desc[:i] + " ..."


def prepend_debian_cve(filename, cve, desc):
    '''This is prefix the Debian CVE list with a new CVE and
       truncated description with a TODO: check marker'''

    input = open(filename)
    output = open(filename + ".new", 'w')

    print("Prepending %s ..." % (cve))
    output.write(cve)
    if len(desc) > 0:
        output.write(' (%s)' % (debian_truncate(desc)))
    output.write('\n\tTODO: check\n')
    output.write(input.read())
    input.close()
    output.close()
    os.rename(filename + ".new", filename)


def update_debian_todo_cves(ignored, known, filename, debian_sources, verbose=False, update=True):
    '''This will replace any "TODO: check" entries with
    knowledge from the Ubuntu CVE Tracker'''

    input = open(filename)
    if update:
        if verbose:
            print("Updating %s ..." % (filename))
        output = open(filename + ".new", 'w')
    else:
        if verbose:
            print("Dry run ...")
        output = open('/dev/null', 'w')
    cves = dict()

    count = 0
    cve = None
    reserved = False
    reserved_text = None
    todo = False
    for line in input:
        count += 1
        line = line.rstrip('\n')
        if line.startswith('CVE'):
            # finish up previous CVE processing
            if todo and reserved:
                if cve in ignored and reserved_text.rstrip('\n') == '\tRESERVED':
                    print("\tNOT-FOR-US: %s" % (ignored[cve]), file=output)
                else:
                    print(reserved_text.rstrip('\n'), file=output)

            # now start the new CVE processing
            cve = line.split().pop(0)
            todo = True
            reserved = False
            reserved_text = []
        elif line.startswith('\t'):
            if todo and (line == '\tTODO: check' or line == '\tRESERVED'):
                if cve in ignored:
                    if line == '\tRESERVED':
                        reserved_text = line + "\n"
                        reserved = True
                    elif line == '\tTODO: check':
                        print("\tNOT-FOR-US: %s" % (ignored[cve]), file=output)
                        todo = False
                        if verbose:
                            print("%s: NFU" % (cve))
                    continue
                if cve in known:
                    if cve not in cves:
                        cves[cve] = load_cve('%s/%s' % (active_dir, cve))
                    pkgs = cves[cve]['pkgs']
                    # HACK: Debian package name fix-ups
                    if 'linux' in pkgs:
                        pkgs = ['linux-2.6']
                    for src in pkgs:
                        # Skip packages not in Debian
                        if src not in debian_sources:
                            continue
                        print("\t- %s <unfixed>" % (src), file=output)
                        if verbose:
                            print("%s: %s" % (cve, src))
                        todo = False
                    # If the CVE is known to Ubuntu but doesn't hit anything, leave it alone
                    if todo and not reserved:
                        print(line, file=output)
                    continue
            elif reserved:
                if line.startswith('\tNOT-FOR-US: '):
                    print(reserved_text.rstrip('\n'), file=output)
                    todo = False
                else:
                    reserved_text += line + "\n"
                    continue
        elif line.startswith('begin') or line.startswith('end'):
            pass
        else:
            raise ValueError("Error parsing line %d: '%s'" % (count, line))
        print(line, file=output)
    input.close()
    output.close()
    if update:
        os.rename(filename + ".new", filename)




def cve_age(cve, open_date, close_stamp, oldest=None):
    # 'oldest' is a timestamp that is used to add a lower bound to
    # dates in "open_date" and "close_stamp"
    if open_date == 'unknown' or len(open_date) == 0:
        raise ValueError("%s: empty PublicDate" % (cve))
    date = open_date
    # CRDs are traditionally 1400UTC, so use this unless something else
    # is specified.
    mytime = '14:00:00'
    if ' ' in date:
        tmp = date
        date = tmp.split()[0]
        mytime = tmp.split()[1]
    year, mon, day = [int(x) for x in date.split('-')]
    hour, minute, second = [int(x) for x in mytime.split(':')]
    open_obj = datetime.datetime(year, mon, day, hour, minute, second)
    close_obj = datetime.datetime.utcfromtimestamp(int(close_stamp))
    if oldest:
        oldest = datetime.datetime.utcfromtimestamp(oldest)
        if open_obj < oldest:
            open_obj = oldest
        if close_obj < oldest:
            close_obj = oldest
    delta = close_obj - open_obj
    return delta.days


def recursive_rm(dirPath):
    '''recursively remove directory'''
    names = os.listdir(dirPath)
    for name in names:
        path = os.path.join(dirPath, name)
        if not os.path.isdir(path):
            os.unlink(path)
        else:
            recursive_rm(path)
    os.rmdir(dirPath)


def git_add(filename):
    '''Add a modified file to the git index, preparing for commit'''
    rc, output = cmd(['git', 'add', filename])
    if rc != 0:
        raise ValueError('git add "%s" failed: %s' % (filename, output))


# @message = string, git commit message
# @filenames = list of filenames to commit (they need to be added to the
#    index first); if nothing is passed, all changes in the index will
#    be committed
def git_commit(message, filenames=None, edit=False, debug=False):

    git_cmd = ['git', 'commit', '-s']
    if debug:
        git_cmd.append('--quiet')
    git_cmd += ['-m', message]
    if filenames:
        git_cmd += filenames

    rc, output = cmd(git_cmd)
    if rc != 0:
        raise ValueError('failed to commit to git\n%s' % (output))
    return True


def git_is_tree_clean(debug=False):
    rc, output = cmd(['git', 'diff-index', '--quiet', 'HEAD', '--'])
    if debug and rc != 0:
        _, output = cmd(['git', 'diff-index', '--name-only', 'HEAD', '--'])
        print('git believes the following files have been modified:\n%s' % output,
              file=sys.stderr)
    return rc == 0


def git_get_branch_name():
    rc, output = cmd(['git', 'symbolic-ref', '--short', '-q', 'HEAD'])
    if rc != 0:
        raise ValueError('failed to get current git branch:\n%s' % (output))
    return output.strip()


def git_checkout_new_branch(branch, tracking_branch='origin/master', debug=False):
    git_cmd = ['git', 'checkout']
    if debug:
        git_cmd.append('--quiet')
    git_cmd += ['-b', branch, tracking_branch]
    rc, output = cmd(git_cmd)
    if rc != 0:
        raise ValueError('failed to get current git branch:\n%s' % (output))
    return True


def git_checkout_existing_branch(branch, debug=False):
    git_cmd = ['git', 'checkout']
    if debug:
        git_cmd.append('--quiet')
    git_cmd.append(branch)
    rc, output = cmd(git_cmd)
    if rc != 0:
        raise ValueError('failed to get current git branch:\n%s' % (output))
    return True


def git_delete_branch(branch, debug=False):
    if git_get_branch_name() == branch:
        print("Error: can't delete currently checked out branch %s" % branch, file=sys.stderr)
        return False

    git_cmd = ['git', 'branch']
    if debug:
        git_cmd.append('--quiet')
    git_cmd += ['-D', branch]
    rc, output = cmd(git_cmd)
    if rc != 0:
        raise ValueError('failed to delete git branch:\n%s' % (output))
    return True


# Usage:
# config = ConfigObj(os.path.expanduser("~/.ubuntu-cve-tracker.conf"))
# cve_lib.check_mirror_timestamp(config)
# cve_lib.check_mirror_timestamp(config, mirror='packages_mirror')
def check_mirror_timestamp(config, mirror=None):
    mirrors = ['packages_mirror']
    if mirror is not None:
        mirrors = [mirror]
    for m in mirrors:
        if m not in config:
            continue
        a = config[m]

        secs = 86400

        if os.path.exists(a + ".timestamp") and time.mktime(time.localtime()) - os.stat(a + ".timestamp").st_mtime > secs:
            print("WARNING: '%s' is %1.1f days older than %1.1f day(s). Please run '$UCT/scripts/packages-mirror -t'." %
                  (a, float(time.mktime(time.localtime()) - os.stat(a + ".timestamp").st_mtime - secs) / 86400, float(secs) / 86400), file=sys.stderr)


# return the arch that the arch 'all' packages are built on. For utopic
# and prior, it was i386, but vivid and later are built on amd64
def get_all_arch(release):
    return release_expectations[release]['arch_all']


def arch_is_valid_for_release(arch, release):
    return (arch in release_expectations[release]['required'] or
            arch in release_expectations[release]['expected'] or
            arch in release_expectations[release]['bonus'])


def oldest_supported_release():
    '''Get oldest non-eol release'''
    for r in all_releases:
        if r not in eol_releases:
            return r


def subprocess_setup():
    # Python installs a SIGPIPE handler by default. This is usually not what
    # non-Python subprocesses expect.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def cmd(command, input=None, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, stdin=None, timeout=None):
    '''Try to execute given command (array) and return its stdout, or return
    a textual error if it failed.'''

    try:
        sp = subprocess.Popen(command, stdin=stdin, stdout=stdout, stderr=stderr, close_fds=True, universal_newlines=True, preexec_fn=subprocess_setup)
    except OSError as e:
        return [127, str(e)]

    out, outerr = sp.communicate(input)
    # Handle redirection of stdout
    if out is None:
        out = ''
    # Handle redirection of stderr
    if outerr is None:
        outerr = ''
    return [sp.returncode, out + outerr]


def check_editmoin():
    # Make sure editmoin would actually work
    if not os.path.exists(os.path.expanduser('~/.moin_ids')) and not os.path.exists(os.path.expanduser('~/.moin_users')):
        print("Error: Need to configure editmoin to use this option (usually ~/.moin_ids).\n", file=sys.stderr)
        return False

    return True

def cve_sort(a, b):

    # Strip any path elements before sorting
    a = a.split("/")[-1]
    b = b.split("/")[-1]

    a_year = int(a.split("-")[1])
    a_number = int(a.split("-")[2])
    b_year = int(b.split("-")[1])
    b_number = int(b.split("-")[2])

    if a_year > b_year:
        return 1
    elif a_year < b_year:
        return -1
    elif a_number > b_number:
        return 1
    elif a_number < b_number:
        return -1
    else:
        return 0

def is_retired(cve):
    return os.path.exists(os.path.join(retired_dir, cve))

def parse_cvss(cvss):
    # parse a CVSS string into components suitable for MITRE / NVD JSON
    # format - assumes only the Base metric group from
    # https://www.first.org/cvss/specification-document since this is
    # mandatory - also validates by raising exceptions on errors
    metrics = {
        'attackVector': {
            'abbrev': 'AV',
            'values': {'NETWORK': 0.85,
                       'ADJACENT': 0.62,
                       'LOCAL': 0.55,
                       'PHYSICAL': 0.2}
        },
        'attackComplexity': {
            'abbrev': 'AC',
            'values': {'LOW': 0.77,
                       'HIGH': 0.44}
        },
        'privilegesRequired': {
            'abbrev': 'PR',
            'values': {'NONE': 0.85,
                       # [ scope unchanged, changed ]
                       'LOW': [0.62, 0.68], # depends on scope
                       'HIGH': [0.27, 0.5]} # depends on scope
        },
        'userInteraction': {
            'abbrev': 'UI',
            'values': {'NONE': 0.85,
                       'REQUIRED': 0.62}
        },
        'scope': {
            'abbrev': 'S',
            'values': {'UNCHANGED', 'CHANGED'}
        },
        'confidentialityImpact': {
            'abbrev': 'C',
            'values': {'HIGH': 0.56,
                       'LOW': 0.22,
                       'NONE': 0}
        },
        'integrityImpact': {
            'abbrev': 'I',
            'values': {'HIGH': 0.56,
                       'LOW': 0.22,
                       'NONE': 0}
        },
        'availabilityImpact': {
            'abbrev': 'A',
            'values': {'HIGH': 0.56,
                       'LOW': 0.22,
                       'NONE': 0}
        }
    }
    severities = {'NONE': 0.0,
                  'LOW': 3.9,
                  'MEDIUM': 6.9,
                  'HIGH': 8.9,
                  'CRITICAL': 10.0 }
    js = None
    # coerce cvss into a string
    cvss = str(cvss)
    for c in cvss.split('/'):
        elements = c.split(':')
        if len(elements) != 2:
            raise ValueError("Invalid CVSS element '%s'" % c)
        valid = False
        metric = elements[0]
        value = elements[1]
        if metric == 'CVSS':
            if value == '3.0' or value == '3.1':
                js = {'baseMetricV3':
                      { 'cvssV3':
                        { 'version': value }}}
                valid = True
            else:
                raise ValueError("Unable to process CVSS version '%s' (we only support 3.x)" % value)
        else:
            for m in metrics.keys():
                if metrics[m]['abbrev'] == metric:
                    for val in metrics[m]['values']:
                        if val[0:1] == value:
                            js['baseMetricV3']['cvssV3'][m] = val
                            valid = True
        if not valid:
            raise ValueError("Invalid CVSS elements '%s:%s'" % (metric, value))
    for m in metrics.keys():
        if m not in js['baseMetricV3']['cvssV3']:
            raise ValueError("Missing required CVSS base element %s" % m)
    # add vectorString
    js['baseMetricV3']['cvssV3']['vectorString'] = cvss

    # now calculate CVSS scores
    iss = 1 - ((1 - metrics['confidentialityImpact']['values'][js['baseMetricV3']['cvssV3']['confidentialityImpact']]) *
               (1 - metrics['integrityImpact']['values'][js['baseMetricV3']['cvssV3']['integrityImpact']]) *
               (1 - metrics['availabilityImpact']['values'][js['baseMetricV3']['cvssV3']['availabilityImpact']]))
    if js['baseMetricV3']['cvssV3']['scope'] == 'UNCHANGED':
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
    attackVector = metrics['attackVector']['values'][js['baseMetricV3']['cvssV3']['attackVector']]
    attackComplexity = metrics['attackComplexity']['values'][js['baseMetricV3']['cvssV3']['attackComplexity']]
    privilegesRequired = metrics['privilegesRequired']['values'][js['baseMetricV3']['cvssV3']['privilegesRequired']]
    # privilegesRequires could be a list if is LOW or HIGH (and then the
    # value depends on whether the scope is unchanged or not)
    if isinstance(privilegesRequired, list):
        if js['baseMetricV3']['cvssV3']['scope'] == 'UNCHANGED':
            privilegesRequired = privilegesRequired[0]
        else:
            privilegesRequired = privilegesRequired[1]
    userInteraction = metrics['userInteraction']['values'][js['baseMetricV3']['cvssV3']['userInteraction']]
    exploitability = (8.22 * attackVector * attackComplexity * privilegesRequired * userInteraction)
    if impact <= 0:
        base_score = 0
    elif js['baseMetricV3']['cvssV3']['scope'] == 'UNCHANGED':
        # use ceil and * 10 / 10 to get rounded up to nearest 10th decimal (where rounded-up is say 0.01 -> 0.1)
        base_score = math.ceil(min(impact + exploitability, 10) * 10) / 10
    else:
        base_score = math.ceil(min(1.08 * (impact + exploitability), 10) * 10) / 10
    js['baseMetricV3']['cvssV3']['baseScore'] = base_score
    for severity in severities.keys():
        if base_score <= severities[severity]:
            js['baseMetricV3']['cvssV3']['baseSeverity'] = severity
            break
    # these use normal rounding to 1 decimal place
    js['baseMetricV3']['exploitabilityScore'] = round(exploitability * 10) / 10
    js['baseMetricV3']['impactScore'] = round(impact * 10) / 10
    return js

def wordwrap(text, width):
    """
    A word-wrap function that preserves existing line breaks
    and most spaces in the text. Expects that existing line
    breaks are posix newlines (\n).
    """
    return reduce(lambda line, word, width=width:
                  '%s%s%s' %
                  (line,
                   ' \n'[(len(line) - line.rfind('\n') - 1 + len(word.split('\n', 1)[0]) >= width)],
                   word),
                  text.split(' ')
                  )

def wrap_text(text, width=75):
    """
    Wrap text to width chars wide.
    """
    return wordwrap(text, width).replace(' \n', '\n')
