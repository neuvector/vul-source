#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Script to query launchpad and get package publication history for Release
# Security and Updates pockets. This is needed for creating OVAL content.
#
# Author: Eduardo Barretto <eduardo.barretto@canonical.com>
# Copyright (C) 2023 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#

from cve_lib import (all_releases, devel_release, eol_releases, needs_oval, product_series, release_parent, release_ppa)

import argparse
import datetime
import json
import lpl_common
import os
import sys
import traceback

is_debug = False

pockets = []

def load_cache_file(cache_dir, release):
    rel = release.replace('/', '_')
    filename = f"{rel}-pkg-cache.json"
    cache = {}
    try:
        with open(os.path.join(cache_dir, filename), 'r') as json_file:
            cache = json.load(json_file)
            debug(f"Reading {filename}")
            pockets.append("Security")
            pockets.append("Updates")
    except OSError:
        debug(f"File {filename} not found!")
        debug(f"Creating {filename}")
        pockets.append("Release")
    except json.decoder.JSONDecodeError:
        error(f"There was a problem loading JSON file: {filename}")

    return cache


def write_to_cache(cache_dir, release, cache):
    rel = release.replace('/', '_')
    debug(f"{rel}, {release}")
    filename = f"{rel}-pkg-cache.json"
    try:
        with open(os.path.join(cache_dir, filename), 'w+') as json_file:
            json.dump(cache, json_file, indent=2, sort_keys=True)
    except Exception:
        error(f"Could not write to JSON file: {filename}")


def update_cache(release, cache, ppa=None, latest_date_created=None):
    lp = lpl_common.connect(version='devel')
    ubuntu = lp.distributions['ubuntu']
    series = ubuntu.getSeries(name_or_version=product_series(release)[1])

    real_threshold = None
    if latest_date_created:
        # Allow a grace period to cope with publications arriving out of
        # order during long transactions.
        real_threshold = latest_date_created - datetime.timedelta(hours=1)

    if ppa:
        archive, group, ppa_full_name = lpl_common.get_archive(
            ppa,
            lp,
            False,
            distribution=ubuntu
        )
    else:
        archive = ubuntu.main_archive

    debug(f"Retrieving Launchpad publications since {real_threshold}")
    sources = archive.getPublishedSources(order_by_date=True, created_since_date=real_threshold, distro_series=series)
    for s in sources:
        if s.pocket not in pockets:
            continue

        debug(f"{s.source_package_name}, {s.date_created}, {s.status}")
        if latest_date_created is None or s.date_created > latest_date_created:
            latest_date_created = s.date_created

        src = s.source_package_name
        src_ver = s.source_package_version
        src_component = None
        if not ppa:
            src_component = s.component_name

        binaries = s.getPublishedBinaries(active_binaries_only=False)
        for b in binaries:
            bin_name = b.binary_package_name
            bin_version = b.binary_package_version
            bin_component = b.component_name
            pocket = b.pocket
            bin_arch = b.display_name.split(' ')[-1]

            if src not in cache:
                cache[src] = {}
            if src_ver not in cache[src]:
                cache[src][src_ver] = {
                    "binaries": {},
                    "component": src_component,
                    "pocket": pocket,
                }
            if bin_name not in cache[src][src_ver]["binaries"]:
                cache[src][src_ver]["binaries"][bin_name] = {
                    "arch": [],
                    "component": bin_component,
                    "version": bin_version
                }
            if bin_arch not in cache[src][src_ver]["binaries"][bin_name]["arch"]:
                cache[src][src_ver]["binaries"][bin_name]["arch"].append(bin_arch)

    return latest_date_created


def warn(message):
    """ print a warning message """
    sys.stdout.write(f"\rWARNING: {message}\n")


def error(message):
    """ print an error message """
    sys.stderr.write(traceback.format_exc())
    sys.stderr.write(f"\rERROR: {message}\n")
    sys.exit(1)


def debug(message):
    """ print a debugging message """
    if is_debug:
        sys.stdout.write(f"\rDEBUG: {message}\n")


def get_supported_releases():
    supported_releases = []
    for r in set(all_releases).difference(set(eol_releases)).difference(set([devel_release])):
        if needs_oval(r):
            supported_releases.append(r)
        parent = release_parent(r)
        if parent and parent not in supported_releases:
            supported_releases.append(parent)

    return supported_releases


def parse_args():
    argparser = argparse.ArgumentParser()
    argparser.add_argument("--cache-dir", help="cache files directory")
    argparser.add_argument("-d", "--debug", action="store_true",
                           help="make execution verbose")
    return argparser.parse_args()


def main():
    args = parse_args()

    global is_debug
    is_debug = args.debug

    cache_dir = args.cache_dir
    if not cache_dir:
        cache_dir = os.getcwd()
    elif not os.path.exists(cache_dir):
        error("Cache directory does not exist")

    supported_releases = get_supported_releases()

    try:
        for release in supported_releases:
            cache = load_cache_file(cache_dir, release)

            latest_date_created = None
            if "latest_date_created" in cache:
                latest_date_created = datetime.datetime.fromtimestamp(
                    cache["latest_date_created"],
                    tz=datetime.timezone.utc
                )

            debug('UPDATING CACHE')

            ppa = release_ppa(release)
            latest_date_created = update_cache(release, cache, ppa, latest_date_created)

            if latest_date_created is not None:
                epoch = datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc)
                new_threshold = (latest_date_created - epoch).total_seconds()
                cache["latest_date_created"] = new_threshold
                debug(f"NEW DATE: {cache['latest_date_created']}")

            debug('WRITING TO CACHE')
            write_to_cache(cache_dir, release, cache)

    except Exception as e:
        error(e)


if __name__ == '__main__':
    main()
