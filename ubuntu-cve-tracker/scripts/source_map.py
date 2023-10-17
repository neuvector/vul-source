#!/usr/bin/env python2

# Copyright (C) 2005-2017 Canonical Ltd.
# Authors: Kees Cook <kees@ubuntu.com>
#          Jamie Strandboge <jamie@ubuntu.com>
#          Marc Deslauriers <marc.deslauriers@canonical.com>
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

from __future__ import print_function

import apt_pkg
import os
import re
import subprocess
import sys
import cve_lib
import yaml

built_using_tags = ["Built-Using", "Static-Built-Using", "X-Cargo-Built-Using"]
apt_pkg.init_system()


def version_compare(one, two):
    return apt_pkg.version_compare(one, two)

def read_config_file(config_file):
    '''Read in and do basic validation on config file'''
    try:
        from configobj import ConfigObj
    except ImportError:
        # Some releases lack this class, so reimplement it quickly
        class ConfigObj(dict):
            def __init__(self, filepath):
                for line in open(filepath).readlines():
                    line = line.strip()
                    if line.startswith('#') or len(line) == 0:
                        continue
                    name, stuff = line.strip().split('=', 1)
                    self[name] = eval(stuff)

            def __attr__(self, name):
                return self.stuff[name]

    return ConfigObj(config_file)

def _find_sources(pockets=None, releases=None, skip_eol_releases=True, arch='amd64'):
    config = read_config_file(os.path.expanduser("~/.ubuntu-cve-tracker.conf"))
    if 'packages_mirror' in config:
        cve_lib.check_mirror_timestamp(config)
        return _find_from_mirror(config['packages_mirror'],
                                 'sources',
                                 pockets=pockets,
                                 releases=releases,
                                 skip_eol_releases=skip_eol_releases,
                                 arch=arch)
    else:
        return _find_sources_from_apt(pockets=pockets, releases=releases)


def _find_packages(pockets=None, releases=None, skip_eol_releases=True, arch='amd64'):
    config = read_config_file(os.path.expanduser("~/.ubuntu-cve-tracker.conf"))
    if 'packages_mirror' in config:
        cve_lib.check_mirror_timestamp(config)
        return _find_from_mirror(config['packages_mirror'],
                                 'packages',
                                 pockets=pockets,
                                 releases=releases,
                                 skip_eol_releases=skip_eol_releases,
                                 arch=arch)
    else:
        raise Exception("TODO: implement _find_packages_from_apt()")
        # return _find_packages_from_apt()


def _find_path_with_ext(path):
    for ext in ["", ".xz", ".bz2", ".gz"]:
        path_ext = "%s%s" % (path, ext)
        if os.path.exists(path_ext):
            return (True, path_ext)

    return (False, None)


def load_debian(basedir, data_type='sources'):
    if data_type not in ['sources', 'packages']:
        raise ValueError("'data_type' should be either 'sources' or 'packages'")

    debian_sources = dict()
    for section in ['main', 'contrib', 'non-free']:
        rel = 'testing'
        if data_type == 'sources':
            deb_src_path = os.path.join(basedir, 'dists', rel, section, 'source', 'Sources')
            found, deb_src_path_ext = _find_path_with_ext(deb_src_path)
            if not found:
                raise ValueError("Unable to find debian 'sources' at %s" % deb_src_path_ext)
            load_sources_collection((deb_src_path_ext, rel, '', section), debian_sources)
    return debian_sources


def _find_from_mirror(ubuntu, data_type, arch='amd64', pockets=None, releases=None, skip_eol_releases=True):
    if data_type not in ['sources', 'packages']:
        raise ValueError("'data_type' should be either 'sources' or 'packages'")

    collection = []
    errors = False
    missing = ""

    if pockets is None:
        pockets = ['', '-updates', '-security']
    if releases is None:
        releases = cve_lib.all_releases

    # Dev release may not be opened
    if releases == ['']:
        return collection

    for rel in releases:
        if skip_eol_releases and rel in cve_lib.eol_releases:
            continue
        _, product, series, details = cve_lib.get_subproject_details(rel)
        # for esm-apps/esm-infra and external_releases avoid loading info
        # from packages_mirror and instead read supported.txt file only
        if product not in [cve_lib.PRODUCT_UBUNTU]:
            continue
        if details is None:
            print("Failed to load details for %s" % rel)
            continue
        try:
            sections = details['components']
        except KeyError:
            # we handle components only, not file lists for now
            continue
        # free
        for pocket in pockets:
            for section in sections:
                if data_type == 'sources':
                    fn = os.path.join(ubuntu, 'dists', series + pocket, section,
                                      'source', 'Sources')
                else:
                    fn = os.path.join(ubuntu, 'dists', series + pocket, section,
                                      'binary-%s' % arch, 'Packages')

                found, fn_path = _find_path_with_ext(fn)
                if not found:
                    missing += " %s\n" % (fn)
                    errors = True
                    continue
                else:
                    fn = fn_path
                name = pocket
                if name.startswith('-'):
                    name = name[1:]
                else:
                    name = ''

                collection += [(fn, rel, name, section)]

    if errors:
        raise NameError("Missing mirror elements:\n" + missing)

    return collection


def _find_sources_from_apt(pockets=None, releases=None):
    collection = []

    if pockets is None:
        pockets = ['', '-updates', '-security']
    if releases is None:
        releases = cve_lib.releases

    saw = dict()
    lists = '/var/lib/apt/lists'
    for f in os.listdir(lists):
        if not f.endswith('_source_Sources'):
            continue
        parts = f.split('_')
        parts.pop()  # _Sources
        parts.pop()  # _source
        section = parts.pop()  # _main
        release_real = parts.pop()  # _dapper
        saw.setdefault('%s_%s' % (release_real, section), True)
        tmp = release_real.split('-')
        release = tmp[0]
        if len(tmp) > 1:
            pocket = tmp[1]
        else:
            pocket = ''
        collection += [(os.path.join(lists, f), release, pocket, section)]

    # Validate all the sources are available
    errors = False
    missing = ""
    for rel in releases:
        if rel in cve_lib.eol_releases:
            continue
        for pocket in pockets:
            for section in cve_lib.components:
                # verify we found all pockets + sections, the exception is that
                # devel-security and devel-updates won't usually be populated yet
                if '%s%s_%s' % (rel, pocket, section) not in saw and \
                   not (rel == cve_lib.devel_release and pocket in ['-updates', '-security']):
                    missing += " deb-src http://archive.ubuntu.com/ubuntu %s%s %s\n" % (rel, pocket, ' '.join(cve_lib.components))
                    errors = True
    if errors:
        raise NameError("Missing /etc/apt/sources.list lines:\n%s" % (missing))

    return collection


# release -> pkg -> dict( 'section', 'pocket', 'version' )
def load(data_type='sources', pockets=None, releases=None, skip_eol_releases=True, arch="amd64"):
    if data_type not in ['sources', 'packages']:
        raise ValueError("'data_type' should be either 'sources' or 'packages'")

    map = dict()
    if data_type == 'sources':
        for item in _find_sources(pockets=pockets, releases=releases, skip_eol_releases=skip_eol_releases, arch=arch):
            load_sources_collection(item, map)
    else:
        for item in _find_packages(pockets=pockets, releases=releases, skip_eol_releases=skip_eol_releases, arch=arch):
            load_packages_collection(item, map)

    # subprojects only do sources, not binaries
    if data_type == 'sources':
        subproject_lists = load_subprojects_lists(releases=releases)
        for item in subproject_lists:
            map.setdefault(item, dict())
            for pkg in subproject_lists[item]:
                map[item].setdefault(pkg, subproject_lists[item][pkg])

    # duplicate "devel" into the map for ease of use
    if "devel" not in map and cve_lib.devel_release in map:
        map["devel"] = map[cve_lib.devel_release]
    return map


def _get_apt_tags(tagfile):
    tags = None
    if tagfile.endswith('.gz'):
        tags = subprocess.Popen(['/bin/gunzip', '-c', tagfile], stdout=subprocess.PIPE).stdout
    elif tagfile.endswith('.bz2'):
        tags = subprocess.Popen(['/bin/bunzip2', '-c', tagfile], stdout=subprocess.PIPE).stdout
    elif tagfile.endswith('.xz'):
        tags = subprocess.Popen(['/usr//bin/xzcat', tagfile], stdout=subprocess.PIPE).stdout
    else:
        tags = open(tagfile)

    return tags


def load_sources_collection(item, map):
    tagfile, release, pocket, section = item

    parser = apt_pkg.TagFile(_get_apt_tags(tagfile))
    while parser.step():
        pkg = parser.section['Package']
        map.setdefault(release, dict()).setdefault(pkg, {'section': 'unset', 'version': '~', 'pocket': 'unset'})
        map[release][pkg]['section'] = section
        if 'Description' in parser.section:
            map[release][pkg]['description'] = parser.section['Description']
        if not pocket:
            map[release][pkg]['release_version'] = parser.section['Version']
        if apt_pkg.version_compare(parser.section['Version'], map[release][pkg]['version']) > 0:
            map[release][pkg]['pocket'] = pocket
            map[release][pkg]['version'] = parser.section['Version']
            map[release][pkg]['binaries'] = parser.section['Binary'].split(', ')

    return map


def load_packages_collection(item, map):
    tagfile, release, pocket, section = item

    parser = apt_pkg.TagFile(_get_apt_tags(tagfile))
    while parser.step():
        pkg = parser.section['Package']
        map.setdefault(release, dict()).setdefault(pkg, {'section': 'unset', 'version': '~', 'pocket': 'unset'})
        map[release][pkg]['section'] = section
        if 'Description' in parser.section:
            map[release][pkg]['description'] = parser.section['Description']

        if not pocket:
            map[release][pkg]['release_version'] = parser.section['Version']
        if apt_pkg.version_compare(parser.section['Version'], map[release][pkg]['version']) > 0:
            map[release][pkg]['pocket'] = pocket
            map[release][pkg]['version'] = parser.section['Version']

            if 'Source' in parser.section:
                map[release][pkg]['source'] = parser.section['Source'].split()[0]
            else:
                map[release][pkg]['source'] = parser.section['Package']

            for tag in built_using_tags:
                if tag in parser.section:
                    map[release][pkg][tag] = parser.section[tag].split(', ')

            map[release][pkg]['architecture'] = parser.section['Architecture']

    return map


def load_built_using_collection(pmap, releases=None, component=None):
    built_using = dict()

    for rel in pmap.keys():
        if releases is not None and rel not in releases:
            continue

        for pkg in pmap[rel]:
            for tag in built_using_tags:
                if tag in pmap[rel][pkg]:
                    section = pmap[rel][pkg]['section']
                    if component is not None and section != component:
                        continue

                    pocket = rel
                    if pmap[rel][pkg]['pocket'] != '':
                        pocket += "-%s" % pmap[rel][pkg]['pocket']

                    for pkg_cmp_ver in map(lambda x: x.split(' ', 3),
                                        pmap[rel][pkg][tag]):
                        if len(pkg_cmp_ver) != 3:
                            print('WARN: Skipping invalid entry (', pkg_cmp_ver, ') for', rel, pkg, 'with tag', tag)
                            continue

                        s = pkg_cmp_ver[0]
                        v = pkg_cmp_ver[2].rstrip(')')
                        if s not in built_using:
                            built_using[s] = dict()
                        if v not in built_using[s]:
                            built_using[s][v] = dict()
                        if section not in built_using[s][v]:
                            built_using[s][v][section] = dict()
                        if pocket not in built_using[s][v][section]:
                            built_using[s][v][section][pocket] = []
                        if pkg not in built_using[s][v][section][pocket]:
                            built_using[s][v][section][pocket].append(
                                (pkg, pmap[rel][pkg]['version'], tag))

    return built_using


built_using_source_format = '%-55s'
built_using_pocket_format = '%-20s'
built_using_component_format = '%-11s'
built_using_tag_format = '%-24s'
built_using_usedby_format = '%-35s'


def get_built_using(built_using_map, src):
    out = ""
    src_version = None
    lessthan = False
    if '/' in src:
        src, src_version = src.split('/', 2)
        if src_version.startswith('-'):
            lessthan = True
            src_version = src_version.lstrip('-')
    if src in built_using_map:
        for version in sorted(built_using_map[src]):
            if src_version is not None:
                if lessthan:
                    if apt_pkg.version_compare(version, src_version) >= 0:
                        print("Skipping %s >= %s" % (version, src_version), file=sys.stderr)
                        continue
                elif src_version != version:
                    continue

            for section in sorted(built_using_map[src][version]):
                for pocket in sorted(built_using_map[src][version][section]):
                    for s, v, t in sorted(
                            built_using_map[src][version][section][pocket]):
                        out += built_using_source_format % ("%s (%s) " % (src, version))
                        out += built_using_pocket_format % pocket
                        out += built_using_component_format % section
                        out += built_using_tag_format % t
                        out += built_using_usedby_format % s
                        out += '\n'

    return out


def get_built_using_header():
    header = built_using_source_format % "Source (version)"
    header += built_using_pocket_format % "Pocket"
    header += built_using_component_format % "Component"
    header += built_using_tag_format % 'Tag'
    header += built_using_usedby_format % "Used by"
    header += "\n" + "-" * 120
    return header

def get_all_aliases(sources, rel):
    aliases = []

    if not rel in sources:
        return aliases

    for pkg in sources[rel]:
        if 'aliases' in sources[rel][pkg]:
            for alias in sources[rel][pkg]['aliases']:
                aliases.append(alias)
    return aliases

def get_aliases_of_ubuntu_package(sources, pkg_name, rel):
    aliases = []
    if not rel in sources:
        return aliases

    for pkg in sources[rel]:
        if 'aliases' in sources[rel][pkg]:
            if pkg_name in sources[rel][pkg]['aliases']:
                aliases.append(pkg)
    return aliases

def get_packages_from_generic_name(sources, generic_name, rel):
    pkgs = []
    if not rel in sources:
        return pkgs

    for pkg in sources[rel]:
        if 'generic_name' in sources[rel][pkg] and sources[rel][pkg]['generic_name'] == generic_name:
            pkgs.append(pkg)
    return pkgs

def load_subprojects_lists(releases=None):
    map = dict()

    if releases is None:
        releases = cve_lib.all_releases

    all_sources_esm = {}
    for item in _find_sources(releases=cve_lib.get_active_releases_with_esm(), skip_eol_releases=False):
        load_sources_collection(item, all_sources_esm)

    for rel in releases:
        _, _, _, details = cve_lib.get_subproject_details(rel)
        if details is None:
            print("Failed to load details for %s" % rel)
            continue
        try:
            packagelists = details['packages']
        except KeyError:
            # we handle file lists only
            continue

        map[rel] = dict()
        for packages in packagelists:
            if "/" in  packages:
                fn = packages
            else:
                fn = os.path.join(os.path.dirname(os.path.dirname(sys.argv[0])),
                                  packages)
                #  Fallback to UCT if possible
                if not os.path.isfile(fn) and 'UCT' in os.environ:
                    fn = os.path.join(os.environ['UCT'], os.path.basename(fn))

            if not os.path.isfile(fn):
                print("WARN: could not find '%s'. Skipping" % os.path.basename(fn))
                continue

            with open(fn, "r") as f:
                lines = f.read().split('\n')
                f.close()

            pat = re.compile(r'^[_A-Za-z0-9]')
            for line in lines:
                if not pat.search(line):
                    continue
                pkg = line.split()[0]
                # Mock-up an apt Sources file
                if pkg not in map[rel]:
                    map[rel][pkg] = dict()
                    map[rel][pkg]['pocket'] = ''

                    orig_rel = cve_lib.get_orig_rel_name(rel)
                    if not orig_rel in all_sources_esm or pkg not in all_sources_esm[orig_rel]:
                        # Not an ESM subproject
                        _, orig_rel = cve_lib.product_series(rel)

                    if orig_rel in all_sources_esm and pkg in all_sources_esm[orig_rel]:
                        map[rel][pkg]['section'] = all_sources_esm[orig_rel][pkg]['section']
                    else:
                        map[rel][pkg]['section'] = 'main'

                    if '|' in pkg:
                        main_package_name = pkg.split('|')[0]
                        map[rel][pkg]['generic_name'] = main_package_name

            if 'aliases' in details:
                with open(details['aliases'], 'r') as file:
                    aliases = yaml.safe_load(file)

                    for pkg in aliases:
                        for src_pkg in map[rel]:
                            if pkg == src_pkg or \
                                ('generic_name' in map[rel][src_pkg] and pkg == map[rel][src_pkg]['generic_name']):
                                map[rel][src_pkg]['aliases'] = aliases[pkg]
                            #else:
                            #    print("WARN: pkg %s found in aliases but not in supported list for %s. Skipping" % (pkg, rel))

    return map


def madison(source, pkg, releases=None):
    answer = dict()
    if not releases:
        releases = cve_lib.releases
    for rel in releases:
        if rel in cve_lib.eol_releases:
            continue
        if rel in cve_lib.external_releases:
            continue
        if pkg in source[rel]:
            name = rel
            if source[rel][pkg]['pocket'] != '':
                name += '-%s' % (source[rel][pkg]['pocket'])
            name += '/%s' % (source[rel][pkg]['section'])
            answer.setdefault(name, dict())
            answer[name].setdefault(pkg, source[rel][pkg]['version'])
    return answer
