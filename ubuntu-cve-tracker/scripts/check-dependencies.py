#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Get dependent source package tree of a source package
#
# Author: David Fernandez Gonzalez <david.fernandezgonzalez@canonical.com>
# Copyright (C) 2022 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 2 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# Example usage:
# $ $UCT/scripts/packages-mirror -t
# $ python3 check-dependencies.py golang-x-text bionic --arch=amd64
# 
# The tool depends on having a complete package mirror setup and having it updated.
# It is recommended to update the mirrors prior running the tool.
# 
# The location of the mirror directory should be available in the 
# file ~/.ubuntu-cve-tracker.conf.
# You should update the base path manually if you don't have the conf file.
#

# TODO: implement threading

from os import walk, path
import gzip
import argparse
import subprocess
import re

parser = argparse.ArgumentParser()
parser.add_argument("dependency", help="name of the dependency to search")
parser.add_argument("release", help="name of the release that will be used to search package in")
parser.add_argument("--version", help="version of the dependency")
parser.add_argument("--arch", help="name of the architecture to search (i.e. amd64, riscv)")
parser.add_argument("--ppa", help="name of the dependency to search")
parser.add_argument("--depth", help="max recurssion depth to follow")
parser.add_argument('--no-version', help="ignore versions when checking", action="store_true")

args = parser.parse_args()
affected_packages = {}
base_path = None

with open(f'{path.expanduser("~")}/.ubuntu-cve-tracker.conf') as conf_file:
    for line in conf_file:
        if "packages_mirror=" in line:
            base_path = line[17:-2]
            break

if not base_path:
    print('Unable to find package mirror location. Please, manually update the script to add custom location')
    exit(1)

def gather_files(release, base_path, arch='', ppa_type=''):
    sources = []
    packages = []

    all_folders = [x[0] for x in walk(base_path)]
    target_folders = list(filter(lambda folder_path: 'debian-installer' not in folder_path, all_folders))
    source_folders = list(filter(lambda folder_path: 'source' in folder_path and ppa_type in folder_path and release in folder_path, target_folders))
    binary_folders = list(filter(lambda folder_path: 'binary-' in folder_path and arch in folder_path and ppa_type in folder_path and release in folder_path, target_folders))
    
    for folder in source_folders:
            sources.append(folder + '/Sources.gz')
    for folder in binary_folders:
            packages.append(folder + '/Packages.gz')

    return sources, packages

def get_data_sources(files, arch=''):
    dependencies = []
    binaries = []
    packages = []
    versions = []

    for filename in files:
        loading_deps = False
        loading_binaries = False
        deps = []
        bins = []
        no_deps = False
        print(f'Processing {filename:<150}', end= '\r')
        with gzip.open(filename, 'rt') as file:
            for line in file:
                if 'Package: ' in line:
                    if no_deps:
                        packages.pop(-1)
                        binaries.pop(-1)
                        versions.pop(-1)
                    packages.append(line[9:-1])
                    no_deps = True
                elif 'Version:' in line[0:9]:
                    versions.append(line[9:-1])
                elif 'Binary: ' in line:
                    loading_binaries = True
                    bins = [item.strip() for item in line[8:].split(', ')]
                elif loading_binaries:
                    if ':' in line:
                        binaries.append(bins)
                        loading_binaries = False
                        bins = ''
                    else:
                        bins += [item.strip() for item in line.split(', ')]

                if 'Build-Depends:' in line:
                    loading_deps = True
                    deps = []
                    line = re.sub(':native', '', line)
                    for item in line[15:].split(', '):
                        item = item.strip()
                        if '[' in item:
                            if not arch or arch in item[item.index('[')+1: item.index(']')]:
                                deps.append(re.sub(' \[.*\]', '', item))
                        else:
                            deps.append(item)
                    no_deps = False
                elif loading_deps:
                    line = re.sub(':native', '', line)
                    if ':' in line:
                        dependencies.append(list(map(lambda item: re.sub(' <!\S*>','',item), deps)))
                        loading_deps = False
                        deps = ''
                    else:
                        for item in line[15:].split(', '):
                            item = item.strip()
                            if '[' in item:
                                if not arch or arch in item[item.index('[')+1: item.index(']')]:
                                    deps.append(re.sub(' \[.*\]', '', item))
                            else:
                                deps.append(item)

    print()
    return packages, dependencies, binaries, versions

def get_alternative_provides(files, packages, binaries):
    for filename in files:
        print(f'Processing {filename:<150}', end= '\r')
        with gzip.open(filename, 'rt') as file:
            current_package = ''
            is_providing = False
            provides = []
            for line in file:
                if 'Package: ' in line:
                    current_package = line[9:-1]
                elif 'Source: ' in line:
                    current_package = line[8:-1].split(' ')[0]
                elif 'Provides: ' in line:
                    is_providing = True
                    provides = [item.strip() for item in line[10:].split(', ')]
                elif is_providing:
                    if ':' in line:
                        is_providing = False
                        if current_package in packages:
                            provides = list(map(lambda item: item.split(' ')[0],provides)) 
                            binaries[packages.index(current_package)] += provides
                        provides = ', '
                    else:
                        provides += [item.strip() for item in line.split(', ')]
    print()

def version_compare(version1, version2, specifier):
    relation = ''
    if specifier == '<<':
        relation = 'lt'
    elif specifier == '<=':
        relation = 'le'
    elif specifier == '=':
        relation = 'eq'
    elif specifier == '>=':
        relation = 'ge'
    elif specifier == '>>':
        relation = 'gt'

    process = subprocess.Popen(['dpkg', '--compare-versions', version1, relation ,version2])
    process.wait()
    if process.returncode == 0:
        return True
    else:
        return False
        
def version_check(dependency, target_version):
    try:
        version_string = dependency[dependency.index('(')+1:dependency.index(')')]
        specifier, version = version_string.split(' ')

        return version_compare(target_version, version, specifier)
    except ValueError:
        return True

def check_dependency(names, dependencies, version, ignore_version=False):
    indexes = []
    for i in range(len(dependencies)):
        for name in names:
            for dependency in dependencies[i]:
                if name == dependency.split(' ')[0]:
                    if version_check(dependency, version) or ignore_version:
                        indexes.append(i)

    return indexes

def print_dependencies(dependencies):
    print('------------------------------')
    for dependency in dependencies:
        print(f'{dependency} depends on {dependencies[dependency]}')
    print('------------------------------')

if __name__ == '__main__':
    sources,packages_files = gather_files(args.release, base_path, args.arch if args.arch else '', args.ppa if args.ppa else '')
    print('This tool uses package mirrors to gather the information. Please, run `$UCT/scripts/packages-mirror -t` to get the latest available information.')
    print('Loading sources...')
    packages, dependencies, binaries, versions = get_data_sources(sources, args.arch if args.arch else '')
    print('Loading alternative binaries provided...')
    get_alternative_provides(packages_files, packages, binaries)
    target_package_index = packages.index(args.dependency)
    pending = [target_package_index]
    if args.version:
        versions[target_package_index] = args.version

    max_depth = int(args.depth) if args.depth else 0
    depth = 0
    finished = False
    ignore_version = False if not args.no_version else args.no_version
    print(f'Total: pcks-{len(packages)}, deps-{len(dependencies)}, bins-{len(binaries)}, vers-{len(versions)}')
    print('------------------------------')
    while not finished:
        indexes = []
        fathers = []
        for search_term in pending:
            print(f'Checking {packages[search_term]}')
            new_indexes = check_dependency(binaries[search_term], dependencies, versions[search_term], ignore_version)
            [indexes.append(i) for i in new_indexes]
            [fathers.append(search_term) for _ in new_indexes]

        pending = []
        for i,index in enumerate(indexes):
            if packages[index] not in affected_packages:
                pending.append(index)
                affected_packages[packages[index]] = []
            if (packages[fathers[i]] + ' ' + versions[fathers[i]]) not in affected_packages[packages[index]]:
                affected_packages[packages[index]].append(packages[fathers[i]] + ' ' + versions[fathers[i]])

        print(f'Pending packages to check: {len(pending)}')
        print_dependencies(affected_packages)
        depth += 1

        if len(pending) == 0 or depth == max_depth:
            finished = True
