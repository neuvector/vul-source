#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Module containing classes, variables, etc. for creating OVAL content
#
# Author: David Ries <ries@jovalcm.com>
# Author: Joy Latten <joy.latten@canonical.com>
# Copyright (C) 2015 Farnam Hall Ventures LLC
# Copyright (C) 2019 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 2 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# NOTES / TODOs
# This script creates OVAL ids based on the related CVE ID but does not
# currently increment the version number of generated elements when they
# change.

from __future__ import unicode_literals

from datetime import datetime, timezone
import apt_pkg
import io
import os
import re
import shutil
import sys
import tempfile
import collections
import glob
import xml.etree.cElementTree as etree
import json
from xml.dom import minidom
from typing import Tuple # Needed because of Python < 3.9 and to also support < 3.7

from source_map import load
import cve_lib

from xml.sax.saxutils import escape

sources = {}
source_map_binaries = {}
debug_level = 0
GENERIC_VERSION = '0:0'

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

def _open(fn, mode, encoding='utf-8'):
    """ open file """
    fd = None
    if sys.version_info[0] < 3:
        fd = io.open(fn, mode=mode, encoding=encoding)
    else:
        fd = open(fn, mode=mode, encoding=encoding)
    return fd

def prepare_instructions(instruction, cve, product_description, package):
    if "LSN" in cve:
        instruction = """\n
To check your kernel type and Livepatch version, enter this command:

canonical-livepatch status"""

    if not instruction:
        instruction = """\n
Update Instructions:

Run `sudo pro fix {0}` to fix the vulnerability. The problem can be corrected
by updating your system to the following package versions:""".format(cve)

    instruction += '\n\n'
    for binary in package["binaries"]:
        instruction += """{0} - {1}\n""".format(binary, package["fix-version"])

    if "LSN" in cve:
        instruction += "Livepatch subscription required"
    elif "Long Term" in product_description or "Interim" in product_description:
        instruction += "No subscription required"
    else:
        instruction += product_description

    return instruction

def is_kernel_binaries(binaries):
    reg = re.compile('linux-image-.*')
    if any(filter(reg.match, binaries)):
        return True
    return False


""" Using the following kernel uname, we can understand its format:
    uname -r -> 5.4.0-1059-generic
    MAJOR_VERSION="5.4.0"
    ABI="1059"
    FLAVOUR="generic"
"""
def process_kernel_binaries(binaries, oval_format):
    packages = ' '.join(binaries)
    parts = re.findall('linux-image-[a-z]*-?([\d|\.]+-)\d+(-[\w|-]+)', packages)
    if parts:
        values = set(map(lambda x: x[0], parts))
        version = ''.join(values)
        values = sorted(set(map(lambda x: x[1], parts)))
        flavours = '|'.join(values)
        regex = version + '\d+(' + flavours + ')'
        if oval_format == 'oci':
            regex = 'linux-image-(?:unsigned-)?' + version + '\d+(?:' + flavours + ')'
        return regex

    return None

def debug(message):
    """ print a debuging message """
    if debug_level > 0:
        sys.stdout.write('\rDEBUG: {0}\n'.format(message))

def generate_cve_tag(cve):
    cve_ref = '<cve href="https://ubuntu.com/security/{0}" priority="{1}" public="{2}"'.format(cve['Candidate'], cve['Priority'], cve['PublicDate'].split(' ')[0].replace('-', ''))

    if 'CVSS' in cve and cve['CVSS']:
        cve_ref += ' cvss_score="{0}" cvss_vector="{1}" cvss_severity="{2}"'.format(cve['CVSS'][0]['baseScore'], cve['CVSS'][0]['vector'], cve['CVSS'][0]['baseSeverity'].lower())

    cve_ref_usns = False
    if 'References' in cve:
        for ref in cve['References']:
            if 'https://ubuntu.com/security/notices/USN' in ref:
                if not cve_ref_usns:
                    cve_ref_usns = True
                    cve_ref += ' usns="'
                cve_ref += '{0},'.format(ref[40:])

    if cve_ref_usns:
        cve_ref = '{0}"'.format(cve_ref[:-1])

    cve_ref += '>{0}</cve>'.format(cve['Candidate'])
    return cve_ref

def get_binarypkgs(cache, source_name, release):
    """ return a list of binary packages from the source package version """
    packages_to_ignore = ("-dev", "-doc", "-dbg", "-dbgsym", "-udeb", "-locale-")
    binaries_map = collections.defaultdict(dict)

    if source_name not in cache[release]:
        rel = release
        while cve_lib.release_parent(rel):
            rel = cve_lib.release_parent(rel)
            r , vb  = get_binarypkgs(cache, source_name, rel)
            if r:
                return r, vb

        # if a source package does not exist in such a release
        # return None
        return None, None
    
    for source_version in cache[release][source_name]:
        binaries_map.setdefault(source_version, dict())
        for binary, bin_data in cache[release][source_name][source_version]['binaries'].items():
            # for kernel we only want linux images
            if source_name.startswith('linux') and not binary.startswith('linux-image-'):
                continue
            # skip ignored packages, with exception of golang*-dev pkgs
            if binary.startswith(('golang-go')) or \
                    not any(s in binary for s in packages_to_ignore):
                binaries_map[source_version].setdefault(bin_data['version'], list())
                binaries_map[source_version][bin_data['version']].append(binary)

    return release, binaries_map

class CVEPkgRelEntry:
    def __init__(self, pkg, release, cve, status, note) -> None:
        self.pkg = pkg
        self.cve = cve
        self.orig_status = status
        self.orig_note = note
        self.release = release
        cve_info = CVEPkgRelEntry.parse_package_status(self.release, pkg.name, status, note, cve.number, None)

        self.note = cve_info['note']
        self.status = cve_info['status']
        self.fixed_version = cve_info['fix-version'] if self.status == 'fixed' else None

    @staticmethod
    def parse_package_status(release, package, status_text, note, filepath, cache):
        """ parse ubuntu package status string format:
            <status code> (<version/notes>)
            outputs dictionary: {
            'status'        : '<not-applicable | unknown | vulnerable | fixed>',
            'note'          : '<description of the status>',
            'fix-version'   : '<version with issue fixed, if applicable>',
            'bin-pkgs'      : []
            } """

        # TODO fix for CVE Generator

        # break out status code and detail
        code = status_text.lower()
        detail = note.strip('()') if note else None
        status = {}
        fix_version = ""

        if detail and detail[0].isdigit() and len(detail.split(' ')) == 1:
            fix_version = detail

        note_end = " (note: '{0}').".format(detail) if detail else '.'
        if code == 'dne':
            status['status'] = 'not-applicable'
            status['note'] = \
                " package does not exist in {0}{1}".format(release, note_end)
        elif code == 'ignored':
            status['status'] = 'vulnerable'
            status['note'] = ": while related to the CVE in some way, a decision has been made to ignore this issue{0}".format(note_end)
        elif code == 'not-affected':
            # check if there is a release version and if so, test for
            # package existence with that version
            if fix_version:
                status['status'] = 'fixed'
                status['note'] = " package in {0}, is related to the CVE in some way and has been fixed{1}".format(release, note_end)
                status['fix-version'] = fix_version
            else:
                status['status'] = 'not-vulnerable'
                status['note'] = " package in {0}, while related to the CVE in some way, is not affected{1}".format(release, note_end)
        elif code == 'needed':
            status['status'] = 'vulnerable'
            status['note'] = \
                " package in {0} is affected and needs fixing{1}".format(release, note_end)
        elif code == 'pending':
            # pending means that packages have been prepared and are in
            # -proposed or in a ppa somewhere, and should have a version
            # attached. If there is a version, test for package existence
            # with that version, otherwise mark as vulnerable
            if fix_version:
                status['status'] = 'fixed'
                status['note'] = " package in {0} is affected. An update containing the fix has been completed and is pending publication{1}".format(release, note_end)
                status['fix-version'] = fix_version
            else:
                status['status'] = 'vulnerable'
                status['note'] = " package in {0} is affected. An update containing the fix has been completed and is pending publication{1}".format(release, note_end)
        elif code == 'deferred':
            status['status'] = 'vulnerable'
            status['note'] = " package in {0} is affected, but a decision has been made to defer addressing it{1}".format(release, note_end)
        elif code in ['released']:
            # if there isn't a release version, then just mark
            # as vulnerable to test for package existence
            if not fix_version:
                status['status'] = 'vulnerable'
                status['note'] = " package in {0} was vulnerable and has been fixed, but no release version available for it{1}".format(release, note_end)
            else:
                status['status'] = 'fixed'
                status['note'] = " package in {0} was vulnerable but has been fixed{1}".format(release, note_end)
                status['fix-version'] = fix_version
        elif code == 'needs-triage':
            status['status'] = 'vulnerable'
            status['note'] = " package in {0} is affected and may need fixing{1}".format(release, note_end)
        else:
            # TODO LOGGIN
            print('Unsupported status "{0}" in {1}_{2} in "{3}". Setting to "unknown".'.format(code, release, package, filepath))
            status['status'] = 'unknown'
            status['note'] = " package in {0} has a vulnerability that is not known (status: '{1}'). It is pending evaluation{2}".format(release, code, note_end)

        return status

    def is_not_applicable(self) -> bool:
        return self.status in ['not-vulnerable', 'not-applicable']

    def __str__(self) -> str:
        return f'{str(self.pkg)}:{self.status} {self.fixed_version}'

class CVE:
    def __init__(self, number, info, pkgs=None) -> None:
        self.number = number
        self.description = info['Description']
        self.priority = info['Priority'][0]
        self.public_date = info['PublicDate']
        self.public_date_at_usn = info['PublicDateAtUSN'] if 'PublicDateAtUSN' in info else ''
        self.cvss = info['CVSS']
        self.assigned_to = info['Assigned-to'] if 'Assigned-to' in info else ''
        self.discoverd_by = info['Discovered-by'] if 'Discovered-by' in info else ''
        self.usns = []
        self.references = []
        self.bugs = []
        for url in info['References'].split('\n'):
            if 'https://ubuntu.com/security/notices/USN-' in url:
                self.usns.append(url[40:])
            elif re.match("https?:\/\/(bugs\.)?launchpad\.net\/(.*\/\+bug|bugs)\/\d+", url):
                self.bugs.append(url)
            elif url:
                self.references.append(url)
        
        for bug in info['Bugs'].split('\n'):
            if bug:
                self.bugs.append(bug)

        self.pkg_rel_entries = {}
        self.pkgs = pkgs if pkgs else []

    def get_pkgs(self, releases):
        # We assume priority is as the order in the list
        pkgs = []
        pkg_rel = {}
        for pkg in self.pkgs:
            if pkg.rel not in releases:
                continue
            
            if pkg.name not in pkg_rel:
                pkg_rel[pkg.name] = pkg
            else:
                pkg_rel_entry = self.pkg_rel_entries[str(pkg)]
                curr_pkg_rel_entry = self.pkg_rel_entries[str(pkg_rel[pkg.name])]
                if curr_pkg_rel_entry.status == 'fixed':
                    priority = releases.index(pkg.rel) > releases.index(pkg_rel[pkg.name].rel) and \
                        pkg_rel_entry.fixed_version in pkg.versions_binaries
                else:
                    priority = releases.index(pkg.rel) < releases.index(pkg_rel[pkg.name].rel)

                if priority:
                    pkg_rel[pkg.name] = pkg

        for pkg in self.pkgs:
            if self.pkg_rel_entries[str(pkg)].is_not_applicable():
                continue

            if pkg.name in pkg_rel and pkg_rel[pkg.name].rel == pkg.rel:
                pkgs.append(pkg)
        
        return pkgs


    def add_pkg(self, pkg_object, release, state, note):
        cve_pkg_entry = CVEPkgRelEntry(pkg_object, release, self, state, note)
        self.pkg_rel_entries[str(pkg_object)] = cve_pkg_entry
        self.pkgs.append(pkg_object)
        pkg_object.add_cve(self)

    def __str__(self) -> str:
        return self.number

    def __repr__(self):
        return self.__str__()

class Package:
    def __init__(self, pkgname, rel, versions_binaries):
        self.name = pkgname
        self.rel = rel
        self.description = cve_lib.lookup_package_override_description(pkgname)

        if not self.description:
            if 'description' in sources[rel][pkgname]:
                self.description = sources[rel][pkgname]['description']
            elif pkgname in source_map_binaries[rel] and \
                'description' in source_map_binaries[rel][pkgname]:
                self.description = source_map_binaries[rel][pkgname]['description']
            else:
                # Get first description found
                if 'binaries' in sources[self.rel][self.name]:
                    for binary in sources[self.rel][self.name]['binaries']:
                        if binary in source_map_binaries[self.rel] and 'description' in source_map_binaries[self.rel][binary]:
                            self.description = source_map_binaries[self.rel][binary]["description"]
                            break

        self.section = sources[rel][pkgname]['section']
        self.versions_binaries = versions_binaries if versions_binaries else {}
        self.earliest_version = self.get_earliest_version()
        self.latest_version = self.get_latest_version()

        binary_versions = self.get_binary_versions(self.earliest_version)
        self.is_kernel_pkg = False if len(binary_versions) == 0 else \
            is_kernel_binaries(self.get_binaries(self.earliest_version, binary_versions[0]))
        self.cves = []

    def add_cve(self, cve) -> None:
        self.cves.append(cve)

    def get_latest_version(self):
        latest = None
        for version in self.versions_binaries.keys():
            if not latest:
                latest = version
                continue
            elif apt_pkg.version_compare(version, latest) > 0:
                latest = version

        return latest

    def get_earliest_version(self):
        earliest = None
        for version in self.versions_binaries.keys():
            if not earliest:
                earliest = version
                continue
            elif apt_pkg.version_compare(earliest, version) > 0:
                earliest = version

        return earliest

    def version_exists(self, source_version):
        return source_version in self.versions_binaries
    
    def all_binaries_same_version(self, source_version):
        if source_version not in self.versions_binaries:
            return len(self.versions_binaries[self.earliest_version]) <= 1
        return len(self.versions_binaries[source_version]) <= 1

    def get_version_to_check(self, source_version):
        if not source_version:
            return self.latest_version
        else:
            if source_version in self.versions_binaries or self.all_binaries_same_version(source_version):
                return source_version
            else:
                if source_version:
                    if apt_pkg.version_compare(source_version, self.latest_version) > 0:
                        print(f'Wrong CVE entry version {source_version} - latest for package {self.name} in {self.rel} is {self.latest_version}')
                        return self.latest_version
                    elif apt_pkg.version_compare(source_version, self.earliest_version) < 0:
                        return self.earliest_version
                    else:
                        for version in self.versions_binaries:
                            if apt_pkg.version_compare(version, source_version) > 0:
                                print(f'CVE entry version in the middle {source_version} - for package {self.name} in {self.rel} is {self.earliest_version}- {self.latest_version} - using {version} instead')
                                return version

                return self.earliest_version

    def get_binary_versions(self, source_version):
        if not self.versions_binaries: return []

        if source_version not in self.versions_binaries:
            # If this is the case, package binaries should all have the same version
            # Relying on that, we can use the version of the CVE as the right version
            return [source_version]
        return list(self.versions_binaries[source_version].keys())

    def get_binaries(self, source_version, binary_version):
        if not self.versions_binaries: return {}
        if source_version not in self.versions_binaries:
            version_binaries = self.versions_binaries[self.earliest_version]
            if len(version_binaries) > 1:
                print(f"WARN: Version {source_version} doesn't exist yet the package {self.name} has different versions for the binaries")
            elif len(version_binaries) == 0:
                return []
            binary_versions = self.get_binary_versions(self.earliest_version)
            return version_binaries[binary_versions[0]]
        return self.versions_binaries[source_version][binary_version]

    def __str__(self) -> str:
        return f"{self.name}/{self.rel}"

    def __repr__(self):
        return self.__str__()

class USN:
    def __init__(self, data):
        for item in ['description', 'releases', 'title', 'timestamp', 'summary', 'action', 'cves', 'id', 'isummary']:
            if item in data:
                setattr(self, item, data[item])
            else:
                setattr(self, item, None)
    
    def __str__(self) -> str:
        return self.id

    def __repr__(self) -> str:
        return self.id

# Oval Generators
class OvalGenerator:
    supported_oval_elements = ('definition', 'test', 'object', 'state', 'variable')
    generator_version = '2'
    oval_schema_version = '5.11.1'
    def __init__(self, type, releases, cve_paths, packages, progress, pkg_cache, fixed_only=True, cve_cache=None,  cve_prefix_dir=None, outdir='./', oval_format='dpkg') -> None:
        self.releases = releases
        self.output_dir = outdir
        self.oval_format = oval_format
        self.generator_type = type
        self.progress = progress
        self.cve_cache = cve_cache
        self.pkg_cache = pkg_cache
        self.cve_paths = cve_paths
        self.fixed_only = fixed_only
        self.packages, self.cves = self._load(cve_prefix_dir, packages)

    def _init_ids(self, release):
        # e.g. codename for trusty/esm should be trusty
        self.release = release
        self.release_codename = cve_lib.release_progenitor(self.release) if cve_lib.release_progenitor(self.release) else self.release.replace('/', '_')
        self.release_name = cve_lib.release_name(self.release)
        
        self.parent_releases = list()
        current_release = self.release
        while(cve_lib.release_parent(current_release)):
            current_release = cve_lib.release_parent(current_release)
            if current_release != self.release and \
                current_release not in self.parent_releases:
                self.parent_releases.append(current_release)
        
        self.ns = 'oval:com.ubuntu.{0}'.format(self.release_codename)
        self.id = 100
        self.host_def_id = self.id
        self.release_applicability_definition_id = '{0}:def:{1}0'.format(self.ns, self.id)
        ###
        # ID schema: 2204|00001|0001
        # * The first four digits are the ubuntu release number
        # * The next 5 digits is # just a package counter, we increase it for each definition
        # * The last 4 digits is a counter for the criterion
        ###
        release_code = int(self.release_name.split(' ')[1].replace('.', '')) if self.release not in cve_lib.external_releases else 1111
        self.release_id = release_code * 10 ** 10
        self.definition_id = self.release_id
        self.definition_step = 1 * 10 ** 5
        self.criterion_step = 10
        self.output_filepath = \
            '{0}com.ubuntu.{1}.{2}.oval.xml'.format('oci.' if self.oval_format == 'oci' else '', self.release.replace('/', '_'), self.generator_type)
        
    def _add_structure(self, root) -> None:
        structure = {}
        for element in self.supported_oval_elements:
            structure_element = element + 's'
            etree.SubElement(root, structure_element)

        return structure

    def _get_generator(self, type) -> etree.Element:
        oval_timestamp = datetime.now(tz=timezone.utc).strftime(
            '%Y-%m-%dT%H:%M:%S')

        generator = etree.Element("generator")
        product_name = etree.SubElement(generator, "oval:product_name")
        product_version = etree.SubElement(generator, "oval:product_version")
        schema_version = etree.SubElement(generator, "oval:schema_version")
        timestamp = etree.SubElement(generator, "oval:timestamp")

        product_name.text = f"Canonical {type} OVAL Generator"
        product_version.text = self.generator_version
        schema_version.text = self.oval_schema_version
        timestamp.text = oval_timestamp

        return generator

    def _get_root_element(self) -> etree.Element:
        root_element = etree.Element("oval_definitions", attrib= {
            "xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5",
            "xmlns:ind-def":"http://oval.mitre.org/XMLSchema/oval-definitions-5#independent",
            "xmlns:oval":"http://oval.mitre.org/XMLSchema/oval-common-5",
            "xmlns:unix-def":"http://oval.mitre.org/XMLSchema/oval-definitions-5#unix",
            "xmlns:linux-def":"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux",
            "xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance" ,
            "xsi:schemaLocation":"http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5#independent independent-definitions-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5#unix unix-definitions-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5#linux linux-definitions-schema.xsd"
        })

        xml_tree = etree.ElementTree(root_element)
        return xml_tree, root_element

    def _add_release_checks(self, root_element) -> None:
        rel_definition = self._create_release_definition()
        rel_family_test, rel_test = self._create_release_test()
        rel_family_obj, rel_obj = self._create_release_object()
        rel_family_state, rel_state = self._create_release_state()

        definitions = root_element.find("definitions")
        tests = root_element.find("tests")
        objects = root_element.find("objects")
        states = root_element.find("states")

        definitions.append(rel_definition)
        tests.append(rel_family_test)
        tests.append(rel_test)
        objects.append(rel_family_obj)
        objects.append(rel_obj)
        states.append(rel_family_state)
        states.append(rel_state)


    def _create_release_definition(self) -> etree.Element:
        if self.oval_format == 'dpkg':
            definition = etree.Element("definition")
            definition.set("class", "inventory")
            definition.set("id", f'{self.ns}:def:{self.id}')
            definition.set("version", "1")

            # Metadata tag
            metadata = etree.Element("metadata")
            title = etree.SubElement(metadata, "title")
            etree.SubElement(metadata, "description")
            title.text = f"Check that {self.release_name} ({self.release_codename}) is installed."

            # Criteria tag
            criteria = etree.Element("criteria")
            criterion_unix = etree.SubElement(criteria, "criterion")
            criterion_rel = etree.SubElement(criteria, "criterion")


            criterion_unix.set("test_ref", f'{self.ns}:tst:{self.id}')
            criterion_unix.set("comment", "The host is part of the unix family.")

            criterion_rel.set("test_ref", f'{self.ns}:tst:{self.id+1}')
            criterion_rel.set("comment", f"The host is running Ubuntu {self.release_codename}")


            definition.append(metadata)
            definition.append(criteria)
        else:
            definition = etree.Element()

        return definition

    def _create_release_test(self) -> Tuple[etree.Element, etree.Element]:
        if self.oval_format == 'dpkg':
            family_test = etree.Element("ind-def:family_test", attrib={
                "id": f'{self.ns}:tst:{self.id}',
                "check":"at least one",
                "check_existence":"at_least_one_exists",
                "version":"1",
                "comment":"Is the host part of the unix family?"
            })

            family_test_obj = etree.SubElement(family_test, "ind-def:object")
            family_test_state = etree.SubElement(family_test, "ind-def:state")
            family_test_obj.set("object_ref", f'{self.ns}:obj:{self.id}')
            family_test_state.set("state_ref", f'{self.ns}:ste:{self.id}')

            textfilecontent54_test = etree.Element("ind-def:textfilecontent54_test", attrib={
                "id": f'{self.ns}:tst:{self.id+1}',
                "check":"at least one",
                "check_existence":"at_least_one_exists",
                "version":"1",
                "comment":f"Is the host running Ubuntu {self.release_codename}?"
            })

            textfc54_test_obj = etree.SubElement(textfilecontent54_test, "ind-def:object")
            textfc54_test_state = etree.SubElement(textfilecontent54_test, "ind-def:state")
            textfc54_test_obj.set("object_ref", f'{self.ns}:obj:{self.id+1}')
            textfc54_test_state.set("state_ref", f'{self.ns}:ste:{self.id+1}')

        else:
            family_test = etree.Element()
            textfilecontent54_test = etree.Element()

        return family_test, textfilecontent54_test

    def _create_release_object(self) -> Tuple[etree.Element, etree.Element]:
        if self.oval_format == 'dpkg':
            family_object = etree.Element("ind-def:family_object",
                attrib={
                    'id' : f"{self.ns}:obj:{self.id}",
                    'version': "1",
                    "comment": "The singleton family object."
                })

            object = etree.Element("ind-def:textfilecontent54_object",
                attrib={
                    'id' : f"{self.ns}:obj:{self.id+1}",
                    'version': "1",
                    "comment": f"The singleton {self.release_codename} object."
                })
            filepath = etree.SubElement(object, "ind-def:filepath")
            pattern = etree.SubElement(object, "ind-def:pattern",attrib={"operation": "pattern match"})
            instance = etree.SubElement(object, "ind-def:instance",attrib={"datatype": "int"})

            filepath.text = "/etc/lsb-release"
            pattern.text = "^[\s\S]*DISTRIB_CODENAME=([a-z]+)$"
            instance.text = "1"
        else:
            family_object = etree.Element("")
            object = etree.Element("")

        return family_object, object

    def _create_release_state(self) -> Tuple[etree.Element, etree.Element]:
        if self.oval_format == 'dpkg':

            family_state= etree.Element("ind-def:family_state",
                attrib={
                    'id' : f"{self.ns}:ste:{self.id}",
                    'version': "1",
                    "comment": "The singleton family state."
                })

            state = etree.Element("ind-def:textfilecontent54_state",
                attrib={
                    'id' : f"{self.ns}:ste:{self.id+1}",
                    'version': "1",
                    "comment": f"The singleton {self.release_codename} state."
                })

            family = etree.SubElement(family_state, "ind-def:family")
            subexpression = etree.SubElement(state, "ind-def:subexpression")

            family.text = "unix"
            subexpression.text = cve_lib.product_series(self.release)[1]
        else:
            family_state = etree.Element()
            state = etree.Element()

        return family_state, state

    def _add_new_package(self, package_name, cve, release, cve_data, packages) -> None:
        if package_name not in packages:
            _, versions_binaries = get_binarypkgs(self.pkg_cache, package_name, release)
            pkg_obj = Package(package_name, release, versions_binaries)
            packages[package_name] = pkg_obj

        pkg_obj = packages[package_name]
        cve.add_pkg(pkg_obj, release, cve_data['pkgs'][package_name][release][0],cve_data['pkgs'][package_name][release][1])

    def _load(self, cve_prefix_dir, packages_filter=None) -> None:
        cve_lib.load_external_subprojects()

        cve_paths = []
        for pathname in self.cve_paths:
            cve_paths = cve_paths + glob.glob(os.path.join(cve_prefix_dir, pathname))

        cve_paths.sort(key=lambda cve:
                   (int(cve.split('/')[-1].split('-')[1]), int(cve.split('/')[-1].split('-')[2])) \
                    if cve.split('/')[-1].split('-')[2].isnumeric() \
                    else (int(cve.split('/')[-1].split('-')[1]), 0)
                 )

        packages = {}
        cves = {}
        base_releases = self.releases
        final_releases = set(self.releases)
        for current_release in base_releases:
            while(cve_lib.release_parent(current_release)):
                current_release = cve_lib.release_parent(current_release)
                final_releases.add(current_release)

        for release in final_releases:
            packages.setdefault(release, {})
            cves.setdefault(release, {})
            sources[release] = load(releases=[release], skip_eol_releases=False)[release]

            orig_name = cve_lib.get_orig_rel_name(release)
            if '/' in orig_name:
                orig_name = orig_name.split('/', maxsplit=1)[1]
            source_map_binaries[release] = load(data_type='packages',releases=[orig_name], skip_eol_releases=False)[orig_name] \
                if release not in cve_lib.external_releases else {}

        i = 0
        for cve_path in cve_paths:
            cve_number = cve_path.rsplit('/', 1)[1]
            i += 1

            if self.progress:
                print(f'[{i:5}/{len(cve_paths)}] Processing {cve_number:18}', end='\r')

            if not cve_number in self.cve_cache:
                self.cve_cache[cve_number] = cve_lib.load_cve(cve_path)

            info = self.cve_cache[cve_number]
            cve_obj = CVE(cve_number, info)
            for pkg in info['pkgs']:
                if packages_filter and pkg not in packages_filter:
                    continue

                for release in final_releases:
                    if pkg in sources[release] and release in info['pkgs'][pkg] and \
                        info['pkgs'][pkg][release][0] != 'DNE':
                            self._add_new_package(pkg, cve_obj, release, info, packages[release])
                            if cve_number not in cves[release]:
                                cves[release][cve_number] = cve_obj

        for release in final_releases:
            packages[release] = dict(sorted(packages[release].items()))
            cves[release] = dict(sorted(cves[release].items()))

        if self.progress:
            print(' ' * 40, end='\r')
        return packages, cves

    def _write_oval_xml(self, xml_tree: etree.ElementTree, root_element: etree.ElementTree) -> None:
        if sys.version_info[0] >= 3 and sys.version_info[1] >= 9:
            etree.indent(xml_tree, level=0) # indent only available from Python 3.9
            xml_tree.write(os.path.join(self.output_dir, self.output_filepath))
        else:
            xmlstr = minidom.parseString(etree.tostring(root_element)).toprettyxml(indent="  ")
            with open(os.path.join(self.output_dir, self.output_filepath), 'w') as file:
                file.write(xmlstr)

    # Object generators
    def _generate_criteria(self) -> etree.Element:
        criteria = etree.Element("criteria")
        if self.oval_format == 'dpkg':
            extend_definition = etree.SubElement(criteria, "extend_definition")

            extend_definition.set("definition_ref", f"{self.ns}:def:{self.host_def_id}")
            extend_definition.set("comment", f"{self.release_name} is installed.")
            extend_definition.set("applicability_check", "true")

        return criteria
    
    def _generate_definition_object(self, object) -> etree.Element:
        id = f"{self.ns}:def:{self.definition_id}"
        definition = etree.Element("definition")
        definition.set("class", "vulnerability")
        definition.set("id", id)
        definition.set("version", "1")

        metadata = self._generate_metadata(object)
        criteria = self._generate_criteria()
        definition.append(metadata)
        definition.append(criteria)

        return definition

    def _add_test_ref_to_cve_tag(self, test_ref_id: int, cve: CVE, definition: etree.Element):
        advisory = definition.find('.//advisory')

        for cve_tag in advisory.findall('cve'):
            if cve_tag.text == cve.number:
                cve_tag.attrib['test_ref'] = f"{self.ns}:tst:{test_ref_id}"
                return

    def _generate_cve_tag(self, cve: CVE) -> etree.Element:
        cve_tag = etree.Element("cve",
            attrib={
                'href' : f"https://ubuntu.com/security/{cve.number}",
                'priority': cve.priority,
                'public': cve.public_date.split(' ')[0].replace('-', '')
            })

        cve_tag.text = cve.number
        if cve.cvss:
            cve_tag.set('cvss_score', cve.cvss[0]['baseScore'])
            cve_tag.set('cvss_vector', cve.cvss[0]['vector'])
            cve_tag.set('cvss_severity', cve.cvss[0]['baseSeverity'].lower())
            if cve.usns:
                cve_tag.set('usns', ','.join(cve.usns))

        return cve_tag
    
    def _generate_var_element(self, comment, id, binaries) -> etree.Element:
        var = etree.Element("constant_variable",
            attrib={
                'id' : f"{self.ns}:var:{id}",
                'version': "1",
                "datatype": "string",
                "comment": comment
            })

        for binary in binaries:
            item = etree.SubElement(var, "value")
            item.text = binary

        return var

    def _generate_object_element(self, comment, id, var_id) -> etree.Element:
        if self.oval_format == 'dpkg':
            object = etree.Element("linux-def:dpkginfo_object",
                attrib={
                    'id' : f"{self.ns}:obj:{id}",
                    'version': "1",
                    "comment": comment
                })

            etree.SubElement(object, "linux-def:name", attrib={
                "var_ref": f"{self.ns}:var:{var_id}",
                "var_check": "at least one"
            })
        elif self.oval_format == 'oci':
            object = etree.Element("ind-def:textfilecontent54_object",
                attrib={
                    'id' : f"{self.ns}:obj:{id}",
                    'version': "1",
                    "comment": comment
                })
            path = etree.SubElement(object, 'ind-def:path')
            filename = etree.SubElement(object, 'ind-def:filename')
            etree.SubElement(object, "ind-def:pattern", attrib={
                "operation": "pattern match",
                "datatype": "string",
                "var_ref": f"{self.ns}:var:{var_id}",
                "var_check": "at least one"
            })
            instance = etree.SubElement(object, 'ind-def:instance', attrib={
                "operation": "greater than or equal",
                "datatype": "int"
            })
            path.text = '.'
            filename.text = 'manifest'
            instance.text = '1'

        return object

    def _generate_test_element(self, comment, id, create_state, type, obj_id = None, state_id=None) -> etree.Element:
        if type == 'pkg':
            if self.oval_format == 'dpkg':
                tag = 'dpkginfo_test'
                pre_tag = 'linux-def'
            elif self.oval_format == 'oci':
                tag = 'textfilecontent54_test'
                pre_tag = 'ind-def'
            else:
                ValueError()
        elif type == 'kernel':
            tag = 'variable_test'
            pre_tag = 'ind-def'

        test = etree.Element(f'{pre_tag}:{tag}', attrib={
            "id": f"{self.ns}:tst:{id}",
            "version": "1",
            "check_existence": "at_least_one_exists",
            "check": "at least one",
            "comment": comment
        })
        textfc54_test_obj = etree.SubElement(test, f"{pre_tag}:object")
        textfc54_test_obj.set("object_ref", f'{self.ns}:obj:{obj_id if obj_id else id}')

        if create_state:
            textfc54_test_state = etree.SubElement(test, f"{pre_tag}:state")
            textfc54_test_state.set("state_ref", f'{self.ns}:ste:{state_id if state_id else id}')

        return test

    def _generate_state_element(self, comment, id, version) -> None:
        if version.find(':') == -1:
            version = f"0:{version}"

        if self.oval_format == 'dpkg':
            object = etree.Element("linux-def:dpkginfo_state",
                attrib={
                    'id' : f"{self.ns}:ste:{id}",
                    'version': "1",
                    "comment": comment
                })

            version_check = etree.SubElement(object, "linux-def:evr", attrib={
                "datatype": "debian_evr_string",
                "operation": "less than"
            })

            version_check.text = f"{version}"
        elif self.oval_format == 'oci':
            object = etree.Element("ind-def:textfilecontent54_state",
                attrib={
                    'id' : f"{self.ns}:ste:{id}",
                    'version': "1",
                    "comment": comment
                })

            version_check = etree.SubElement(object, "ind-def:subexpression", attrib={
                "datatype": "debian_evr_string",
                "operation": "less than"
            })

            version_check.text = f"{version}"
        else:
            ValueError(f"Format not {self.oval_format} not supported")

        return object

    def _generate_criterion_element(self, comment, id) -> etree.Element:
        criterion = etree.Element("criterion", attrib={
            "test_ref": f"{self.ns}:tst:{id}",
            "comment": comment
        })

        return criterion

    def _generate_vulnerable_elements(self, package, binaries, obj_id=None):
        binary_keyword = 'binaries' if len(binaries) > 1 else 'binary'
        test_note = f"Does the '{package.name}' package exist?"
        object_note = f"The '{package.name}' package {binary_keyword}"

        test = self._generate_test_element(test_note, self.definition_id, False, 'pkg', obj_id=obj_id)

        if not obj_id:
            object = self._generate_object_element(object_note, self.definition_id, self.definition_id)

            if package.is_kernel_pkg:
                regex = process_kernel_binaries(binaries, 'oci')
                binaries = [f'{regex}']

            final_binaries = []
            if self.oval_format == 'oci':
                variable_values = '(?::\w+|)\s+(.*)$'
                for binary in binaries:
                    final_binaries.append(f'^{binary}{variable_values}')
            else:
                final_binaries = binaries

            var = self._generate_var_element(object_note, self.definition_id, final_binaries)
        else:
            object = None
            var = None
        return test, object, var

    def _generate_fixed_elements(self, package, binaries, version, obj_id=None):
        binary_keyword = 'binaries' if len(binaries) > 1 else 'binary'
        test_note = f"Does the '{package.name}' package exist and is the version less than '{version}'?"
        object_note = f"The '{package.name}' package {binary_keyword}"
        state_note = f"The package version is less than '{version}'"

        test = self._generate_test_element(test_note, self.definition_id, True, 'pkg', obj_id=obj_id)
        if not obj_id:
            object = self._generate_object_element(object_note, self.definition_id, self.definition_id)

            final_binaries = binaries
            if self.oval_format == 'oci':
                if package.is_kernel_pkg:
                    regex = process_kernel_binaries(binaries, 'oci')
                    final_binaries = [f'^{regex}(?::\w+|)\s+(.*)$']
                else:
                    variable_values = '(?::\w+|)\s+(.*)$'

                    final_binaries = []
                    for binary in binaries:
                        final_binaries.append(f'^{binary}{variable_values}')

            var = self._generate_var_element(object_note, self.definition_id, final_binaries)
        else:
            object = None
            var = None
        state = self._generate_state_element(state_note, self.definition_id, version)

        return test, object, var, state

    # Running kernel element generators
    def _add_running_kernel_checks(self, root_element):
        objects = root_element.find("objects")
        variables = root_element.find("variables")

        variable_local_kernel_check = self._generate_local_variable_kernel(self.definition_id, "Kernel version in evr format", self.definition_id)
        obj_running_kernel = self._generate_uname_object_element(self.definition_id)

        objects.append(obj_running_kernel)
        variables.append(variable_local_kernel_check)

    def _generate_local_variable_kernel(self, id, comment, uname_obj_id):
        var = etree.Element("local_variable",
            attrib={
                'id': f"{self.ns}:var:{id}",
                'version': "1",
                "datatype": "debian_evr_string",
                "comment": comment
            })
        concat = etree.SubElement(var, "concat")
        component = etree.SubElement(concat, "literal_component")
        regex = etree.SubElement(concat, "regex_capture", attrib={
            "pattern": "^([\d|\.]+-\d+)[-|\w]+$"
        })

        etree.SubElement(regex, "object_component", attrib={
            "object_ref": f"{self.ns}:obj:{uname_obj_id}",
            "item_field": "os_release"
        })

        component.text = "0:"

        return var

    def _generate_uname_object_element(self, id):
        object = etree.Element("unix-def:uname_object",
            attrib={
                'id' : f"{self.ns}:obj:{id}",
                'version': "1",
                "comment": "The uname object."
            })

        return object

    def _generate_uname_state_element(self, id, regex, comment):
        object = etree.Element("unix-def:uname_state",
            attrib={
                'id' : f"{self.ns}:ste:{id}",
                'version': "1",
                "comment": comment
            })

        version_check = etree.SubElement(object, "unix-def:os_release", attrib={
            "operation": "pattern match"
        })

        version_check.text = regex

        return object

    def _generate_test_element_running_kernel(self, id, comment, obj_id):
        test = etree.Element("unix-def:uname_test", attrib={
            "id": f"{self.ns}:tst:{id}",
            "version": "1",
            "check": "at least one",
            "comment": comment
        })

        textfc54_test_obj = etree.SubElement(test, "unix-def:object")
        textfc54_test_obj.set("object_ref", f'{self.ns}:obj:{obj_id}')

        textfc54_test_state = etree.SubElement(test, "unix-def:state")
        textfc54_test_state.set("state_ref", f'{self.ns}:ste:{id}')

        return test

    # Kernel elements generators
    def _generate_criteria_kernel(self, operator) -> etree.Element:
        return etree.Element("criteria", attrib={
            "operator": operator
        })

    def _generate_kernel_version_object_element(self, id, var_id) -> etree.Element:
        object = etree.Element("ind-def:variable_object",
            attrib={
                'id' : f"{self.ns}:obj:{id}",
                'version': "1",
            })

        var_ref = etree.SubElement(object, 'ind-def:var_ref')
        var_ref.text = f"{self.ns}:var:{var_id}"

        return object

    def _generate_state_kernel_element(self, comment, id, version) -> None:
        patched = re.search('([\d|\.]+-\d+)[\.|\d]+', version)
        if patched:
            patched = patched.group(1)
        else:
            patched = version

        state = etree.Element("ind-def:variable_state",
            attrib={
                'id' : f"{self.ns}:ste:{id}",
                'version': "1",
                "comment": comment
            })

        value = etree.SubElement(state, "ind-def:value", attrib={
            "datatype": "debian_evr_string",
            "operation": "less than",
        })

        value.text = f"0:{patched}"
        return state

    def _generate_kernel_package_elements(self, package: Package, binaries, root_element, running_kernel_check_id) -> etree.Element:
        tests = root_element.find("tests")
        states = root_element.find("states")

        comment_running_kernel = f'Is kernel {package.name} running?'
        regex = process_kernel_binaries(binaries, self.oval_format)

        criterion_running_kernel = self._generate_criterion_element(comment_running_kernel, self.definition_id)
        test_running_kernel = self._generate_test_element_running_kernel(self.definition_id, comment_running_kernel, running_kernel_check_id)
        state_running_kernel = self._generate_uname_state_element(self.definition_id, regex, f"Regex match for kernel {package.name}")

        self.definition_id += self.criterion_step

        tests.append(test_running_kernel)
        states.append(state_running_kernel)

        return criterion_running_kernel

    def _add_kernel_elements(self, cve: CVE, package: Package, version, package_rel_entry:CVEPkgRelEntry, root_element, running_kernel_id, fixed_versions) -> etree.Element:
        tests = root_element.find("tests")
        objects = root_element.find("objects")
        states = root_element.find("states")

        comment_version = f'Kernel {package.name} version comparison'
        comment_criterion = ''
        if self.generator_type == 'pkg':
            comment_criterion = f'({cve.number}) '
        comment_criterion = comment_criterion + f'{package.name}{package_rel_entry.note}'

        if version in fixed_versions:
            criterion_version = self._generate_criterion_element(comment_criterion, fixed_versions[version])
        else:
            create_state = False

            if version:
                create_state = True
                ste_kernel_version = self._generate_state_kernel_element("Kernel check", self.definition_id, version)
                states.append(ste_kernel_version)

            obj_kernel_version = self._generate_kernel_version_object_element(self.definition_id, running_kernel_id)

            test_kernel_version = self._generate_test_element(comment_version, self.definition_id, create_state, 'kernel', self.definition_id)

            criterion_version = self._generate_criterion_element(comment_criterion, self.definition_id)

            tests.append(test_kernel_version)
            objects.append(obj_kernel_version)

            fixed_versions[version] = self.definition_id

        return criterion_version

    # General functions
    def _increase_id(self, is_definition):
        if is_definition:
            self.definition_id += self.definition_step
            # Ugly hack, Python doesn't like operating big numbers
            criterion_appendix_length = len(str(self.definition_step)) - 1
            self.definition_id = int(str(self.definition_id)[: -1 * criterion_appendix_length])
            self.definition_id = int(self.definition_id * self.definition_step)
        else:
            self.definition_id += self.criterion_step

    def _add_to_criteria(self, definition, element, depth=2, operator='OR'):
        criteria = definition
        for _ in range(depth):
            prev_criteria = criteria
            criteria = criteria.find('criteria')
            if criteria == None:
                criteria = etree.SubElement(prev_criteria, "criteria")
                criteria.set("operator", operator)

        criteria.append(element)

    def _add_criterion(self, id, package_entry, cve, definition, depth=2) -> None:
        criterion_note = f'({cve.number}) ' if self.generator_type == 'pkg' else ''
        criterion_note += f'{package_entry.pkg.name}{package_entry.note}'
        criterion = self._generate_criterion_element(criterion_note, id)
        self._add_to_criteria(definition, criterion, depth)

    def _generate_elements(self, package, binaries, version, pkg_rel_entry, obj_id=None):
        create_state = False
        state = None
        var = None
        obj = None
        binary_keyword = 'binaries' if len(binaries) > 1 else 'binary'
        object_note = f"The '{package.name}' package {binary_keyword}"
        test_note = ""

        final_binaries = binaries
        if self.oval_format == 'oci':
            if package.is_kernel_pkg:
                regex = process_kernel_binaries(binaries, 'oci')
                final_binaries = [f'^{regex}(?::\w+|)\s+(.*)$']
            else:
                variable_values = '(?::\w+|)\s+(.*)$'

                final_binaries = []
                for binary in binaries:
                    final_binaries.append(f'^{binary}{variable_values}')

        if pkg_rel_entry.status == 'vulnerable':
            test_note = f"Does the '{package.name}' package exist?"
        elif pkg_rel_entry.status == 'fixed':
            test_note = f"Does the '{package.name}' package exist and is the version less than '{version}'?"
            state_note = f"The package version is less than '{version}'"

            state = self._generate_state_element(state_note, self.definition_id, version)
            create_state = True

        if not obj_id:
            var = self._generate_var_element(object_note, self.definition_id, final_binaries)
            obj = self._generate_object_element(object_note, self.definition_id, self.definition_id)

        test = self._generate_test_element(test_note, self.definition_id, create_state, 'pkg', obj_id=obj_id)

        return test, obj, var, state

    # returns True if we should ignore this source package; primarily used
    # for -edge kernels
    def _ignore_source_package(self, source):
        if re.match('linux-.*-edge$', source):
            return True
        if re.match('linux-riscv.*$', source):
            # linux-riscv.* currently causes a lot of false positives, skip
            # it altogether while we don't land a better fix
            return True
        return False


class OvalGeneratorPkg(OvalGenerator):
    def __init__(self, releases, cve_paths, packages, progress, pkg_cache, fixed_only=True, cve_cache=None,  cve_prefix_dir=None, outdir='./', oval_format='dpkg') -> None:
        super().__init__('pkg', releases, cve_paths, packages, progress, pkg_cache, fixed_only, cve_cache,  cve_prefix_dir, outdir, oval_format)

    def _generate_advisory(self, package: Package) -> etree.Element:
        advisory = etree.Element("advisory")
        rights = etree.SubElement(advisory, "rights")
        component = etree.SubElement(advisory, "component")
        version = etree.SubElement(advisory, "current_version")

        for cve in package.cves:
            if self.fixed_only and cve.pkg_rel_entries[str(package)].status != 'fixed':
                continue
            elif cve.pkg_rel_entries[str(package)].is_not_applicable():
                continue
            cve_obj = self._generate_cve_tag(cve)
            advisory.append(cve_obj)

        rights.text = f"Copyright (C) {datetime.now().year} Canonical Ltd."
        component.text = package.section
        version.text = package.get_latest_version()

        return advisory

    def _generate_metadata(self, package: Package) -> etree.Element:
        metadata = etree.Element("metadata")
        title = etree.SubElement(metadata, "title")
        reference = self._generate_reference(package)
        advisory = self._generate_advisory(package)
        metadata.append(reference)
        description = etree.SubElement(metadata, "description")
        affected = etree.SubElement(metadata, "affected", attrib = {"family": "unix"})
        platform = etree.SubElement(affected, "platform")
        metadata.append(advisory)

        platform.text = self.release_name
        title.text = package.name
        description.text = package.description

        return metadata

    # Element generators
    def _generate_reference(self, package) -> etree.Element:
        reference = etree.Element("reference", attrib={
            "source": "Package",
            "ref_id": package.name,
            "ref_url": f'https://launchpad.net/ubuntu/+source/{package.name}'
        })

        return reference

    def _populate_pkg(self, package, root_element):
        tests = root_element.find("tests")
        objects = root_element.find("objects")
        variables = root_element.find("variables")
        states = root_element.find("states")

        # Add package definition
        definitions = root_element.find("definitions")
        definition_element = self._generate_definition_object(package)

        # Control/cache variables
        one_time_added_id = None
        fixed_versions = {}
        binaries_ids = {}
        cve_added = False

        #criteria = None
        #if len(package.binaries) > 1:
        #    criteria = self._generate_subcriteria('AND')

        for cve in package.cves:
            if self.fixed_only and cve.pkg_rel_entries[str(package)].status != 'fixed':
                continue
            pkg_rel_entry = cve.pkg_rel_entries[str(package)]
            if pkg_rel_entry.is_not_applicable(): continue
            source_version = package.get_version_to_check(pkg_rel_entry.fixed_version)
            for binary_version in package.get_binary_versions(source_version):
                binaries = package.get_binaries(source_version, binary_version)

                # For released / not affected (version) CVEs
                if pkg_rel_entry.fixed_version:
                    if binary_version in fixed_versions:
                        self._add_test_ref_to_cve_tag(fixed_versions[binary_version], cve, definition_element)
                        self._add_criterion(fixed_versions[binary_version], pkg_rel_entry, cve, definition_element)
                        continue
                    else:
                        self._add_test_ref_to_cve_tag(self.definition_id, cve, definition_element)
                        self._add_criterion(self.definition_id, pkg_rel_entry, cve, definition_element)
                        fixed_versions[binary_version] = self.definition_id
                # For not fixed CVEs, we already added one for this package
                elif one_time_added_id:
                    self._add_test_ref_to_cve_tag(one_time_added_id, cve, definition_element)
                    self._add_criterion(one_time_added_id, pkg_rel_entry, cve, definition_element)
                    continue
                # For not fixed CVEs, only need to add it once per package
                else:
                    self._add_test_ref_to_cve_tag(self.definition_id, cve, definition_element)
                    self._add_criterion(self.definition_id, pkg_rel_entry, cve, definition_element)
                    one_time_added_id = self.definition_id

                # If version doesn't exist and only one binary_version, they all have the same binaries
                if not package.version_exists(source_version) and package.all_binaries_same_version:
                    binary_id_version = GENERIC_VERSION
                else:
                    binary_id_version = binary_version

                binaries_ids.setdefault(binary_id_version, None)
                binaries_id = binaries_ids[binary_id_version]  
                test, obj, var, state = self._generate_elements(package, binaries, binary_version, pkg_rel_entry, binaries_id)

                if state:
                    states.append(state)

                if obj and var:
                    binaries_ids[binary_id_version] = self.definition_id
                    variables.append(var)
                    objects.append(obj)

                tests.append(test)
                self._increase_id(is_definition=False)
                cve_added = True

        if cve_added:
            definitions.append(definition_element)

        self._increase_id(is_definition=True)

    def _populate_kernel_pkg(self, package, root_element, running_kernel_id):            
        for cve in package.cves:
            pkg_rel_entry = cve.pkg_rel_entries[str(package)]
            version_to_check = package.get_version_to_check(pkg_rel_entry.fixed_version)
            for binary_version in package.get_binary_versions(version_to_check):
                binaries = package.get_binaries(version_to_check, binary_version)
        # Add package definition
        definitions = root_element.find("definitions")
        definition_element = self._generate_definition_object(package)

        # Control/cache variables
        fixed_versions = {}
        cve_added = False

        # Kernel binaries have all same version
        version = package.get_latest_version()
        binaries = package.get_binaries(version, version)

        # Generate one-time elements
        kernel_criterion = self._generate_kernel_package_elements(package, binaries, root_element, running_kernel_id)
        criteria = self._generate_criteria_kernel('OR')

        self._add_to_criteria(definition_element, kernel_criterion, operator='AND')
        self._add_to_criteria(definition_element, criteria, operator='AND')

        for cve in package.cves:
            pkg_rel_entry = cve.pkg_rel_entries[str(package)]
            if pkg_rel_entry.is_not_applicable(): continue
            cve_added = True

            self._add_test_ref_to_cve_tag(self.definition_id, cve, definition_element)

            kernel_version_criterion = self._add_kernel_elements(cve, package, pkg_rel_entry.fixed_version, pkg_rel_entry, root_element, running_kernel_id, fixed_versions)
            self._add_to_criteria(definition_element, kernel_version_criterion, depth=3)
            self._increase_id(is_definition=False)

        if cve_added:
            definitions.append(definition_element)
        self._increase_id(is_definition=True)

    def generate_oval(self) -> None:
        for release in self.releases:
            self._init_ids(release)
            xml_tree, root_element = self._get_root_element()
            generator = self._get_generator("Package")
            root_element.append(generator)
            self._add_structure(root_element)

            if self.oval_format == 'dpkg':
                # One time kernel check
                self._add_release_checks(root_element)
                self._add_running_kernel_checks(root_element)
                running_kernel_id = self.definition_id
                self._increase_id(is_definition=True)

            all_pkgs = dict()
            for parent_release in self.parent_releases[::-1]:
                all_pkgs.update(self.packages[parent_release])
            
            all_pkgs.update(self.packages[self.release])

            for pkg in all_pkgs:
                if self._ignore_source_package(pkg): continue
                if not all_pkgs[pkg].versions_binaries: continue
                if not all_pkgs[pkg].get_binary_versions(next(iter(all_pkgs[pkg].versions_binaries))): continue
                if all_pkgs[pkg].is_kernel_pkg and self.oval_format != 'oci':
                    self._populate_kernel_pkg(all_pkgs[pkg], root_element, running_kernel_id)
                else:
                    self._populate_pkg(all_pkgs[pkg], root_element)

            self._write_oval_xml(xml_tree, root_element)

class OvalGeneratorCVE(OvalGenerator):
    def __init__(self, releases, cve_paths, packages, progress, pkg_cache, fixed_only=True, cve_cache=None,  cve_prefix_dir=None, outdir='./', oval_format='dpkg') -> None:
        super().__init__('cve', releases, cve_paths, packages, progress, pkg_cache, fixed_only, cve_cache,  cve_prefix_dir, outdir, oval_format)

    # For CVE OVAL, the definition ID is generated
    # from the CVE ID
    def _set_definition_id(self, cve_id):
        self.definition_id = int(re.sub('[^0-9]', '', cve_id)) * self.definition_step

    def _generate_advisory(self, cve: CVE) -> etree.Element:
        advisory = etree.Element("advisory")
        severity = etree.SubElement(advisory, "severity")
        rights = etree.SubElement(advisory, "rights")
        public_date = etree.SubElement(advisory, "public_date")

        if cve.public_date_at_usn:
            public_date_at_usn = etree.SubElement(advisory, "public_date_at_usn")
            public_date_at_usn.text = cve.public_date_at_usn

        if cve.assigned_to:
            assigned_to = etree.SubElement(advisory, "assigned_to")
            assigned_to.text = cve.assigned_to
            
        if cve.discoverd_by:
            discoverd_by = etree.SubElement(advisory, "discoverd_by")
            discoverd_by.text = cve.discoverd_by

        for bug in cve.bugs:
            element = etree.SubElement(advisory, 'bug')
            element.text = bug

        for usn in cve.usns:
            element = etree.SubElement(advisory, 'ref')
            element.text = f'https://ubuntu.com/security/notices/USN-{usn}'

        advisory.append(self._generate_cve_tag(cve))
        rights.text = f"Copyright (C) {cve.public_date.split('-', 1)[0]} Canonical Ltd."
        severity.text = cve.priority.capitalize()
        public_date.text = cve.public_date

        return advisory

    def _generate_metadata(self, cve: CVE) -> etree.Element:
        metadata = etree.Element("metadata")
        title = etree.SubElement(metadata, "title")
        reference = self._generate_reference(cve)
        advisory = self._generate_advisory(cve)
        description = etree.SubElement(metadata, "description")
        affected = etree.SubElement(metadata, "affected", attrib = {"family": "unix"})
        platform = etree.SubElement(affected, "platform")
        metadata.append(reference)
        metadata.append(advisory)

        platform.text = self.release_name
        title.text = f'{cve.number} on {self.release_name} ({self.release_codename}) - {cve.priority}'
        description.text = cve.description.replace('\n','')

        return metadata

    # Element generators
    def _generate_reference(self, cve: CVE) -> etree.Element:
        reference = etree.Element("reference", attrib={
            "source": "CVE",
            "ref_id": cve.number,
            "ref_url": f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve.number}'
        })

        return reference        

    def prepare_instructions(self, instruction, cve: CVE, product_description, package: Package, fixed_version):
        if "LSN" in cve.number:
            instruction = """\n
    To check your kernel type and Livepatch version, enter this command:

    canonical-livepatch status"""

        if not instruction:
            instruction = """\n
    Update Instructions:

    Run `sudo pro fix {0}` to fix the vulnerability. The problem can be corrected
    by updating your system to the following package versions:""".format(cve)

        instruction += '\n\n'
        source_version = package.get_version_to_check(fixed_version)
        for binary_version in package.get_binary_versions(source_version):
            binaries = package.get_binaries(source_version, binary_version)
            for binary in binaries:
                instruction += """{0} - {1}\n""".format(binary, binary_version)

        if "LSN" in cve.number:
            instruction += "Livepatch subscription required"
        elif "Long Term" in product_description or "Interim" in product_description:
            instruction += "No subscription required"
        else:
            instruction += product_description

        return instruction

    def _populate_pkg(self, cve: CVE, package: Package, root_element, main_criteria, cache, fixed_versions) -> bool:
        tests = root_element.find("tests")
        objects = root_element.find("objects")
        variables = root_element.find("variables")
        states = root_element.find("states")
        pkg_rel_entry = cve.pkg_rel_entries[str(package)]
        added = False

        source_version = package.get_version_to_check(pkg_rel_entry.fixed_version)
        for binary_version in package.get_binary_versions(source_version):
            binaries = package.get_binaries(source_version, binary_version)
            if not binaries: continue
            cache_entry = f'{package.name}-{binary_version}'

            cache.setdefault(cache_entry, dict(bin_id=None, def_id=None))

            # If version doesn't exist and only one binary_version, they all have the same binaries
            if not package.version_exists(source_version) and package.all_binaries_same_version:
                cache_entry_bin = f'{package.name}-{GENERIC_VERSION}'
                cache.setdefault(cache_entry_bin, dict(bin_id=None, def_id=None))
            else:
                cache_entry_bin = cache_entry

            if pkg_rel_entry.status == 'vulnerable' and not self.fixed_only:
                added = True
                if not cache_entry in cache or not cache[cache_entry]['def_id']:
                    self._add_criterion(self.definition_id, pkg_rel_entry, cve, main_criteria)

                    test, object, var = self._generate_vulnerable_elements(package, binaries, cache[cache_entry_bin]['bin_id'])
                    tests.append(test)

                    if not cache[cache_entry_bin]['bin_id']:
                        objects.append(object)
                        variables.append(var)
                        cache[cache_entry_bin]['bin_id'] = self.definition_id

                    cache[cache_entry]['def_id'] = self.definition_id
                    self._increase_id(is_definition=False)
                else:
                    self._add_criterion(cache[cache_entry]['def_id'], pkg_rel_entry, cve, main_criteria)
            elif pkg_rel_entry.status == 'fixed':
                added = True
                if binary_version in fixed_versions:
                    self._add_criterion(fixed_versions[binary_version], pkg_rel_entry, cve, main_criteria)
                else:
                    self._add_criterion(self.definition_id, pkg_rel_entry, cve, main_criteria)

                    test, object, var, state = self._generate_fixed_elements(package, binaries, binary_version, cache[cache_entry_bin]['bin_id'])
                    tests.append(test)
                    states.append(state)

                    if not cache[cache_entry_bin]['bin_id']:
                        objects.append(object)
                        variables.append(var)
                        cache[cache_entry_bin]['bin_id'] = self.definition_id

                    fixed_versions[binary_version] = self.definition_id
                    self._increase_id(is_definition=False)

        return added

    def _populate_kernel_pkg(self, cve: CVE, package: Package, root_element, main_criteria, running_kernel_id, cache, fixed_versions) -> None:
        # Kernel binaries have all same version
        version = package.get_latest_version()
        binaries = package.get_binaries(version, version)
        pkg_rel_entry = cve.pkg_rel_entries[str(package)]
        cache_entry = f'{package.name}-{pkg_rel_entry.fixed_version}'

        if not cache_entry in cache:
            # Generate one-time elements
            kernel_criterion = self._generate_kernel_package_elements(package, binaries, root_element, running_kernel_id)
            cache[cache_entry] = kernel_criterion

        if pkg_rel_entry.status == 'fixed':
            criteria = self._generate_criteria_kernel('AND')
            self._add_to_criteria(criteria, cache[cache_entry], operator='AND', depth=0)

            kernel_version_criterion = self._add_kernel_elements(cve, package, pkg_rel_entry.fixed_version, pkg_rel_entry, root_element, running_kernel_id, fixed_versions)
            self._add_to_criteria(criteria, kernel_version_criterion, depth=0)
            self._add_to_criteria(main_criteria, criteria, depth=2, operator='OR')
            self._increase_id(is_definition=False)
        else:
            self._add_to_criteria(main_criteria, cache[cache_entry], depth=2, operator='OR')

    def _generate_elements_from_cve(self, cve, supported_releases, root_element, running_kernel_id, pkg_cache, fixed_versions) -> None:
        if not cve.pkgs: return
        cve_added = False
        definition_element = self._generate_definition_object(cve)
        instructions = ''
        pkgs = cve.get_pkgs(supported_releases)
        for pkg in pkgs:
            pkg_added = False
            if not pkg.versions_binaries: continue
            if self._ignore_source_package(pkg.name): continue

            pkg_rel_entry = cve.pkg_rel_entries[str(pkg)]
            if pkg.is_kernel_pkg and self.oval_format != 'oci':
                self._populate_kernel_pkg(cve, pkg, root_element, definition_element, running_kernel_id, pkg_cache, fixed_versions)
                pkg_added = True
            else:
                pkg_added = self._populate_pkg(cve, pkg, root_element, definition_element, pkg_cache, fixed_versions)
            
            if pkg_rel_entry.status == 'fixed' and pkg_added:
                product_description = cve_lib.get_subproject_description(pkg_rel_entry.release)
                instructions = self.prepare_instructions(instructions, cve, product_description, pkg, pkg_rel_entry.fixed_version)

            cve_added = cve_added | pkg_added
        
        if cve_added:
            definitions = root_element.find("definitions")
            metadata = definition_element.find('metadata')
            metadata.find('description').text = metadata.find('description').text + instructions
            definitions.append(definition_element)


    def generate_oval(self) -> None:
        for release in self.releases:
            self._init_ids(release)
            self.definition_step = 1 * 10 ** 7
            xml_tree, root_element = self._get_root_element()
            generator = self._get_generator("CVE")
            root_element.append(generator)
            self._add_structure(root_element)
            running_kernel_id = None

            if self.oval_format == 'dpkg':
                # One time kernel check
                self._add_release_checks(root_element)
                self._add_running_kernel_checks(root_element)
                running_kernel_id = self.definition_id

            pkg_cache = {}
            fixed_versions = {}
            accepted_releases = self.parent_releases.copy()
            accepted_releases.insert(0, self.release)

            all_cves = self.cves[self.release]
            for parent_release in self.parent_releases:
                for cve in self.cves[parent_release]:
                    if cve not in all_cves:
                        all_cves[cve] = self.cves[parent_release][cve]

            all_cves = dict(sorted(all_cves.items()))

            for cve in all_cves:
                self._set_definition_id(cve_id=all_cves[cve].number)
                self._generate_elements_from_cve(all_cves[cve], accepted_releases, root_element, running_kernel_id, pkg_cache, fixed_versions)

            self._write_oval_xml(xml_tree, root_element)

class OvalGeneratorUSNs(OvalGenerator):
    def __init__(self, release, release_name, cve_paths, packages, progress, pkg_cache, usn_db_dir, fixed_only=True, cve_cache=None,  cve_prefix_dir=None, outdir='./', oval_format='dpkg') -> None:
        super().__init__('usn', release, release_name, cve_paths, packages, progress, pkg_cache, fixed_only, cve_cache,  cve_prefix_dir, outdir, oval_format)
        self._load_usns(usn_db_dir)

    def _load_usns(self, usn_db_dir):
        self.usns = {}
        for filename in glob.glob(os.path.join(usn_db_dir, 'database*.json')):
            with open(filename, 'r') as f:
                data = json.load(f)
                for item in data:
                    usn = USN(item)
                    self.usns[usn.id] = usn

        for usn_id in sorted(self.usns.keys()):
            if re.search(r'^[0-9]+-[0-9]$', usn_id):
                self.usns[usn_id]['id'] = 'USN-' + usn_id

    def _generate_advisory(self, usn: USN) -> etree.Element:
        severities = ['low', 'medium', 'high', 'critical']
        advisory = etree.Element("advisory")
        severity = etree.SubElement(advisory, "severity")
        issued = etree.SubElement(advisory, "issued")
        severity = None
        for cve in usn.cves:
            cve_obj = self._generate_cve_tag(self.cves[cve])
            advisory.append(cve_obj)

            if not severity or severities.index(self.cves[cve].severity) > severities.index(severity):
                severity = self.cves[cve].severity

        severity.text = severity.capitalize()
        issued.text = usn.timestamp

        return advisory

    def _generate_metadata(self, usn: USN) -> etree.Element:
        metadata = etree.Element("metadata")
        title = etree.SubElement(metadata, "title")
        description = etree.SubElement(metadata, "description")
        affected = etree.SubElement(metadata, "affected", attrib = {"family": "unix"})
        platform = etree.SubElement(affected, "platform")

        reference = self._generate_reference(usn)
        metadata.append(reference)            
        advisory = self._generate_advisory(usn)
        metadata.append(reference)
        metadata.append(advisory)

        platform.text = self.release_name
        title.text = usn.title
        description.text = usn.description

        return metadata

    # Element generators
    def _generate_reference(self, usn: USN) -> etree.Element:
        reference = etree.Element("reference", attrib={
            "source": "USN",
            "ref_id": usn.id,
            "ref_url": f'https://ubuntu.com/security/notices/{usn.id}'
        })

        return reference

    def _populate_pkg(self, cve: CVE, package: Package, root_element, main_criteria, cache, fixed_versions) -> None:
        tests = root_element.find("tests")
        objects = root_element.find("objects")
        variables = root_element.find("variables")
        states = root_element.find("states")
        pkg_rel_entry = cve.pkg_rel_entries[str(package)]
        cache.setdefault(package.name, dict(bin_id=None, def_id=None))


        if pkg_rel_entry.status == 'vulnerable' and not self.fixed_only:
            if not package.name in cache or not cache[package.name]['def_id']:
                self._add_criterion(self.definition_id, pkg_rel_entry, cve, main_criteria)

                test, object, var = self._generate_vulnerable_elements(package, cache[package.name]['bin_id'])
                tests.append(test)

                if not cache[package.name]['bin_id']:
                    objects.append(object)
                    variables.append(var)
                    cache[package.name]['bin_id'] = self.definition_id

                cache[package.name]['def_id'] = self.definition_id
                self._increase_id(is_definition=False)
            else:
                self._add_criterion(cache[package.name]['def_id'], pkg_rel_entry, cve, main_criteria)
        elif pkg_rel_entry.status == 'fixed':
            if pkg_rel_entry.fixed_version in fixed_versions:
                self._add_criterion(fixed_versions[pkg_rel_entry.fixed_version], pkg_rel_entry, cve, main_criteria)
            else:
                self._add_criterion(self.definition_id, pkg_rel_entry, cve, main_criteria)

                test, object, var, state = self._generate_fixed_elements(package, pkg_rel_entry, cache[package.name]['bin_id'])
                tests.append(test)
                states.append(state)

                if not cache[package.name]['bin_id']:
                    objects.append(object)
                    variables.append(var)
                    cache[package.name]['bin_id'] = self.definition_id

                fixed_versions[pkg_rel_entry.fixed_version] = self.definition_id
                self._increase_id(is_definition=False)

    def _populate_kernel_pkg(self, cve: CVE, package: Package, root_element, main_criteria, running_kernel_id, cache, fixed_versions) -> None:
        if not package.name in cache:
            # Generate one-time elements
            kernel_criterion = self._generate_kernel_package_elements(package, root_element, running_kernel_id)
            cache[package.name] = kernel_criterion

        pkg_rel_entry = cve.pkg_rel_entries[str(package)]

        if pkg_rel_entry.status == 'fixed':
            criteria = self._generate_criteria_kernel('AND')
            self._add_to_criteria(criteria, cache[package.name], operator='AND', depth=0)

            kernel_version_criterion = self._add_kernel_elements(cve, package, pkg_rel_entry, root_element, running_kernel_id, fixed_versions)
            self._add_to_criteria(criteria, kernel_version_criterion, depth=0)
            self._add_to_criteria(main_criteria, criteria, depth=2, operator='OR')
            self._increase_id(is_definition=False)
        else:
            self._add_to_criteria(main_criteria, cache[package.name], depth=2, operator='OR')
        
        self._increase_id(is_definition=True)

    def generate_oval(self) -> None:
        self._reset()
        xml_tree, root_element = self._get_root_element()
        generator = self._get_generator("USN")
        root_element.append(generator)
        self._add_structure(root_element)

        if self.oval_format == 'dpkg':
            # One time kernel check
            self._add_release_checks(root_element)
            self._add_running_kernel_checks(root_element)
            running_kernel_id = self.definition_id
            self._increase_id(is_definition=True)

        definitions = root_element.find("definitions")
        pkg_cache = {}
        fixed_versions = {}

        for usn in self.usns:
            definition_element = self._generate_definition_object(self.usns[usn])
            instructions = ''

            for cve in self.cves:
                for pkg in self.cves[cve].pkgs:
                    pkg_rel_entry = self.cves[cve].pkg_rel_entries[str(pkg)]
                    if self.packages[pkg].is_kernel_pkg and self.oval_format != 'oci':
                        self._populate_kernel_pkg(self.cves[cve], pkg, root_element, definition_element, running_kernel_id, pkg_cache, fixed_versions)
                    else:
                        self._populate_pkg(self.cves[cve], pkg, root_element, definition_element, pkg_cache, fixed_versions)
                    
                    if pkg_rel_entry.status == 'fixed' and pkg.binaries:
                        product_description = cve_lib.get_subproject_description(pkg_rel_entry.release)
                        instructions = prepare_instructions(instructions, self.cves[cve].number, product_description, {'binaries': pkg.binaries, 'fix-version': pkg_rel_entry.fixed_version})
            
            metadata = definition_element.find('metadata')
            metadata.find('description').text = metadata.find('description').text + instructions
            definitions.append(definition_element)

        self._write_oval_xml(xml_tree, root_element)

class OvalGeneratorUSN():
    supported_oval_elements = ('definition', 'test', 'object', 'state',
                               'variable')
    cve_base_url = 'https://ubuntu.com/security/{}'
    mitre_base_url = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name={}'
    usn_base_url = 'https://ubuntu.com/security/notices/{}'
    lookup_cve_path = ['./active', './retired']
    generator_version = '1'
    oval_schema_version = '5.11.1'
    priorities = {'negligible': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

    def __init__(self, release, release_name, outdir='./', cve_dir=None, prefix='', oval_format='dpkg'):
        self.release = release
        self.release_codename = cve_lib.release_progenitor(release) if cve_lib.release_progenitor(release) else self.release.replace('/', '_')
        self.release_name = release_name
        self.pocket = "security"
        self.product_description = None
        self.current_oval = None
        self.tmpdir = tempfile.mkdtemp(prefix='oval_lib-')
        self.output_dir = outdir
        self.prefix = prefix
        self.oval_format = oval_format
        self.output_filepath = \
            '{0}com.ubuntu.{1}.usn.oval.xml'.format(prefix, self.release_codename)
        self.ns = 'oval:com.ubuntu.{0}'.format(self.release_codename)
        self.id = 100
        self.release_applicability_definition_id = '{0}:def:{1}'.format(self.ns, self.id)
        self.oval_structure = None
        self.load_oval_file_structures()
        self.create_release_oval_info()

    def load_oval_file_structures(self):
        _file = '{}.oval.usn'.format(self.release_codename)
        mode = 'w'

        self.oval_structure = {
            key: _open(os.path.join(self.tmpdir, '{}.{}.xml'.format(_file, key)),
                                   mode=mode, encoding='utf-8')  for key in
                    ['definition', 'test', 'object', 'state', 'variable']
        }

    # loads the release info either from oval_db or creating it
    def load_oval_release_struct(self):
        elements = {
            'definition': self.create_release_definition(),
            'test': self.create_release_test(),
            'object': self.create_release_object(),
            'state': self.create_release_state()
            }
        return elements

    # creates from scratch or just load from the oval_db
    def create_release_oval_info(self):
        oval_rel_struct = self.load_oval_release_struct()

        self.oval_structure['definition'].write(oval_rel_struct['definition'])
        self.oval_structure['test'].write(oval_rel_struct['test'])
        self.oval_structure['object'].write(oval_rel_struct['object'])
        self.oval_structure['state'].write(oval_rel_struct['state'])

    # TODO: xml lib
    def create_release_definition(self):
        if self.oval_format == 'dpkg':
            definition =\
        f"""
        <definition class="inventory" id="{self.ns}:def:{self.id}" version="1">
            <metadata>
                <title>Check that {self.release_name} ({self.release_codename}) is installed.</title>
                <description></description>
            </metadata>
            <criteria>
                <criterion test_ref="{self.ns}:tst:{self.id}" comment="The host is part of the unix family." />
                <criterion test_ref="{self.ns}:tst:{self.id+1}" comment="The host is running {self.release_name} ({self.release_codename})." />
            </criteria>
        </definition>"""
        else:
            definition = ""

        return definition

    # TODO: xml lib
    def create_release_test(self):
        if self.oval_format == 'dpkg':
            test =\
        f"""
        <ind:family_test id="{self.ns}:tst:{self.id}" check="at least one" check_existence="at_least_one_exists" version="1" comment="Is the host part of the unix family?">
            <ind:object object_ref="{self.ns}:obj:{self.id}"/>
            <ind:state state_ref="{self.ns}:ste:{self.id}"/>
        </ind:family_test>
        <ind:textfilecontent54_test check="at least one" check_existence="at_least_one_exists" id="{self.ns}:tst:{self.id+1}" version="1" comment="Is the host running Ubuntu {self.release_codename}?">
            <ind:object object_ref="{self.ns}:obj:{self.id+1}" />
            <ind:state state_ref="{self.ns}:ste:{self.id+1}" />
        </ind:textfilecontent54_test>"""
        else:
            test = ""

        return test

    # TODO: xml lib
    def create_release_object(self):
        if self.oval_format == 'dpkg':
            _object =\
        f"""
        <ind:family_object id="{self.ns}:obj:{self.id}" version="1" comment="The singleton family object."/>
        <ind:textfilecontent54_object id="{self.ns}:obj:{self.id+1}" version="1">
            <ind:filepath datatype="string">/etc/lsb-release</ind:filepath>
                <ind:pattern operation="pattern match">^[\s\S]*DISTRIB_CODENAME=([a-z]+)$</ind:pattern>
            <ind:instance datatype="int">1</ind:instance>
        </ind:textfilecontent54_object>"""
        else:
            _object = ""

        return _object

    # TODO: xml lib
    def create_release_state(self):
        if self.oval_format == 'dpkg':
            state =\
        f"""
        <ind:family_state id="{self.ns}:ste:{self.id}" version="1" comment="The singleton family object.">
            <ind:family>unix</ind:family>
        </ind:family_state>
        <ind:textfilecontent54_state id="{self.ns}:ste:{self.id+1}" version="1" comment="{self.release_name}">
            <ind:subexpression datatype="string" operation="equals">{self.release_codename}</ind:subexpression>
        </ind:textfilecontent54_state>"""
        else:
            state = ""

        return state

    def create_bug_references(self, urls):
        bug_urls = []
        alien_urls = []
        bugs = ""

        for url in urls:
            is_bug = re.match("https?:\/\/(bugs\.)?launchpad\.net\/(.*\/\+bug|bugs)\/\d+", url)

            if is_bug:
                bug_urls.append(url)
            else:
                alien_urls.append(url)

        for bug in bug_urls:
            bugs += \
                """
                <bug>{}</bug>
                """.format(bug)

        for alien in alien_urls:
            bugs += \
                """<ref>{}</ref>
                """.format(alien)

        return bugs.strip()

    def generate_cve_ref(self, cve):
        return '<reference source="CVE" ref_id="{0}" ref_url="{1}"/>'.format(cve['Candidate'], cve['CVE_URL'])

    def create_cves_elements(self, cves):
        cve_tags = ""
        cve_references = ""
        for cve in cves:
            cve_references += \
                """{0}
                """.format(self.generate_cve_ref(cve))

            cve_tags += \
                """{0}
                    """.format(generate_cve_tag(cve))
        return cve_references.strip(), cve_tags.strip()

    def get_usn_severity(self, cves):
        if not cves:
            return "None"

        max_severity = max(cves)
        if max_severity == 1 and cves.count(1) >= 5:
            return 'Medium'

        usn_severity = [key for key in self.priorities.items()
                            if key[1] == max_severity][0][0]
        return usn_severity.capitalize()

    # TODO: xml lib
    def create_usn_definition(self, usn_object, usn_number, id_base, test_refs, cve_dir, instructions):
        urls, cves_info = self.format_cves_info(usn_object['cves'], cve_dir)
        cve_references, cve_tags = self.create_cves_elements(cves_info)
        bug_references = self.create_bug_references(urls)

        for cve in cves_info:
            if cve['Priority'] not in self.priorities:
                sys.stderr.write('\rERROR: {} in USN {} has a priority of {}, please assign a valid priority to the CVE. Defaulting to medium.\n'.format(cve['Candidate'],
                        usn_number, cve['Priority']))
                # Throw an error if the CVE's priority is not valid but assign
                # the CVE a priority of medium so it has a valid priority in
                # the oval file output
                cve['Priority'] = 'medium'

        usn_severity = self.get_usn_severity([self.priorities[cve['Priority']]
                                                        for cve in cves_info])
        mapping = {
            'id': id_base,
            'usn_id': usn_object['id'],
            'ns': self.ns,
            'title': "{} -- {}".format(usn_object['id'], usn_object['title']),
            'codename': escape(self.release_codename),
            'release_name': escape(self.release_name),
            'applicability_def_id': escape(
                self.release_applicability_definition_id),
            'usn_url': self.usn_base_url.format(usn_object['id']),
            'description': escape(' '.join((usn_object['description'].strip() + instructions).split('\n'))),
            'cves_references': cve_references,
            'cve_tags': cve_tags,
            'bug_references': bug_references,
            'severity': usn_severity,
            'usn_timestamp': datetime.fromtimestamp(usn_object['timestamp'], tz=timezone.utc).strftime('%Y-%m-%d'),
            'criteria': '',
        }

        if self.oval_format == 'dpkg':
            mapping['os_release_check'] = """<extend_definition definition_ref="{applicability_def_id}" comment="{release_name} ({codename}) is installed." applicability_check="true" />""".format(**mapping)
        else:
            mapping['os_release_check'] = ""

        # convert number versions of binary pkgs into test criteria
        criteria = []
        kernel = False
        criteria.append('<criteria operator="OR">')
        for test_ref in test_refs:
            if self.pocket == 'livepatch' and self.oval_format == 'dpkg':
                criteria.append('    <criteria operator="AND">')
                criteria.append('        <criterion test_ref="{0}:tst:{1}" comment="{2}" />'.format(self.ns, str(int(test_ref['testref_id']) + 1), self.product_description))
                criteria.append('        <criterion test_ref="{0}:tst:{1}" comment="{2}" />'.format(self.ns, test_ref['testref_id'], self.product_description))
                criteria.append('    </criteria>')
            elif 'kernel' in test_ref and self.oval_format == 'dpkg':
                kernel = True
                criteria.append('    <criteria operator="AND">')
                criteria.append('        <criterion test_ref="{0}:tst:{1}" comment="{2}" />'.format(self.ns, test_ref['testref_id'], self.product_description))
            elif kernel:
                kernel = False
                criteria.append('        <criterion test_ref="{0}:tst:{1}" comment="{2}" />'.format(self.ns, test_ref['testref_id'], self.product_description))
                criteria.append('    </criteria>')
            else:
                criteria.append('    <criterion test_ref="{0}:tst:{1}" comment="{2}" />'.format(self.ns, test_ref['testref_id'], self.product_description))
        criteria.append('</criteria>')

        mapping['criteria'] = '\n                '.join(criteria)

        definition = \
        """
        <definition id="{ns}:def:{id}" version="1" class="patch">
            <metadata>
                <title>{title}</title>
                <affected family="unix">
                    <platform>{release_name}</platform>
                </affected>
                <reference source="USN" ref_id="{usn_id}" ref_url="{usn_url}"/>
                {cves_references}
                <description>{description}</description>
                <advisory from="security@ubuntu.com">
                    <severity>{severity}</severity>
                    <issued date="{usn_timestamp}"/>
                    {cve_tags}
                    {bug_references}
                </advisory>
            </metadata>
            <criteria>
                {os_release_check}
                {criteria}
            </criteria>
        </definition>""".format(**mapping)

        return definition

    # TODO: xml lib
    def create_usn_test(self, test_ref):
        mapping = {
            'id': test_ref['testref_id'],
            'ns': self.ns,
            'product': self.product_description,
            'name': test_ref['kernel'] if 'kernel' in test_ref else None
        }

        if self.oval_format == 'dpkg':
            if 'kernel' in test_ref:
                test =  \
        """
        <unix:uname_test check="at least one" comment="Is kernel {name} currently running?" id="{ns}:tst:{id}" version="1">
            <unix:object object_ref="{ns}:obj:{id}"/>
            <unix:state state_ref="{ns}:ste:{id}"/>
        </unix:uname_test>""".format(**mapping)

            elif 'kernelobj' in test_ref:
                test =  \
        """
        <ind:variable_test id="{ns}:tst:{id}" version="1" check="all" check_existence="all_exist" comment="kernel version comparison">
            <ind:object object_ref="{ns}:obj:{id}"/>
            <ind:state state_ref="{ns}:ste:{id}"/>
        </ind:variable_test>""".format(**mapping)

            elif self.pocket == 'livepatch':
                mapping['liv-id'] = str(int(test_ref['testref_id']) + 1)
                test = \
        """
        <unix:file_test id="{ns}:tst:{liv-id}" version="1" check="all" check_existence="all_exist" comment="canonical-livepatch installed">
            <unix:object object_ref="{ns}:obj:{liv-id}" />
            <unix:state state_ref="{ns}:ste:{liv-id}" />
        </unix:file_test>
        <ind:textfilecontent54_test id="{ns}:tst:{id}" version="1" check="all" check_existence="all_exist" comment="livepatch testing">
            <ind:object object_ref="{ns}:obj:{id}"/>
            <ind:state state_ref="{ns}:ste:{id}"/>
        </ind:textfilecontent54_test>""".format(**mapping)

            else:
                test = \
        """
        <linux:dpkginfo_test id="{ns}:tst:{id}" version="1" check_existence="at_least_one_exists" check="at least one" comment="{product}">
            <linux:object object_ref="{ns}:obj:{id}"/>
            <linux:state state_ref="{ns}:ste:{id}"/>
        </linux:dpkginfo_test>""".format(**mapping)
        else:
            test = \
        """
        <ind:textfilecontent54_test id="{ns}:tst:{id}" version="1" check_existence="at_least_one_exists" check="at least one" comment="{product}">
            <ind:object object_ref="{ns}:obj:{id}"/>
            <ind:state state_ref="{ns}:ste:{id}"/>
        </ind:textfilecontent54_test>""".format(**mapping)

        return test

    # TODO: xml lib
    def create_usn_object(self, test_ref):
        mapping = {
            'id': test_ref['testref_id'],
            'ns': self.ns,
            'product': self.product_description,
        }

        if self.oval_format == 'dpkg':
            if 'kernel' in test_ref:
                _object = \
        """
        <unix:uname_object id="{ns}:obj:{id}" version="1"/>""".format(**mapping)

            elif 'kernelobj' in test_ref:
                mapping['varid'] = test_ref['kernelobj']

                _object = \
        """
        <ind:variable_object id="{ns}:obj:{id}" version="1">
            <ind:var_ref>{ns}:var:{varid}</ind:var_ref>
        </ind:variable_object>""".format(**mapping)

            elif self.pocket == "livepatch":
                mapping['liv-id'] = str(int(test_ref['testref_id']) + 1)
                mapping['module'] = test_ref['pkgs']
                _object =  \
        """
        <unix:file_object id="{ns}:obj:{liv-id}" version="1" comment="{product}">
            <unix:filepath>/snap/bin/canonical-livepatch</unix:filepath>
        </unix:file_object>
        <ind:textfilecontent54_object id="{ns}:obj:{id}" version="1" comment="{product}">
            <ind:filepath datatype="string">/proc/modules</ind:filepath>
            <ind:pattern operation="pattern match" var_ref="{ns}:var:{id}" var_check="at least one" />
            <ind:instance datatype="int">1</ind:instance>
        </ind:textfilecontent54_object>""".format(**mapping)

            else:
                _object = \
        """
        <linux:dpkginfo_object id="{ns}:obj:{id}" version="1" comment="{product}">
            <linux:name var_ref="{ns}:var:{id}" var_check="at least one" />
        </linux:dpkginfo_object>""".format(**mapping)
        else:
            mapping['path'] = "."
            mapping['filename'] = "manifest"

            _object = \
        """
        <ind:textfilecontent54_object id="{ns}:obj:{id}" version="1" comment="{product}">
            <ind:path>{path}</ind:path>
            <ind:filename>manifest</ind:filename>
            <ind:pattern operation="pattern match" datatype="string" var_ref="{ns}:var:{id}" var_check="at least one" />
            <ind:instance operation="greater than or equal" datatype="int">1</ind:instance>
        </ind:textfilecontent54_object>""".format(**mapping)

        return _object

    # TODO: xml lib
    def create_usn_state(self, test_ref):
        mapping = {
            'id': test_ref['testref_id'],
            'ns': self.ns,
            'product': self.product_description,
            'regex': test_ref['kernel'] if 'kernel' in test_ref else None
        }

        binary_version = test_ref['version']

        if self.oval_format == 'dpkg':
            if 'kernel' in test_ref:
                state = \
        """
        <unix:uname_state id="{ns}:ste:{id}" version="1">
            <unix:os_release operation="pattern match">{regex}</unix:os_release>
        </unix:uname_state>""".format(**mapping)

            elif 'kernelobj' in test_ref:
                binary_version = test_ref['version']
                binary_version = re.search('([\d|\.]+-\d+)[\.|\d]+', binary_version)
                mapping['bversion'] = "0:" + binary_version.group(1)

                state = \
        """
        <ind:variable_state id="{ns}:ste:{id}" version="1">
            <ind:value datatype="debian_evr_string" operation="less than">{bversion}</ind:value>
        </ind:variable_state>""".format(**mapping)

            elif self.pocket == "livepatch":
                mapping['liv-id'] = str(int(test_ref['testref_id']) + 1)
                mapping['bversion'] = binary_version
                state = \
        """
        <unix:file_state id="{ns}:ste:{liv-id}" version="1">
            <unix:size datatype="int" operation="greater than">0</unix:size>
        </unix:file_state>
        <ind:textfilecontent54_state id="{ns}:ste:{id}" version="1">
            <ind:subexpression datatype="int" operation="less than">{bversion}</ind:subexpression>
        </ind:textfilecontent54_state>""".format(**mapping)

            else:
                if binary_version.find(':') != -1:
                    mapping['bversion'] = binary_version
                else:
                    mapping['bversion'] = "0:" + binary_version

                state = \
        """
        <linux:dpkginfo_state id="{ns}:ste:{id}" version="1" comment="{product}">
            <linux:evr datatype="debian_evr_string" operation="less than">{bversion}</linux:evr>
        </linux:dpkginfo_state>""".format(**mapping)

        else:
            mapping['bversion'] = binary_version

            state = \
        """
        <ind:textfilecontent54_state id="{ns}:ste:{id}" version="1" comment="{product}">
            <ind:subexpression datatype="debian_evr_string" operation="less than">{bversion}</ind:subexpression>
        </ind:textfilecontent54_state>""".format(**mapping)

        return state

    # TODO: xml lib
    def create_usn_variable(self, test_ref):
        binaries_list = test_ref['pkgs']

        mapping = {
            'id': test_ref['testref_id'],
            'ns': self.ns,
            'product': self.product_description,
        }

        values = ""
        if self.oval_format == 'dpkg':
            if 'kernel' in test_ref:
                variable = \
            """
        <local_variable id="{ns}:var:{id}" datatype="debian_evr_string" version="1" comment="kernel version in evr format">
            <concat>
                <literal_component>0:</literal_component>
                <regex_capture pattern="^([\d|\.]+-\d+)[-|\w]+$">
                    <object_component object_ref="{ns}:obj:{id}" item_field="os_release"  />
                </regex_capture>
            </concat>
        </local_variable>""".format(**mapping)
                return variable

            elif 'kernelobj' in test_ref:
                return

            else:
                for binary in binaries_list:
                    values += \
            """<value>{}</value>
            """.format(binary)
        else:
            for binary in binaries_list:
                values += \
            """<value>^{}(?::\w+|)\s+(.*)$</value>
            """.format(binary)

        mapping['values'] = values.strip()

        constant_variable = \
        """
        <constant_variable id="{ns}:var:{id}" version="1" datatype="string" comment="{product}">
            {values}
        </constant_variable>""".format(**mapping)

        return constant_variable

    def get_cve_info_from_file(self, cve, cve_dir):
        cve_active_file_path = os.path.join(cve_dir, 'active', cve)
        cve_retired_file_path = os.path.join(cve_dir, 'retired', cve)

        if os.path.exists(cve_active_file_path):
            cve_file_path = cve_active_file_path
        elif os.path.exists(cve_retired_file_path):
            cve_file_path = cve_retired_file_path
        else:
            return None

        cve_object = cve_lib.load_cve(cve_file_path)
        if not cve_object:
            return None

        public_date = cve_object['PublicDate']
        priority = cve_object['Priority'][0]
        references = cve_object['References']
        # TODO: deal with multiple CVSS?
        cve_info = {
                'Candidate': cve,
                'PublicDate': public_date,
                'Priority': priority,
                'CVSS': cve_object['CVSS'],
                'References': references.split('\n'),
                'CVE_URL': self.cve_base_url.format(cve),
                'MITRE_URL': self.mitre_base_url.format(cve)
                }

        return cve_info

    # FIXME: BUG: USN adds lp urls to 'cves': field, we need to filter it
    # and handle it separated till USN data be fixed
    def filter_cves(self, cves):
        _cves = cves[:]
        urls = []
        for cve in cves:
            # Takes urls from the list
            is_url = re.match('(www|http:|https:)+[^\s]+[\w]', cve)

            if is_url:
                urls.append(cve)
                _cves.remove(cve)

        return (urls, _cves)

    def format_cves_info(self, cves, cve_dir):
        urls, cves = self.filter_cves(cves)
        cves_info = []
        for cve in cves:
            # ignore empty CVE entries
            if len(cve) == 0:
                continue
            res = self.get_cve_info_from_file(cve, cve_dir)
            if res:
                cves_info.append(res)

        return urls, cves_info

    def get_version_from_binaries(self, usn_allbinaries):
        version_map = collections.defaultdict(list)
        for k, v in usn_allbinaries.items():
            if 'module' in v:
                self.pocket = 'livepatch'
                version_map[v['version']].append(v['module'])
            else:
                self.pocket = 'security'
                version_map[v['version']].append(k)

        return version_map

    def get_testref(self, version, pkgs, testref_id):
        if is_kernel_binaries(pkgs):
            uname_regex = process_kernel_binaries(pkgs, self.oval_format)
            if uname_regex:
                if self.oval_format == 'dpkg':
                    new_id = '{0}0'.format(testref_id)
                    new_id_2 = '{0}0'.format(testref_id + 1)
                    # kernel has two test_ref:
                    # 1. check if running kernel is of same version and flavour as patched
                    # 2. check if running kernel is less than patched kernel
                    return ({'version': version, 'pkgs': pkgs,
                             'testref_id': new_id, 'kernel': uname_regex},
                            {'version': version, 'pkgs': pkgs,
                             'testref_id': new_id_2, 'kernelobj': new_id})
                else:
                    new_id = '{0}0'.format(testref_id)
                    return({'version': version, 'pkgs': [uname_regex], 'testref_id': new_id}, None)

            return (None, None)

        new_id = '{0}0'.format(testref_id)
        return ({'version': version, 'pkgs': pkgs, 'testref_id': new_id}, None)

    def get_all_binaries_object(self, usn_object, usn_release):
        if 'allbinaries' in usn_release.keys():
            usn_allbinaries = usn_release['allbinaries']
        else:
            usn_allbinaries = usn_release['binaries']

        return usn_allbinaries

    def update_release_name_from_pocket_or_stamp(self, binaries, stamp):
        for b in binaries:
            try:
                self.pocket = binaries[b]['pocket']
                break
            except KeyError:
                # trusty usns don't have pocket, so try to check on timestamp
                if self.release_codename == 'trusty' and stamp >= cve_lib.release_stamp('esm/trusty'):
                    self.pocket = 'esm'
                else:
                    self.pocket = 'security'
                break

        if self.pocket in ['security', 'updates', 'livepatch']:
            self.release_name = cve_lib.release_name(self.release_codename)
            self.product_description = cve_lib.get_subproject_description(self.release_codename)
        else:
            # deal with trusty's weirdness
            if self.release_codename == 'trusty':
                self.release_name = cve_lib.release_name('esm/' + self.release_codename)
                self.product_description = cve_lib.get_subproject_description('esm/' + self.release_codename)
            else:
                self.release_name = cve_lib.release_name(self.pocket + '/' + self.release_codename)
                self.product_description = cve_lib.get_subproject_description(self.pocket + '/' + self.release_codename)

    def generate_usn_oval(self, usn_object, usn_number, cve_dir):
        if self.release_codename not in usn_object['releases'].keys():
            return

        usn_release = usn_object['releases'][self.release_codename]
        id_base = int(re.sub('[^0-9]','', usn_number)) * 1000000

        usn_allbinaries = self.get_all_binaries_object(usn_object, usn_release)

        self.update_release_name_from_pocket_or_stamp(usn_allbinaries, usn_object['timestamp'])

        binary_versions = self.get_version_from_binaries(usn_allbinaries)

        # OCI OVAL does not check running system, therefore it can
        # skip LSNs
        if self.oval_format == "oci" and self.pocket == 'livepatch':
            return

        # group binaries with same version (most likely from same source)
        # and create a test_ref for the group to be used when creating
        # the oval def, test, state and var.
        test_refs = []
        instructions = ""
        pkg = {}
        for key in sorted(list(binary_versions)):
            (test_ref, test_ref_2) = self.get_testref(key, binary_versions[key], id_base + len(test_refs))
            if test_ref:
                test_refs.append(test_ref)
                if test_ref_2:
                    test_refs.append(test_ref_2)

            # prepare update instructions
            pkg['binaries'] = binary_versions[key]
            pkg['fix-version'] = key
            instructions = prepare_instructions(instructions, usn_object['id'], self.product_description, pkg)

        # Create the oval objects
        # Only need one definition, but if multiple versions of binary pkgs,
        # then may need several test, object, state and var
        usn_def = self.create_usn_definition(usn_object, usn_number, id_base, test_refs, cve_dir, instructions)
        self.oval_structure['definition'].write(usn_def)

        for test_ref in test_refs:
            usn_variable = self.create_usn_variable(test_ref)
            usn_state = self.create_usn_state(test_ref)
            usn_obj = self.create_usn_object(test_ref)
            usn_test = self.create_usn_test(test_ref)

            self.oval_structure['test'].write(usn_test)
            self.oval_structure['object'].write(usn_obj)
            self.oval_structure['state'].write(usn_state)
            if usn_variable:
                self.oval_structure['variable'].write(usn_variable)

    # TODO: xml lib
    def write_oval_elements(self):
        """ write OVAL elements to .xml file w. OVAL header and footer """
        for key in self.oval_structure:
            self.oval_structure[key].close()
            self.oval_structure[key] = open(self.oval_structure[key].name, 'rt')

        tmp = os.path.join(self.tmpdir, self.output_filepath)
        with open(tmp, 'wt') as f:
            # add header
            oval_timestamp = datetime.now(tz=timezone.utc).strftime(
                '%Y-%m-%dT%H:%M:%S')
            copyright_year = datetime.now(tz=timezone.utc).year
            header = \
"""<oval_definitions
    xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
    xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
    xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
    xmlns:unix="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"
    xmlns:linux="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5#independent independent-definitions-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5#unix unix-definitions-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5#linux linux-definitions-schema.xsd">

    <generator>
        <oval:product_name>Canonical USN OVAL Generator</oval:product_name>
        <oval:product_version>{0}</oval:product_version>
        <oval:schema_version>{1}</oval:schema_version>
        <oval:timestamp>{2}</oval:timestamp>
        <terms_of_use>Copyright (C) {3} Canonical LTD. All rights reserved. This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License version 3 for more details. You should have received a copy of the GNU General Public License version 3 along with this program.  If not, see http://www.gnu.org/licenses/.</terms_of_use>
    </generator>\n""".format(self.generator_version, self.oval_schema_version, oval_timestamp, copyright_year)

            f.write(header)
            # add queued file content
            for element in self.supported_oval_elements:
                if element in self.oval_structure:
                    f.write("\n    <{0}s>\n".format(element))
                    f.write(self.oval_structure[element].read().rstrip())
                    f.write("\n    </{0}s>".format(element))

            # add footer
            footer = "\n</oval_definitions>"
            f.write(footer)

        # close and delete queue files
        for key in self.oval_structure:
            self.oval_structure[key].close()
            os.remove(self.oval_structure[key].name)

        # close self.output_filepath and move into place
        f.close()
        shutil.move(tmp, os.path.join(self.output_dir, self.output_filepath))

        # remove tmp dir if empty
        if not os.listdir(self.tmpdir):
            os.rmdir(self.tmpdir)
