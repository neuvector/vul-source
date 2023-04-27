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
import io
import os
import random
import re
import shutil
import sys
import tempfile
import collections
import glob
import xml.etree.cElementTree as etree
from xml.dom import minidom
from typing import Tuple # Needed because of Python < 3.9 and to also support < 3.7

from source_map import load
import cve_lib

from xml.sax.saxutils import escape

sources = {}
source_map_binaries = {}
debug_level = 0

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
        regex =  version + '\d+(' + flavours + ')'
        if oval_format == 'oci':
            regex = 'linux-image-(?:unsigned-)?' + regex
        return regex

    return None

def debug(message):
    """ print a debuging message """
    if debug_level > 0:
        sys.stdout.write('\rDEBUG: {0}\n'.format(message))

def generate_cve_tag(cve):
    cve_ref = '<cve href="https://ubuntu.com/security/{0}" severity="{1}" public="{2}"'.format(cve['Candidate'], cve['Priority'], cve['PublicDate'].split(' ')[0].replace('-', ''))

    if cve['CVSS']:
        cve_ref += ' cvss_score="{0}" cvss_vector="{1}"'.format(cve['CVSS'][0]['baseScore'], cve['CVSS'][0]['vector'])

    cve_ref_usns = False
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

class OvalGenerator:
    supported_oval_elements = ('definition', 'test', 'object', 'state', 'variable')
    generator_version = '1.1'
    oval_schema_version = '5.11.1'
    def __init__(self, release, release_name, parent = None, warn_method=False, outdir='./', prefix='', oval_format='dpkg') -> None:
        self.release = release
        # e.g. codename for trusty/esm should be trusty
        self.release_codename = parent if parent else self.release.replace('/', '_')
        self.release_name = release_name
        #self.warn = warn_method or self.warn
        self.tmpdir = tempfile.mkdtemp(prefix='oval_lib-')
        self.output_dir = outdir
        self.oval_format = oval_format
        self.output_filepath = \
            '{0}com.ubuntu.{1}.cve.oval.xml'.format(prefix, self.release.replace('/', '_'))
        self.ns = 'oval:com.ubuntu.{0}'.format(self.release_codename)
        self.id = 100
        self.host_def_id = self.id
        self.release_applicability_definition_id = '{0}:def:{1}0'.format(self.ns, self.id)

    def _add_structure(self, root) -> None:
        structure = {}
        for element in self.supported_oval_elements:
            structure_element = element + 's'
            etree.SubElement(root, structure_element)

        return structure

    def _get_root_element(self, type) -> etree.Element:
        oval_timestamp = datetime.now(tz=timezone.utc).strftime(
            '%Y-%m-%dT%H:%M:%S')

        root_element = etree.Element("oval_definitions", attrib= {
            "xmlns":"http://oval.mitre.org/XMLSchema/oval-definitions-5",
            "xmlns:ind-def":"http://oval.mitre.org/XMLSchema/oval-definitions-5#independent",
            "xmlns:oval":"http://oval.mitre.org/XMLSchema/oval-common-5",
            "xmlns:unix-def":"http://oval.mitre.org/XMLSchema/oval-definitions-5#unix",
            "xmlns:linux-def":"http://oval.mitre.org/XMLSchema/oval-definitions-5#linux",
            "xmlns:xsi":"http://www.w3.org/2001/XMLSchema-instance" ,
            "xsi:schemaLocation":"http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5#independent independent-definitions-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5#unix unix-definitions-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5#macos linux-definitions-schema.xsd"
        })

        generator = etree.SubElement(root_element, "generator")
        product_name = etree.SubElement(generator, "oval:product_name")
        product_version = etree.SubElement(generator, "oval:product_version")
        schema_version = etree.SubElement(generator, "oval:schema_version")
        timestamp = etree.SubElement(generator, "oval:timestamp")

        product_name.text = f"Canonical {type} OVAL Generator"
        product_version.text = self.generator_version
        schema_version.text = self.oval_schema_version
        timestamp.text = oval_timestamp

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

class CVEPkgRelEntry:
    def __init__(self, pkg, cve, status, note) -> None:
        self.pkg = pkg
        self.cve = cve
        self.orig_status = status
        self.orig_note = note
        cve_info = CVEPkgRelEntry.parse_package_status(pkg.rel, pkg.name, status, note, cve.number, None)

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

        if cache and code != 'dne':
            if fix_version and code in ['released', 'not-affected']:
                status['bin-pkgs'] = cache.get_binarypkgs(package, release, version=fix_version)
            else:
                status['bin-pkgs'] = cache.get_binarypkgs(package, release)

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

    def __str__(self) -> str:
        return f'{str(self.pkg)}:{self.status} {self.fixed_version}'

class CVE:
    def __init__(self, number, info, pkgs=[]) -> None:
        self.number = number
        self.description = info['Description']
        self.severity = info['Priority']
        self.public_date = info['PublicDate']
        self.cvss = info['CVSS']
        self.usns = []
        for url in info['References'].split('\n'):
            if 'https://ubuntu.com/security/notices/USN-' in url:
                self.usns.append(url[40:])
        self.pkg_rel_entries = {}
        self.pkgs = pkgs

    def add_pkg(self, pkg_object, state, note):
        cve_pkg_entry = CVEPkgRelEntry(pkg_object, self, state, note)
        self.pkg_rel_entries[Package.get_unique_id(pkg_object.name, pkg_object.rel)] = cve_pkg_entry
        self.pkgs.append(pkg_object)

    def __str__(self) -> str:
        return self.number

    def __repr__(self):
        return self.__str__()

class Package:
    def __init__(self, pkgname, rel, binaries, version):
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
        self.version = version
        self.binaries = binaries if binaries else []
        self.cves = []

    @staticmethod
    def get_unique_id(name, rel):
        return f'{name}/{rel}'

    def add_cve(self, cve) -> None:
        self.cves.append(cve)

    def __str__(self) -> str:
        return f"{self.name}/{self.rel}"

    def __repr__(self):
        return self.__str__()

class OvalGeneratorPkg(OvalGenerator):
    def __init__(self, release, release_name, cve_paths, packages, progress, pkg_cache, cve_cache=None,  cve_prefix_dir=None, parent=None, warn_method=False, outdir='./', prefix='', oval_format='dpkg') -> None:
        super().__init__(release, release_name, parent, warn_method, outdir, prefix, oval_format)
        ###
        # ID schema: 2204|00001|0001
        # * The first four digits are the ubuntu release number
        # * The next 5 digits is # just a package counter, we increase it for each definition
        # * The last 4 digits is a counter for the criterion
        ###
        release_code = int(release_name.split(' ')[1].replace('.', '')) if release not in cve_lib.external_releases else 1111
        self.definition_id = release_code * 10 ** 10
        self.definition_step = 1 * 10 ** 5
        self.criterion_step = 10
        self.progress = progress
        self.cve_cache = cve_cache
        self.pkg_cache = pkg_cache
        self.cve_paths = cve_paths
        self.packages = self._load_pkgs(cve_prefix_dir, packages)

    def _generate_advisory(self, package: Package) -> etree.Element:
        advisory = etree.Element("advisory")
        rights = etree.SubElement(advisory, "rights")
        component = etree.SubElement(advisory, "component")
        version = etree.SubElement(advisory, "current_version")

        for cve in package.cves:
            cve_obj = self._generate_cve_object(cve)
            advisory.append(cve_obj)

        rights.text = f"Copyright (C) {datetime.now().year} Canonical Ltd."
        component.text = package.section
        version.text = package.version

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

    def _generate_criteria(self) -> etree.Element:
        criteria = etree.Element("criteria")
        if self.oval_format == 'dpkg':
            extend_definition = etree.SubElement(criteria, "extend_definition")

            extend_definition.set("definition_ref", f"{self.ns}:def:{self.host_def_id}")
            extend_definition.set("comment", f"{self.release_name} is installed.")
            extend_definition.set("applicability_check", "true")

        return criteria

    # Element generators
    def _generate_reference(self, package) -> etree.Element:
        reference = etree.Element("reference", attrib={
            "source": "Package",
            "ref_id": package.name,
            "ref_url": f'https://launchpad.net/ubuntu/+source/{package.name}'
        })

        return reference

    def _generate_definition_object(self, package) -> None:
        id = f"{self.ns}:def:{self.definition_id}"
        definition = etree.Element("definition")
        definition.set("class", "vulnerability")
        definition.set("id", id)
        definition.set("version", "1")

        metadata = self._generate_metadata(package)
        criteria = self._generate_criteria()
        definition.append(metadata)
        definition.append(criteria)
        return definition

    def _generate_cve_object(self, cve: CVE) -> etree.Element:
        cve_tag = etree.Element("cve", 
            attrib={
                'href' : f"https://ubuntu.com/security/{cve.number}",
                'severity': cve.severity,
                'public': cve.public_date.split(' ')[0].replace('-', '')
            })
        
        cve_tag.text = cve.number
        if cve.cvss:
            cve_tag.set('cvss_score', cve.cvss[0]['baseScore'])
            cve_tag.set('cvss_vector', cve.cvss[0]['vector'])
            if cve.usns:
                cve_tag.set('usns', ','.join(cve.usns))

        return cve_tag
    def _generate_var_object(self, comment, id, binaries) -> etree.Element:
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

    def _generate_object_object(self, comment, id, var_id) -> etree.Element:
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

    def _generate_state_object(self, comment, id, version) -> None:
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

            version_check.text = f"0:{version}"
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

            version_check.text = f"0:{version}"
        else:
            ValueError(f"Format not {self.oval_format} not supported")

        return object

    def _generate_criterion_element(self, comment, id) -> etree.Element:
        criterion = etree.Element("criterion", attrib={
            "test_ref": f"{self.ns}:tst:{id}",
            "comment": comment
        })

        return criterion

    # Running kernel element generators
    def _add_running_kernel_checks(self, root_element):
        objects = root_element.find("objects")
        variables = root_element.find("variables")
        states = root_element.find("states")

        variable_local_kernel_check = self._generate_local_variable_kernel(self.definition_id, "Kernel version in evr format", self.definition_id)
        obj_running_kernel = self._generate_uname_object_element(self.definition_id)
        state_kernel_version = self._generate_state_kernel_element("Kernel check", self.definition_id, self.definition_id)

        objects.append(obj_running_kernel)
        variables.append(variable_local_kernel_check)
        states.append(state_kernel_version)

    def _generate_local_variable_kernel(self, id, comment, uname_obj_id):
        var = etree.Element("local_variable",
            attrib={
                'id' : f"{self.ns}:var:{id}",
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

    def _generate_variable_kernel_version(self, comment, id, version):
        var = etree.Element("constant_variable",
            attrib={
                'id' : f"{self.ns}:var:{id}",
                'version': "1",
                "datatype": "debian_evr_string",
                "comment": comment
            })

        item = etree.SubElement(var, "value")
        item.text = f"0:{version.rsplit('.', 1)[0]}"

        return var

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

    def _generate_state_kernel_element(self, comment, id, var_id) -> None:
        state = etree.Element("ind-def:variable_state",
            attrib={
                'id' : f"{self.ns}:ste:{id}",
                'version': "1",
                "comment": comment
            })

        etree.SubElement(state, "ind-def:value", attrib={
            "datatype": "debian_evr_string",
            "operation": "greater than",
            "var_check": "at least one",
            "var_ref": f"{self.ns}:var:{var_id}"
        })

        return state

    def _generate_kernel_package_elements(self, package: Package, root_element, running_kernel_check_id) -> etree.Element:
        tests = root_element.find("tests")
        states = root_element.find("states")

        comment_running_kernel = f'Is kernel {package.name} running?'
        regex = process_kernel_binaries(package.binaries, self.oval_format)

        criterion_running_kernel = self._generate_criterion_element(comment_running_kernel, self.definition_id)
        test_running_kernel = self._generate_test_element_running_kernel(self.definition_id, comment_running_kernel, running_kernel_check_id)
        state_running_kernel = self._generate_uname_state_element(self.definition_id, regex, f"Regex match for kernel {package.name}")

        self.definition_id += self.criterion_step

        tests.append(test_running_kernel)
        states.append(state_running_kernel)

        return criterion_running_kernel

    def _add_fixed_kernel_elements(self, cve: CVE, package: Package, package_rel_entry:CVEPkgRelEntry, root_element, running_kernel_id) -> etree.Element:
        tests = root_element.find("tests")
        objects = root_element.find("objects")
        variables = root_element.find("variables")

        comment_version = f'Kernel {package.name} version comparison ({package_rel_entry.fixed_version})'
        comment_criterion = f'({cve.number}) {package.name} {package_rel_entry.note}'
        criterion_version = self._generate_criterion_element(comment_criterion, self.definition_id)
        test_kernel_version = self._generate_test_element(comment_version, self.definition_id, True, 'kernel', state_id=running_kernel_id)

        obj_kernel_version = self._generate_kernel_version_object_element(self.definition_id, self.definition_id)
        var_version_kernel = self._generate_variable_kernel_version(comment_version, self.definition_id, package_rel_entry.fixed_version)

        tests.append(test_kernel_version)
        objects.append(obj_kernel_version)
        variables.append(var_version_kernel)

        return criterion_version

    # General functions
    def _increase_id(self, is_definition):
        if is_definition:
            self.definition_id += self.definition_step
            clean_value = self.definition_step / 10
            self.definition_id = int(int(self.definition_id / clean_value) * clean_value)
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
        criterion_note = f'({cve.number}) {package_entry.pkg.name}{package_entry.note}'
        criterion = self._generate_criterion_element(criterion_note, id)
        self._add_to_criteria(definition, criterion, depth)

    def _generate_vulnerable_elements(self, package, obj_id=None):
        binary_keyword = 'binaries' if len(package.binaries) > 1 else 'binary'
        test_note = f"Does the '{package.name}' package exist?"
        object_note = f"The '{package.name}' package {binary_keyword}"

        test = self._generate_test_element(test_note, self.definition_id, False, 'pkg', obj_id=obj_id)

        if not obj_id:
            object = self._generate_object_object(object_note, self.definition_id, self.definition_id)

            binaries = package.binaries
            if self.oval_format == 'oci':
                if is_kernel_binaries(package.binaries):
                    regex = process_kernel_binaries(package.binaries, 'oci')
                    binaries = [f'^{regex}(?::\w+|)\s+(.*)$\s+(.*)']
                else:
                    variable_values = '(?::\w+|)\s+(.*)$\s+(.*)'

                    binaries = []
                    for binary in package.binaries:
                        binaries.append(f'^{binary}{variable_values}')
            var = self._generate_var_object(object_note, self.definition_id, binaries)
        else:
            object = None
            var = None
        return test, object, var

    def _generate_fixed_elements(self, package, pkg_rel_entry, obj_id=None):
        binary_keyword = 'binaries' if len(package.binaries) > 1 else 'binary'
        test_note = f"Does the '{package.name}' package exist and is the version less than '{pkg_rel_entry.fixed_version}'?"
        object_note = f"The '{package.name}' package {binary_keyword}"
        state_note = f"The package version is less than '{pkg_rel_entry.fixed_version}'"

        test = self._generate_test_element(test_note, self.definition_id, True, 'pkg', obj_id=obj_id)
        if not obj_id:
            object = self._generate_object_object(object_note, self.definition_id, self.definition_id)

            binaries = package.binaries
            if self.oval_format == 'oci':
                if is_kernel_binaries(package.binaries):
                    regex = process_kernel_binaries(package.binaries, 'oci')
                    binaries = [f'^{regex}(?::\w+|)\s+(.*)$\s+(.*)']
                else:
                    variable_values = '(?::\w+|)\s+(.*)$\s+(.*)'

                    binaries = []
                    for binary in package.binaries:
                        binaries.append(f'^{binary}{variable_values}')

            var = self._generate_var_object(object_note, self.definition_id, binaries)
        else:
            object = None
            var = None
        state = self._generate_state_object(state_note, self.definition_id, pkg_rel_entry.fixed_version)

        return test, object, var, state

    def _populate_pkg(self, package, root_element):
        pkg_id = Package.get_unique_id(package.name, self.release)
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
        binaries_id = None
        cve_added = False

        for cve in package.cves:
            pkg_rel_entry = cve.pkg_rel_entries[pkg_id]
            if pkg_rel_entry.status == 'vulnerable':
                cve_added = True
                if one_time_added_id:
                    self._add_criterion(one_time_added_id, pkg_rel_entry, cve, definition_element)
                else:
                    self._add_criterion(self.definition_id, pkg_rel_entry, cve, definition_element)

                    test, object, var = self._generate_vulnerable_elements(package, binaries_id)
                    tests.append(test)

                    if not binaries_id:
                        objects.append(object)
                        variables.append(var)
                        binaries_id = self.definition_id

                    one_time_added_id = self.definition_id
                    self._increase_id(is_definition=False)
            elif pkg_rel_entry.status == 'fixed':
                cve_added = True

                if pkg_rel_entry.fixed_version in fixed_versions:
                    self._add_criterion(fixed_versions[pkg_rel_entry.fixed_version], pkg_rel_entry, cve, definition_element)
                else:
                    self._add_criterion(self.definition_id, pkg_rel_entry, cve, definition_element)

                    test, object, var, state = self._generate_fixed_elements(package, pkg_rel_entry, binaries_id)
                    tests.append(test)
                    states.append(state)

                    if not binaries_id:
                        objects.append(object)
                        variables.append(var)
                        binaries_id = self.definition_id

                    fixed_versions[pkg_rel_entry.fixed_version] = self.definition_id
                    self._increase_id(is_definition=False)

        if cve_added:
            definitions.append(definition_element)

        self._increase_id(is_definition=True)

    def _populate_kernel_pkg(self, package, root_element, running_kernel_id):
        pkg_id = Package.get_unique_id(package.name, self.release)
        tests = root_element.find("tests")
        objects = root_element.find("objects")
        variables = root_element.find("variables")

        # Add package definition
        definitions = root_element.find("definitions")
        definition_element = self._generate_definition_object(package)

        # Control/cache variables
        one_time_added_id = None
        fixed_versions = []
        binaries_id = None
        cve_added = False

        # Generate one-time elements
        kernel_criterion = self._generate_kernel_package_elements(package, root_element, running_kernel_id)
        criteria = self._generate_criteria_kernel('OR')

        self._add_to_criteria(definition_element, kernel_criterion, operator='AND')
        self._add_to_criteria(definition_element, criteria, operator='AND')

        for cve in package.cves:
            pkg_rel_entry = cve.pkg_rel_entries[pkg_id]
            if pkg_rel_entry.status == 'vulnerable':
                cve_added = True
                if one_time_added_id:
                    self._add_criterion(one_time_added_id, pkg_rel_entry, cve, definition_element, depth=3)
                else:
                    self._add_criterion(self.definition_id, pkg_rel_entry, cve, definition_element, depth=3)

                    test, object, var = self._generate_vulnerable_elements(package, binaries_id)
                    tests.append(test)
                    objects.append(object)

                    if not binaries_id:
                        variables.append(var)
                        binaries_id = self.definition_id

                    one_time_added_id = self.definition_id
                    self._increase_id(is_definition=False)
            elif pkg_rel_entry.status == 'fixed':
                cve_added = True

                if not pkg_rel_entry.fixed_version in fixed_versions:
                    kernel_version_criterion = self._add_fixed_kernel_elements(cve, package, pkg_rel_entry, root_element, running_kernel_id)
                    self._add_to_criteria(definition_element, kernel_version_criterion, depth=3)
                    fixed_versions.append(pkg_rel_entry.fixed_version)
                    self._increase_id(is_definition=False)

        if cve_added:
            definitions.append(definition_element)
        self._increase_id(is_definition=True)

    def _load_pkgs(self, cve_prefix_dir, packages_filter=None) -> None:
        cve_lib.load_external_subprojects()

        cves = []
        for pathname in self.cve_paths:
            cves = cves + glob.glob(os.path.join(cve_prefix_dir, pathname))
        cves.sort()

        packages = {}
        sources[self.release] = load(releases=[self.release], skip_eol_releases=False)[self.release]
        orig_name = cve_lib.get_orig_rel_name(self.release)
        if '/' in orig_name:
            orig_name = orig_name.split('/', maxsplit=1)[1]
        source_map_binaries[self.release] = load(data_type='packages',releases=[orig_name], skip_eol_releases=False)[orig_name] \
            if self.release not in cve_lib.external_releases else {}

        i = 0
        for cve_path in cves:
            cve_number = cve_path.rsplit('/', 1)[1]
            i += 1

            if self.progress:
                print(f'[{i:5}/{len(cves)}] Processing {cve_number:18}', end='\r')

            if not cve_number in self.cve_cache:
                self.cve_cache[cve_number] = cve_lib.load_cve(cve_path)

            info = self.cve_cache[cve_number]
            cve_obj = CVE(cve_number, info)

            for pkg in info['pkgs']:
                if packages_filter and pkg not in packages_filter:
                    continue

                if self.release in info['pkgs'][pkg] and \
                    info['pkgs'][pkg][self.release][0] != 'DNE' and \
                    pkg in sources[self.release]:
                        pkg_id = Package.get_unique_id(pkg, self.release)
                        if pkg_id not in packages:
                            binaries = self.pkg_cache.get_binarypkgs(pkg, self.release)
                            version = ''
                            if binaries:
                                version = self.pkg_cache.pkgcache[pkg]['Releases'][self.release]['source_version']
                            pkg_obj = Package(pkg, self.release, binaries, version)
                            packages[pkg_id] = pkg_obj

                        pkg_obj = packages[pkg_id]
                        pkg_obj.cves.append(cve_obj)
                        # add_pkg (pkg, status, note)
                        cve_obj.add_pkg(pkg_obj, info['pkgs'][pkg][self.release][0],info['pkgs'][pkg][self.release][1])

        packages = dict(sorted(packages.items()))
        print(' ' * 40, end='\r')
        return packages

    def generate_oval(self) -> None:
        xml_tree, root_element = self._get_root_element("Package")
        self._add_structure(root_element)

        if self.oval_format == 'dpkg':
            # One time kernel check
            self._add_release_checks(root_element)
            self._add_running_kernel_checks(root_element)
            running_kernel_id = self.definition_id
            self._increase_id(is_definition=True)

        for pkg in self.packages:
            if len(self.packages[pkg].binaries) == 0:
                continue

            if is_kernel_binaries(self.packages[pkg].binaries) and self.oval_format != 'oci':
                self._populate_kernel_pkg(self.packages[pkg], root_element, running_kernel_id)
            else:
                self._populate_pkg(self.packages[pkg], root_element)

        #etree.indent(xml_tree, level=0) -> only available from Python 3.9
        filename = f"com.ubuntu.{self.release_codename}.pkg.oval.xml"
        xmlstr = minidom.parseString(etree.tostring(root_element)).toprettyxml(indent="  ")
        if self.oval_format == 'oci':
            filename = f'oci.{filename}'

        with open(os.path.join(self.output_dir, filename), 'w') as file:
            file.write(xmlstr)
        #xml_tree.write(os.path.join(self.output_dir, filename))
        return

class OvalGeneratorCVE:
    supported_oval_elements = ('definition', 'test', 'object', 'state',
                               'variable')
    generator_version = '1.1'
    oval_schema_version = '5.11.1'

    def __init__(self, release, release_name, parent, warn_method=False, outdir='./', prefix='', oval_format='dpkg'):
        """ constructor, set defaults for instances """

        self.release = release
        # e.g. codename for trusty/esm should be trusty
        self.release_codename = parent if parent else self.release.replace('/', '_')
        self.release_name = release_name
        self.warn = warn_method or self.warn
        self.tmpdir = tempfile.mkdtemp(prefix='oval_lib-')
        self.output_dir = outdir
        self.oval_format = oval_format
        self.output_filepath = \
            '{0}com.ubuntu.{1}.cve.oval.xml'.format(prefix, self.release.replace('/', '_'))
        self.ns = 'oval:com.ubuntu.{0}'.format(self.release_codename)
        self.id = 10
        self.release_applicability_definition_id = '{0}:def:{1}0'.format(self.ns, self.id)

    def __del__(self):
        """ deconstructor, clean up """
        if os.path.exists(self.tmpdir):
            recursive_rm(self.tmpdir)

    def generate_cve_definition(self, cve):
        """ generate an OVAL definition based on parsed CVE data """

        header = cve['header']
        # if the multiplier is not large enough, the tests IDs will
        # overlap on things with large numbers of binary packages.
        # if we ever have an issue that touches more than 1,000,000
        # binary packages, that will cause a problem.
        id_base = int(re.sub('[^0-9]', '', header['Candidate'])) * 1000000
        if not self.unique_id_base(id_base, header['Source-note']):
            self.warn('Calculated id_base "{0}" based on candidate value "{1}" is not unique. Skipping CVE.'.format(id_base, header['Candidate']))

        instruction = ""
        # make test(s) for each package
        test_refs = []
        packages = cve['packages']
        for package in sorted(packages.keys()):
            releases = packages[package]['Releases']
            for release in sorted(releases.keys()):
                if release == self.release:
                    release_status = releases[release]
                    if 'bin-pkgs' in release_status and release_status['bin-pkgs']:
                        pkg = {
                            'name': package,
                            'binaries': release_status['bin-pkgs'],
                            'status': release_status['status'],
                            'note': release_status['note'],
                            'fix-version': release_status['fix-version'] if 'fix-version' in release_status else '',
                            'id_base': id_base + len(test_refs),
                            'source-note': header['Source-note']
                        }
                        if is_kernel_binaries(pkg['binaries']) and pkg['fix-version']:
                            test_ref = self.get_running_kernel_testref(pkg)
                            if test_ref:
                                test_refs = test_refs + test_ref
                                pkg['id_base'] = id_base + 1
                        else:
                            test_ref = self.get_oval_test_for_package(pkg)
                            if test_ref:
                                test_refs.append(test_ref)
                        # prepare update instructions if package is fixed
                        if pkg['status'] == 'fixed':
                            if 'parent' in release_status:
                                product_description = cve_lib.get_subproject_description(release_status['parent'])
                            else:
                                product_description = cve_lib.get_subproject_description(release)
                            instruction = prepare_instructions(instruction, header['Candidate'], product_description, pkg)

        # if no packages for this release, then we're done
        if not len(test_refs):
            return False

        # convert CVE data to OVAL definition metadata
        mapping = {
            'ns': escape(self.ns),
            'id_base': id_base,
            'codename': escape(self.release_codename),
            'release_name': escape(self.release_name),
            'applicability_def_id': escape(
                self.release_applicability_definition_id),
            'cve_title': escape(header['Candidate']),
            'description': escape('{0} {1}'.format(header['Description'],
                                  header['Ubuntu-Description']).strip() + instruction),
            'priority': escape(header['Priority']),
            'criteria': '',
            'references': '',
            'notes': ''
        }

        # convert test_refs to criteria
        if len(test_refs) == 1:
            negation_attribute = 'negate = "true" ' \
                if 'negate' in test_refs[0] and test_refs[0]['negate'] else ''
            mapping['criteria'] = \
                '<criterion test_ref="{0}" comment="{1}" {2}/>'.format(
                    test_refs[0]['id'], escape(test_refs[0]['comment']), negation_attribute)
        else:
            criteria = []
            criteria.append('<criteria operator="OR">')
            for test_ref in test_refs:
                if 'kernel' in test_ref:
                    criteria.append('    <criteria operator="AND">')
                    negation_attribute = 'negate = "true" ' \
                        if 'negate' in test_ref and test_ref['negate'] else ''
                    criteria.append(
                        '        <criterion test_ref="{0}" comment="{1}" {2}/>'.format(
                            test_ref['id'],
                            escape(test_ref['comment']), negation_attribute))
                elif 'kernelobj' in test_ref:
                    criteria.append(
                        '        <criterion test_ref="{0}" comment="{1}" {2}/>'.format(
                            test_ref['id'],
                            escape(test_ref['comment']), negation_attribute))
                    criteria.append('  </criteria>')
                else:
                    negation_attribute = 'negate = "true" ' \
                        if 'negate' in test_ref and test_ref['negate'] else ''
                    criteria.append(
                        '    <criterion test_ref="{0}" comment="{1}" {2}/>'.format(
                            test_ref['id'],
                            escape(test_ref['comment']), negation_attribute))
            criteria.append('</criteria>')
            mapping['criteria'] = '\n                    '.join(criteria)

        # convert notes
        if header['Notes']:
            mapping['notes'] = '\n                <oval:notes>' + \
                               '\n                    <oval:note>{0}</oval:note>'.format(escape(header['Notes'])) + \
                               '\n                </oval:notes>'

        # convert additional data <advisory> metadata elements
        advisory = []
        advisory.append('<severity>{0}</severity>'.format(
            escape(header['Priority'].title())))
        advisory.append(
            '<rights>Copyright (C) {0}Canonical Ltd.</rights>'.format(escape(
                header['PublicDate'].split('-', 1)[0] + ' '
                if header['PublicDate'] else '')))
        if header['PublicDate']:
            advisory.append('<public_date>{0}</public_date>'.format(
                escape(header['PublicDate'])))
        if header['PublicDateAtUSN']:
            advisory.append(
                '<public_date_at_usn>{0}</public_date_at_usn>'.format(escape(
                    header['PublicDateAtUSN'])))
        if header['Assigned-to']:
            advisory.append('<assigned_to>{0}</assigned_to>'.format(escape(
                header['Assigned-to'])))
        if header['Discovered-by']:
            advisory.append('<discovered_by>{0}</discovered_by>'.format(escape(
                header['Discovered-by'])))
        if header['CRD']:
            advisory.append('<crd>{0}</crd>'.format(escape(header['CRD'])))
        for bug in header['Bugs']:
            advisory.append('<bug>{0}</bug>'.format(escape(bug)))
        for ref in header['References']:
            if ref.startswith('https://cve.mitre'):
                cve_title = ref.split('=')[-1].strip()
                if not cve_title:
                    continue
                mapping['cve_title'] = escape(cve_title)
                mapping['references'] = '\n                    <reference source="CVE" ref_id="{0}" ref_url="{1}" />'.format(mapping['cve_title'], escape(ref))

        cve_ref = generate_cve_tag(header)
        advisory.append(cve_ref)
        mapping['advisory_elements'] = '\n                        '.join(advisory)

        if self.oval_format == 'dpkg':
            mapping['os_release_check'] = """<extend_definition definition_ref="{applicability_def_id}" comment="{release_name} ({codename}) is installed." applicability_check="true" />""".format(**mapping)
        else:
            mapping['os_release_check'] = ''

        self.queue_element('definition', """
            <definition class="vulnerability" id="{ns}:def:{id_base}0" version="1">
                <metadata>
                    <title>{cve_title} on {release_name} ({codename}) - {priority}.</title>
                    <description>{description}</description>
                    <affected family="unix">
                        <platform>{release_name}</platform>
                    </affected>{references}
                    <advisory>
                        {advisory_elements}
                    </advisory>
                </metadata>{notes}
                <criteria>
                    {os_release_check}
                    {criteria}
                </criteria>
            </definition>\n""".format(**mapping))

    def get_running_kernel_testref(self, package):
        uname_regex = process_kernel_binaries(package['binaries'], self.oval_format)
        if uname_regex:
            if self.oval_format == 'dpkg':
                (var_id, var_id_2) = self.get_running_kernel_variable_id(
                    uname_regex,
                    package['id_base'],
                    package['fix-version'])
                (ste_id, ste_id_2) = self.get_running_kernel_state_id(
                    uname_regex,
                    package['id_base'],
                    var_id)
                (obj_id, obj_id_2) = self.get_running_kernel_object_id(
                    package['id_base'], var_id_2)
                (test_id, test_id_2) = self.get_running_kernel_test_id(
                    uname_regex, package['id_base'], package['name'],
                    obj_id, ste_id, obj_id_2, ste_id_2)
                return [{'id': test_id,
                         'comment': 'Is kernel {0} running'.format(package['name']),
                         'kernel': uname_regex, 'var_id': var_id},
                        {'id': test_id_2, 'comment': 'kernel version comparison',
                         'kernelobj': True}]
            else:  # OCI
                object_id = self.get_package_object_id(package['name'],
                                                       [uname_regex],
                                                       package['id_base'])
                state_id = self.get_package_version_state_id(package['id_base'],
                                                             package['fix-version'])
                test_title = "Does the '{0}' package exist and is the version less than '{1}'?".format(package['name'],
                                                                                                       package['fix-version'])
                test_id = self.get_package_test_id(package['name'],
                                                   package['id_base'],
                                                   test_title,
                                                   object_id,
                                                   state_id)
                package['note'] = package['name'] + package['note']
                return [{'id': test_id, 'comment': package['note']}]

        return None

    def get_oval_test_for_package(self, package):
        """ create OVAL test and dependent objects for this package status
                @package = {
                    'name'          : '<package name>',
                    'binaries'      : [ '<binary_pkg_name', '<binary_pkg_name', ... ],
                    'status'        : '<not-applicable | unknown | vulnerable | fixed>',
                    'note'          : '<a description of the status>',
                    'fix-version'   : '<the version in which the issue was fixed, if applicable>',
                    'id_base'       : a base for the integer section of the OVAL id,
                    'source-note'   : a note about the datasource for debugging
                }
        """

        if package['status'] == 'fixed' and not package['fix-version']:
            self.warn('"{0}" package in {1} is marked fixed, but missing a fix-version. Changing status to vulnerable.'.format(package['name'], package['source-note']))
            package['status'] = 'vulnerable'

        if package['status'] == 'not-applicable':
            # if the package status is not-applicable, skip it!
            return False
        elif package['status'] == 'not-vulnerable':
            # if the packaget status is not-vulnerable, skip it!
            return False
            """
            object_id = self.get_package_object_id(package['name'], package['id_base'], 1)

            test_title = "Returns true whether or not the '{0}' package exists.".format(package['name'])
            test_id = self.get_package_test_id(package['name'], package['id_base'], test_title, object_id, None, 1, 'any_exist')

            package['note'] = package['name'] + package['note']
            return {'id': test_id, 'comment': package['note'], 'negate': True}
            """
        elif package['status'] == 'vulnerable':
            object_id = self.get_package_object_id(package['name'], package['binaries'], package['id_base'])

            test_title = "Does the '{0}' package exist?".format(package['name'])
            test_id = self.get_package_test_id(package['name'], package['id_base'], test_title, object_id)

            package['note'] = package['name'] + package['note']
            return {'id': test_id, 'comment': package['note']}
        elif package['status'] == 'fixed':
            object_id = self.get_package_object_id(package['name'], package['binaries'], package['id_base'])

            state_id = self.get_package_version_state_id(package['id_base'], package['fix-version'])

            test_title = "Does the '{0}' package exist and is the version less than '{1}'?".format(package['name'], package['fix-version'])
            test_id = self.get_package_test_id(package['name'], package['id_base'], test_title, object_id, state_id)

            package['note'] = package['name'] + package['note']
            return {'id': test_id, 'comment': package['note']}
        else:
            if package['status'] != 'unknown':
                self.warn('"{0}" is not a supported package status. Outputting for "unknown" status.'.format(package['status']))

            if not hasattr(self, 'id_unknown_test'):
                self.id_unknown_test = '{0}:tst:10'.format(self.ns)
                self.queue_element('test', """
                    <ind-def:unknown_test id="{0}" check="all" comment="The result of this test is always UNKNOWN." version="1" />\n""".format(self.id_unknown_test))

            package['note'] = package['name'] + package['note']
            return {'id': self.id_unknown_test, 'comment': package['note']}

    # TODO: xml lib
    def add_release_applicability_definition(self):
        """ add platform/release applicability OVAL definition for codename """

        mapping = {
            'ns': self.ns,
            'id_base': self.id,
            'codename': self.release_codename,
            'release_name': self.release_name,
        }
        self.release_applicability_definition_id = \
            '{ns}:def:{id_base}0'.format(**mapping)

        if self.oval_format == 'dpkg':
            self.queue_element('definition', """
                <definition class="inventory" id="{ns}:def:{id_base}0" version="1">
                    <metadata>
                        <title>Check that {release_name} ({codename}) is installed.</title>
                        <description></description>
                    </metadata>
                    <criteria>
                        <criterion test_ref="{ns}:tst:{id_base}0" comment="The host is part of the unix family." />
                        <criterion test_ref="{ns}:tst:{id_base}1" comment="The host is running Ubuntu {codename}." />
                    </criteria>
                </definition>\n""".format(**mapping))

            self.queue_element('test', """
                <ind-def:family_test id="{ns}:tst:{id_base}0" check="at least one" check_existence="at_least_one_exists" version="1" comment="Is the host part of the unix family?">
                    <ind-def:object object_ref="{ns}:obj:{id_base}0"/>
                    <ind-def:state state_ref="{ns}:ste:{id_base}0"/>
                </ind-def:family_test>

                <ind-def:textfilecontent54_test id="{ns}:tst:{id_base}1" check="at least one" check_existence="at_least_one_exists" version="1" comment="Is the host running Ubuntu {codename}?">
                    <ind-def:object object_ref="{ns}:obj:{id_base}1"/>
                    <ind-def:state state_ref="{ns}:ste:{id_base}1"/>
                </ind-def:textfilecontent54_test>\n""".format(**mapping))

            # /etc/lsb-release has to be a single path, due to some
            # environments (namely snaps) not being allowed to list the
            # content of /etc/
            self.queue_element('object', """
                <ind-def:family_object id="{ns}:obj:{id_base}0" version="1" comment="The singleton family object."/>

                <ind-def:textfilecontent54_object id="{ns}:obj:{id_base}1" version="1" comment="The singleton release codename object.">
                    <ind-def:filepath>/etc/lsb-release</ind-def:filepath>
                    <ind-def:pattern operation="pattern match">^[\\s\\S]*DISTRIB_CODENAME=([a-z]+)$</ind-def:pattern>
                    <ind-def:instance datatype="int">1</ind-def:instance>
                </ind-def:textfilecontent54_object>\n""".format(**mapping))

            self.queue_element('state', """
                <ind-def:family_state id="{ns}:ste:{id_base}0" version="1" comment="The singleton family object.">
                    <ind-def:family>unix</ind-def:family>
                </ind-def:family_state>

                <ind-def:textfilecontent54_state id="{ns}:ste:{id_base}1" version="1" comment="{release_name}">
                    <ind-def:subexpression>{codename}</ind-def:subexpression>
                </ind-def:textfilecontent54_state>\n""".format(**mapping))

    # TODO: xml lib
    def get_package_object_id(self, name, bin_pkgs, id_base, version=1):
        """ create unique object for each package and return its OVAL id """
        if not hasattr(self, 'package_objects'):
            self.package_objects = {}

        key = tuple(sorted(bin_pkgs))

        if key not in self.package_objects:
            object_id = '{0}:obj:{1}0'.format(self.ns, id_base)

            if len(bin_pkgs) > 1:
                # create variable for binary package names
                variable_id = '{0}:var:{1}0'.format(self.ns, id_base)
                if self.oval_format == 'dpkg':
                    variable_values = '</value>\n                            <value>'.join(bin_pkgs)
                    self.queue_element('variable', """
                        <constant_variable id="{0}" version="{1}" datatype="string" comment="'{2}' package binaries">
                            <value>{3}</value>
                        </constant_variable>\n""".format(variable_id, version, name, variable_values))

                    # create an object that references the variable
                    self.queue_element('object', """
                        <linux-def:dpkginfo_object id="{0}" version="{1}" comment="The '{2}' package binaries.">
                            <linux-def:name var_ref="{3}" var_check="at least one" />
                        </linux-def:dpkginfo_object>\n""".format(object_id, version, name, variable_id))

                else:
                    variable_values = '(?::\w+|)\s+(.*)$\s+(.*)</value>\n                            <value>^'.join(bin_pkgs)
                    self.queue_element('variable', """
                        <constant_variable id="{0}" version="{1}" datatype="string" comment="'{2}' package binaries">
                            <value>^{3}(?::\w+|)\s+(.*)$\s+(.*)</value>
                        </constant_variable>\n""".format(variable_id, version, name, variable_values))

                    # create an object that references the variable
                    self.queue_element('object', """
                        <ind-def:textfilecontent54_object id="{0}" version="{1}" comment="The '{2}' package binaries.">
                            <ind-def:path>.</ind-def:path>
                            <ind-def:filename>manifest</ind-def:filename>
                            <ind-def:pattern operation="pattern match" datatype="string" var_ref="{3}" var_check="at least one" />
                            <ind-def:instance operation="greater than or equal" datatype="int">1</ind-def:instance>
                        </ind-def:textfilecontent54_object>\n""".format(object_id, version, name, variable_id))

            else:
                if self.oval_format == 'dpkg':
                    # 1 binary package, so just use name in object (no variable)
                    self.queue_element('object', """
                        <linux-def:dpkginfo_object id="{0}" version="{1}" comment="The '{2}' package binary.">
                            <linux-def:name>{3}</linux-def:name>
                        </linux-def:dpkginfo_object>\n""".format(object_id, version, name, bin_pkgs[0]))
                else:
                    variable_id = '{0}:var:{1}0'.format(self.ns, id_base)
                    variable_values = '(?::\w+|)\s+(.*)$\s+(.*)</value>\n                            <value>^'.join(bin_pkgs)
                    self.queue_element('variable', """
                        <constant_variable id="{0}" version="{1}" datatype="string" comment="'{2}' package binaries">
                            <value>^{3}(?::\w+|)\s+(.*)$\s+(.*)</value>
                        </constant_variable>\n""".format(variable_id, version, name, variable_values))
                    self.queue_element('object', """
                        <ind-def:textfilecontent54_object id="{0}" version="{1}" comment="The '{2}' package binary.">
                            <ind-def:path>.</ind-def:path>
                            <ind-def:filename>manifest</ind-def:filename>
                            <ind-def:pattern operation="pattern match" datatype="string" var_ref="{3}" var_check="at least one" />
                            <ind-def:instance operation="greater than or equal" datatype="int">1</ind-def:instance>
                        </ind-def:textfilecontent54_object>\n""".format(object_id, version, name, variable_id))

            self.package_objects[key] = object_id

        return self.package_objects[key]

    # TODO: xml lib
    def get_package_version_state_id(self, id_base, fix_version, version=1):
        """ create unique states for each version and return its OVAL id """
        if not hasattr(self, 'package_version_states'):
            self.package_version_states = {}

        key = fix_version
        if key not in self.package_version_states:
            state_id = '{0}:ste:{1}0'.format(self.ns, id_base)
            if self.oval_format == 'dpkg':
                epoch_fix_version = fix_version if fix_version.find(':') != -1 else "0:" + fix_version
                self.queue_element('state', """
                    <linux-def:dpkginfo_state id="{0}" version="{1}" comment="The package version is less than '{2}'.">
                        <linux-def:evr datatype="debian_evr_string" operation="less than">{2}</linux-def:evr>
                    </linux-def:dpkginfo_state>\n""".format(state_id, version, epoch_fix_version))
            else:
                self.queue_element('state', """
                    <ind-def:textfilecontent54_state id="{0}" version="{1}" comment="The package version is less than '{2}'.">
                        <ind-def:subexpression datatype="debian_evr_string" operation="less than">{2}</ind-def:subexpression>
                    </ind-def:textfilecontent54_state>\n""".format(state_id, version, fix_version))
            self.package_version_states[key] = state_id

        return self.package_version_states[key]

    # TODO: xml lib
    def get_package_test_id(self, name, id_base, test_title, object_id, state_id=None, version=1, check_existence='at_least_one_exists'):
        """ create unique test for each parameter set and return its OVAL id """
        if not hasattr(self, 'package_tests'):
            self.package_tests = {}

        key = (name, test_title, object_id, state_id)
        if key not in self.package_tests:
            test_id = '{0}:tst:{1}0'.format(self.ns, id_base)
            if self.oval_format == 'dpkg':
                state_ref = '\n                        <linux-def:state state_ref="{0}" />'.format(state_id) if state_id else ''
                self.queue_element('test', """
                    <linux-def:dpkginfo_test id="{0}" version="{1}" check_existence="{5}" check="at least one" comment="{2}">
                        <linux-def:object object_ref="{3}"/>{4}
                    </linux-def:dpkginfo_test>\n""".format(test_id, version, test_title, object_id, state_ref, check_existence))
            else:
                state_ref = '\n                        <ind-def:state state_ref="{0}" />'.format(state_id) if state_id else ''
                self.queue_element('test', """
                    <ind-def:textfilecontent54_test id="{0}" version="{1}" check_existence="{5}" check="at least one" comment="{2}">
                        <ind-def:object object_ref="{3}"/>{4}
                    </ind-def:textfilecontent54_test>\n""".format(test_id, version, test_title, object_id, state_ref, check_existence))
            self.package_tests[key] = test_id

        return self.package_tests[key]

    # TODO: xml lib
    def get_running_kernel_object_id(self, id_base, var_id, version=1):
        """ creates a uname_object so we can use the value from uname -r for
            mainly two things:
            1. compare with the return uname is of the same version and flavour
               as the kernel we fixed a CVE. This is done in
               get_running_kernel_state_id
            2. store the uname value, minus the flavour, in a debian evr string
               format, e.g: 0:5.4.0-1059. With this we can compare if the patched
               kernel is greater than the running kernel
            The result of this two will go through an AND logic to confirm
            if we are or not vulnerable to such CVE"""
        if not hasattr(self, 'kernel_uname_obj_id'):
            self.kernel_uname_obj_id = None

        if not self.kernel_uname_obj_id:
            object_id = '{0}:obj:{1}0'.format(self.ns, id_base)

            self.queue_element('object', """
                    <unix-def:uname_object id="{0}" version="{1}"/>\n""".format(object_id, version))

            self.kernel_uname_obj_id = object_id

        object_id_2 = '{0}:obj:{1}0'.format(self.ns, id_base + 1)

        self.queue_element('object', """
                <ind-def:variable_object id="{0}" version="{1}">
                    <ind-def:var_ref>{2}</ind-def:var_ref>
                </ind-def:variable_object>\n""".format(object_id_2, version, var_id))


        return (self.kernel_uname_obj_id, object_id_2)

    # TODO: xml lib
    def get_running_kernel_state_id(self, uname_regex, id_base, var_id, version=1):
        """ create uname_state to compare the system uname to the affected kernel
            uname regex, allowing us to verify we are running the same major version
            and flavour as the affected kernel.
            Return its OVAL id
        """
        if not hasattr(self, 'uname_states'):
            self.uname_states = {}

        if not hasattr(self, 'kernel_state_id'):
            self.kernel_state_id = None

        if uname_regex not in self.uname_states:
            state_id = '{0}:ste:{1}0'.format(self.ns, id_base)
            self.queue_element('state', """
                    <unix-def:uname_state id="{0}" version="{1}">
                        <unix-def:os_release operation="pattern match">{2}</unix-def:os_release>
                    </unix-def:uname_state>\n""".format(state_id, version, uname_regex))

            self.uname_states[uname_regex] = state_id

        if not self.kernel_state_id:
            state_id_2 = '{0}:ste:{1}0'.format(self.ns, id_base + 1)
            self.queue_element('state', """
                    <ind-def:variable_state id="{0}" version="{1}">
                        <ind-def:value operation="greater than" datatype="debian_evr_string" var_ref="{2}" var_check="at least one" />
                    </ind-def:variable_state>\n""".format(state_id_2, version, var_id))

            self.kernel_state_id = state_id_2

        return (self.uname_states[uname_regex], self.kernel_state_id)

    # TODO: xml lib
    def get_running_kernel_variable_id(self, uname_regex, id_base, fixed_version, version=1):
        """ creates a local variable to store running kernel version in devian evr string"""
        if not hasattr(self, 'uname_variables'):
            self.uname_variables = {}

            var_id = '{0}:var:{1}0'.format(self.ns, id_base)
            obj_id = '{0}:obj:{1}0'.format(self.ns, id_base)
            self.queue_element('variable', """
                    <local_variable id="{0}" datatype="debian_evr_string" version="{1}" comment="kernel version in evr format">
                        <concat>
                            <literal_component>0:</literal_component>
                            <regex_capture pattern="^([\d|\.]+-\d+)[-|\w]+$">
                                <object_component object_ref="{2}" item_field="os_release" />
                            </regex_capture>
                        </concat>
                    </local_variable>\n""".format(var_id, version, obj_id))

            self.uname_variables['local_variable'] = var_id

        var_id_2 = '{0}:var:{1}0'.format(self.ns, id_base + 1)
        patched = re.search('([\d|\.]+-\d+)[\.|\d]+', fixed_version)
        if patched:
            patched = patched.group(1)
        else:
            patched = fixed_version
        self.queue_element('variable', """
                 <constant_variable id="{0}" version="{1}" datatype="debian_evr_string" comment="patched kernel">
                     <value>0:{2}</value>
                 </constant_variable>""".format(var_id_2, version, patched))

        return (self.uname_variables['local_variable'], var_id_2)

    # TODO: xml lib
    def get_running_kernel_test_id(self, uname_regex, id_base, name, object_id, state_id, object_id_2, state_id_2, version=1):
        """ create uname test and return its OVAL id """
        if not hasattr(self, 'uname_tests'):
            self.uname_tests = {}

        if uname_regex not in self.uname_tests:
            test_id = '{0}:tst:{1}0'.format(self.ns, id_base)
            self.queue_element('test', """
                    <unix-def:uname_test check="at least one" comment="Is kernel {0} currently running?" id="{1}" version="{2}">
                        <unix-def:object object_ref="{3}"/>
                        <unix-def:state state_ref="{4}"/>
                    </unix-def:uname_test>\n""".format(name, test_id, version, object_id, state_id))

            self.uname_tests[uname_regex] = test_id

        test_id_2 = '{0}:tst:{1}0'.format(self.ns, id_base + 1)

        self.queue_element('test', """
                <ind-def:variable_test id="{0}" version="1" check="all" check_existence="all_exist" comment="kernel version comparison">
                    <ind-def:object object_ref="{1}"/>
                    <ind-def:state state_ref="{2}"/>
                </ind-def:variable_test>\n""".format(test_id_2, object_id_2, state_id_2))


        return (self.uname_tests[uname_regex], test_id_2)

    def queue_element(self, element, xml):
        """ add an OVAL element to an output queue file """
        if element not in OvalGenerator.supported_oval_elements:
            self.warn('"{0}" is not a supported OVAL element.'.format(element))
            return

        if not hasattr(self, 'tmp'):
            self.tmp = {}
            self.tmp_n = random.randrange(1000000, 9999999)

        if element not in self.tmp:
            self.tmp[element] = _open(os.path.join(self.tmpdir,
                                           './queue.{0}.{1}.xml'.format(
                                               self.tmp_n, element)), 'wt')

        # trim and fix indenting (assumes fragment is nicely indented internally)
        xml = xml.strip('\n')
        base_indent = re.match(r'\s*', xml).group(0)
        xml = re.sub('^{0}'.format(base_indent), '        ', xml, 0,
                     re.MULTILINE)

        self.tmp[element].write(xml + '\n')

    # TODO: xml lib
    def write_to_file(self):
        """ dequeue all elements into one OVAL definitions file and clean up """
        if not hasattr(self, 'tmp'):
            return

        # close queue files for writing and then open for reading
        for key in self.tmp:
            self.tmp[key].close()
            self.tmp[key] = _open(self.tmp[key].name, 'rt')

        tmp = os.path.join(self.tmpdir, self.output_filepath)
        with _open(tmp, 'wt') as f:
            # add header
            oval_timestamp = datetime.now(tz=timezone.utc).strftime(
                '%Y-%m-%dT%H:%M:%S')
            f.write("""<oval_definitions
    xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
    xmlns:ind-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
    xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
    xmlns:unix-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"
    xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5#independent independent-definitions-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5#unix unix-definitions-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5#macos linux-definitions-schema.xsd">

    <generator>
        <oval:product_name>Canonical CVE OVAL Generator</oval:product_name>
        <oval:product_version>{0}</oval:product_version>
        <oval:schema_version>{1}</oval:schema_version>
        <oval:timestamp>{2}</oval:timestamp>
    </generator>\n""".format(OvalGenerator.generator_version, OvalGenerator.oval_schema_version, oval_timestamp))

            # add queued file content
            for element in OvalGenerator.supported_oval_elements:
                if element in self.tmp:
                    f.write("\n    <{0}s>\n".format(element))
                    f.write(self.tmp[element].read().rstrip())
                    f.write("\n    </{0}s>".format(element))

            # add footer
            f.write("\n</oval_definitions>")

        # close and delete queue files
        for key in self.tmp:
            self.tmp[key].close()
            os.remove(self.tmp[key].name)

        # close self.output_filepath and move into place
        f.close()
        shutil.move(tmp, os.path.join(self.output_dir, self.output_filepath))

        # remove tmp dir if empty
        if not os.listdir(self.tmpdir):
            os.rmdir(self.tmpdir)

    def unique_id_base(self, id_base, note):
        """ queue a warning message """
        if not hasattr(self, 'id_bases'):
            self.id_bases = {}
        is_unique = id_base not in self.id_bases.keys()
        if not is_unique:
            self.warn('ID Base collision {0} in {1} and {2}.'.format(
                id_base, note, self.id_bases[id_base]))
        self.id_bases[id_base] = note
        return is_unique

    def warn(self, message):
        """ print a warning message """
        print('WARNING: {0}'.format(message))

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

    def __init__(self, release_codename, release_name, outdir='./', cve_dir=None, prefix='', oval_format='dpkg'):
        self.release_codename = release_codename.replace('/', '_')
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
            mapping = {
                'id': self.id,
                'ns': self.ns,
                'title': "Check that {} ({})".format(self.release_name, self.release_codename),
                'comment': "{} ({})".format(self.release_name, self.release_codename)
            }

            definition =\
        """
        <definition class="inventory" id="{ns}:def:{id}" version="1">
            <metadata>
                <title>{title} is installed.</title>
                <description></description>
            </metadata>
            <criteria>
                <criterion test_ref="{ns}:tst:{id}" comment="{comment} is installed." />
            </criteria>
        </definition>""".format(**mapping)
        else:
            definition = ""

        return definition

    # TODO: xml lib
    def create_release_test(self):
        if self.oval_format == 'dpkg':
            mapping = {
                'id': self.id,
                'ns': self.ns,
                'comment': "{} ({})".format(self.release_name, self.release_codename)
            }

            test =\
        """
        <ind:textfilecontent54_test check="at least one" check_existence="at_least_one_exists" id="{ns}:tst:{id}" version="1" comment="{comment} is installed.">
            <ind:object object_ref="{ns}:obj:{id}" />
            <ind:state state_ref="{ns}:ste:{id}" />
        </ind:textfilecontent54_test>""".format(**mapping)
        else:
            test = ""

        return test

    # TODO: xml lib
    def create_release_object(self):
        if self.oval_format == 'dpkg':
            mapping = {
                'id': self.id,
                'ns': self.ns,
            }

            _object =\
        """
        <ind:textfilecontent54_object id="{ns}:obj:{id}" version="1">
            <ind:filepath datatype="string">/etc/lsb-release</ind:filepath>
                <ind:pattern operation="pattern match">^[\s\S]*DISTRIB_CODENAME=([a-z]+)$</ind:pattern>
            <ind:instance datatype="int">1</ind:instance>
        </ind:textfilecontent54_object>""".format(**mapping)
        else:
            _object = ""

        return _object

    # TODO: xml lib
    def create_release_state(self):
        if self.oval_format == 'dpkg':
            mapping = {
                'id': self.id,
                'ns': self.ns,
                'comment': "{}".format(self.release_name),
                'release_codename': self.release_codename,
            }

            state =\
        """
        <ind:textfilecontent54_state id="{ns}:ste:{id}" version="1" comment="{comment}">
            <ind:subexpression datatype="string" operation="equals">{release_codename}</ind:subexpression>
        </ind:textfilecontent54_state>""".format(**mapping)
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

    def create_cves_references(self, cves):
        references = ""
        for cve in cves:
            cve_ref = generate_cve_tag(cve)
            references += \
                """{0}
                    """.format(cve_ref)
        return references.strip()

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
        cve_references = self.create_cves_references(cves_info)
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
            'platform': "{}".format(self.release_name),
            'usn_url': self.usn_base_url.format(usn_object['id']),
            'description': escape(' '.join((usn_object['description'].strip() + instructions).split('\n'))),
            'cves_references': cve_references,
            'bug_references': bug_references,
            'severity': usn_severity,
            'usn_timestamp': datetime.fromtimestamp(usn_object['timestamp'], tz=timezone.utc).strftime('%Y-%m-%d'),
            'criteria': '',
        }

        # convert number versions of binary pkgs into test criteria
        criteria = []
        kernel = False
        for test_ref in test_refs:
            if self.pocket == 'livepatch' and self.oval_format == 'dpkg':
                criteria.append('<criteria operator="AND">')
                criteria.append('    <criterion test_ref="{0}:tst:{1}" comment="{2}" />'.format(self.ns, str(int(test_ref['testref_id']) + 1), self.product_description))
                criteria.append('    <criterion test_ref="{0}:tst:{1}" comment="{2}" />'.format(self.ns, test_ref['testref_id'], self.product_description))
                criteria.append('</criteria>')
            elif 'kernel' in test_ref and self.oval_format == 'dpkg':
                kernel = True
                criteria.append('<criteria operator="AND">')
                criteria.append('    <criterion test_ref="{0}:tst:{1}" comment="{2}" />'.format(self.ns, test_ref['testref_id'], self.product_description))
            elif kernel:
                kernel = False
                criteria.append('    <criterion test_ref="{0}:tst:{1}" comment="{2}" />'.format(self.ns, test_ref['testref_id'], self.product_description))
                criteria.append('</criteria>')
            else:
                criteria.append('<criterion test_ref="{0}:tst:{1}" comment="{2}" />'.format(self.ns, test_ref['testref_id'], self.product_description))

        mapping['criteria'] = '\n                '.join(criteria)

        definition = \
        """
        <definition id="{ns}:def:{id}" version="1" class="patch">
            <metadata>
                <title>{title}</title>
                <affected family="unix">
                    <platform>{platform}</platform>
                </affected>
                <reference source="USN" ref_url="{usn_url}" ref_id="{usn_id}"/>
                <description>{description}</description>
                <advisory from="security@ubuntu.com">
                    <severity>{severity}</severity>
                    <issued date="{usn_timestamp}"/>
                    {cves_references}
                    {bug_references}
                </advisory>
            </metadata>
            <criteria operator="OR">
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

                _object = \
        """
        <ind:variable_object id="{ns}:obj:{id}" version="1">
            <ind:var_ref>{ns}:var:{id}</ind:var_ref>
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
                mapping['varid'] = test_ref['kernelobj']
                state = \
        """
        <ind:variable_state id="{ns}:ste:{id}" version="1">
            <ind:value operation="greater than" datatype="debian_evr_string" var_ref="{ns}:var:{varid}" var_check="at least one" />
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
                binary_version = test_ref['version']
                binary_version = re.search('([\d|\.]+-\d+)[\.|\d]+', binary_version)
                mapping['bversion'] = "0:" + binary_version.group(1)

                variable = \
            """
        <constant_variable id="{ns}:var:{id}" version="1" datatype="debian_evr_string" comment="patched kernel">
            <value>{bversion}</value>
        </constant_variable>""".format(**mapping)

                return variable

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
        priority = cve_object['Priority']
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
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5#independent independent-definitions-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5#unix unix-definitions-schema.xsd   http://oval.mitre.org/XMLSchema/oval-definitions-5#macos linux-definitions-schema.xsd">

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
