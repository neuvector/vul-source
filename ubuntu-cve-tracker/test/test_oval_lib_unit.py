#!/usr/bin/python3

import os
import oval_lib
import pytest
import mock
from datetime import datetime, timezone
from shutil import copyfile
import pickle
import collections

supported_oval_elements = ('definition', 'test', 'object', 'state', 'variable')
rel_test_path = "./test/"
gold_oval_structure_path = "{}gold_oval_structure/".format(rel_test_path)

class MockOvalGeneratorUSN(oval_lib.OvalGeneratorUSN):
    generator_version = '1'
    oval_schema_version = '5.11.1'

    def __init__(self, oval_format = 'dpkg'):
        self.release_codename = "bionic"
        self.release_name = "Ubuntu 18.04 LTS"
        self.product_description = "Long Term Support"
        self.tmpdir = rel_test_path
        self.output_dir = "./"
        self.output_filepath = 'com.ubuntu.{0}.usn.oval.xml'.format(
            self.release_codename)
        self.oval_structure = {
            key: open("{}{}.xml".format(rel_test_path, key), "w+") for key in
                supported_oval_elements
        }
        self.testdict = {}
        self.ns = 'oval:com.ubuntu.{}'.format(self.release_codename)
        self.id = 100
        self.oval_format = oval_format

    def file_cleanup(self):
        for key in self.oval_structure:
            if os.path.exists(self.oval_structure[key].name):
                self.oval_structure[key].close()
                os.remove(self.oval_structure[key].name)

class TestOvalLibUnit:
    # Set up dummy values
    oval_gen_mock = MockOvalGeneratorUSN()

    oval_gen_mock_oci = MockOvalGeneratorUSN("oci")

    # Read in USN data to use as input argument to function to test
    with open("{}test_usn.pickle".format(rel_test_path), "rb") as usnfile:
        usn_object_mock = pickle.load(usnfile)
    usn_mock = "4388-1"
    id_base_mock = 43881000000
    test_cve_file = "CVE-TEST"
    usn_object_mock['id'] = "USN-" + usn_mock


    bin_dict_mock = collections.defaultdict(list)
    bin_dict_mock = {'5.0.0.1042.27': ['linux-image-gke-5.0'], '5.0.0-1059.64':
        ['linux-image-5.0.0-1059-oem-osp1'], '5.0.0.1059.58':
        ['linux-image-oem-osp1'], '5.0.0-1042.43':
        ['linux-image-5.0.0-1042-gke']}

    bin_vers_mock = collections.defaultdict(list)
    bin_vers_mock = {'5.0.0-1059.64': ['linux-image-5.0.0-1059-oem-osp1'],
                     '5.0.0-1042.43': ['linux-image-5.0.0-1042-gke']}

    test_ref_mock = [({'version': '5.0.0-1059.64',
                       'pkgs': ['linux-image-5.0.0-1059-oem-osp1'],
                       'testref_id': '438810000000',
                       'kernel': '5.0.0-\d+(-oem-osp1)'},
                      {'version': '5.0.0-1059.64',
                       'pkgs': ['linux-image-5.0.0-1059-oem-osp1'],
                       'testref_id': '438810000010'}),
                      ({'version': '5.0.0-1042.43',
                       'pkgs': ['linux-image-5.0.0-1042-gke'],
                       'testref_id': '438810000020',
                       'kernel': '5.0.0-\d+(-gke)'},
                      {'version': '5.0.0-1042.43',
                       'pkgs': ['linux-image-5.0.0-1042-gke'],
                       'testref_id': '438810000030'})]

    test_refs_mock = [test_ref for tup in test_ref_mock for test_ref in tup]

    definition_mock = """
        <definition id="oval:com.ubuntu.bionic:def:43881000000" version="1" class="patch">
            <metadata>
                <title>USN-4388-1 -- Linux kernel vulnerabilities</title>
                <affected family="unix">
                    <platform>Ubuntu 18.04 LTS</platform>
                </affected>
                <reference source="USN" ref_url="https://ubuntu.com/security/notices/USN-4388-1" ref_id="USN-4388-1"/>
                <reference source="CVE" ref_url="https://ubuntu.com/security/CVE-2020-0067" ref_id="CVE-2020-0067"/>
                <reference source="CVE" ref_url="https://ubuntu.com/security/CVE-2020-0543" ref_id="CVE-2020-0543"/>
                <reference source="CVE" ref_url="https://ubuntu.com/security/CVE-2020-12114" ref_id="CVE-2020-12114"/>
                <reference source="CVE" ref_url="https://ubuntu.com/security/CVE-2020-12464" ref_id="CVE-2020-12464"/>
                <reference source="CVE" ref_url="https://ubuntu.com/security/CVE-2020-12659" ref_id="CVE-2020-12659"/>
                <reference source="CVE" ref_url="https://ubuntu.com/security/CVE-2020-1749" ref_id="CVE-2020-1749"/>
                <description>It was discovered that the F2FS file system implementation in the Linux kernel did not properly perform bounds checking on xattrs in some situations. A local attacker could possibly use this to expose sensitive information (kernel memory). (CVE-2020-0067)  It was discovered that memory contents previously stored in microarchitectural special registers after RDRAND, RDSEED, and SGX EGETKEY read operations on Intel client and Xeon E3 processors may be briefly exposed to processes on the same or different processor cores. A local attacker could use this to expose sensitive information. (CVE-2020-0543)  Piotr Krysiuk discovered that race conditions existed in the file system implementation in the Linux kernel. A local attacker could use this to cause a denial of service (system crash). (CVE-2020-12114)  It was discovered that the USB susbsystem's scatter-gather implementation in the Linux kernel did not properly take data references in some situations, leading to a use-after-free. A physically proximate attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2020-12464)  Bui Quang Minh discovered that the XDP socket implementation in the Linux kernel did not properly validate meta-data passed from user space, leading to an out-of-bounds write vulnerability. A local attacker with the CAP_NET_ADMIN capability could use this to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2020-12659)  Xiumei Mu discovered that the IPSec implementation in the Linux kernel did not properly encrypt IPv6 traffic in some situations. An attacker could use this to expose sensitive information. (CVE-2020-1749)  Update Instructions:  Run `sudo pro fix USN-4388-1` to fix the vulnerability. The problem can be corrected by updating your system to the following package versions:  linux-image-5.0.0-1042-gke - 5.0.0-1042.43 No subscription required  linux-image-5.0.0-1059-oem-osp1 - 5.0.0-1059.64 No subscription required</description>
                <advisory from="security@ubuntu.com">
                    <severity>Medium</severity>
                    <issued date="2020-06-09"/>
                    <ref>https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/SRBDS</ref>
                </advisory>
            </metadata>
            <criteria operator="OR">
                <criteria operator="AND">
                    <criterion test_ref="oval:com.ubuntu.bionic:tst:438810000000" comment="Long Term Support" />
                    <criterion test_ref="oval:com.ubuntu.bionic:tst:438810000010" comment="Long Term Support" />
                </criteria>
                <criteria operator="AND">
                    <criterion test_ref="oval:com.ubuntu.bionic:tst:438810000020" comment="Long Term Support" />
                    <criterion test_ref="oval:com.ubuntu.bionic:tst:438810000030" comment="Long Term Support" />
                </criteria>
            </criteria>
        </definition>"""

    references_mock = """<reference source="CVE" ref_url="https://ubuntu.com/security/CVE-2020-0067" ref_id="CVE-2020-0067"/>
                <reference source="CVE" ref_url="https://ubuntu.com/security/CVE-2020-0543" ref_id="CVE-2020-0543"/>
                <reference source="CVE" ref_url="https://ubuntu.com/security/CVE-2020-12114" ref_id="CVE-2020-12114"/>
                <reference source="CVE" ref_url="https://ubuntu.com/security/CVE-2020-12464" ref_id="CVE-2020-12464"/>
                <reference source="CVE" ref_url="https://ubuntu.com/security/CVE-2020-12659" ref_id="CVE-2020-12659"/>
                <reference source="CVE" ref_url="https://ubuntu.com/security/CVE-2020-1749" ref_id="CVE-2020-1749"/>"""

    test_mock = ["""
        <unix:uname_test check="at least one" comment="Is kernel 5.0.0-\d+(-oem-osp1) currently running?" id="oval:com.ubuntu.bionic:tst:438810000000" version="1">
            <unix:object object_ref="oval:com.ubuntu.bionic:obj:438810000000"/>
            <unix:state state_ref="oval:com.ubuntu.bionic:ste:438810000000"/>
        </unix:uname_test>""",
        """
        <linux:dpkginfo_test id="oval:com.ubuntu.bionic:tst:438810000010" version="1" check_existence="at_least_one_exists" check="at least one" comment="Long Term Support">
            <linux:object object_ref="oval:com.ubuntu.bionic:obj:438810000010"/>
            <linux:state state_ref="oval:com.ubuntu.bionic:ste:438810000010"/>
        </linux:dpkginfo_test>""",
        """
        <linux:dpkginfo_test id="oval:com.ubuntu.bionic:tst:438810000020" version="1" check_existence="at_least_one_exists" check="at least one" comment="Long Term Support">
            <linux:object object_ref="oval:com.ubuntu.bionic:obj:438810000020"/>
            <linux:state state_ref="oval:com.ubuntu.bionic:ste:438810000020"/>
        </linux:dpkginfo_test>""",
        """
        <linux:dpkginfo_test id="oval:com.ubuntu.bionic:tst:438810000030" version="1" check_existence="at_least_one_exists" check="at least one" comment="Long Term Support">
            <linux:object object_ref="oval:com.ubuntu.bionic:obj:438810000030"/>
            <linux:state state_ref="oval:com.ubuntu.bionic:ste:438810000030"/>
        </linux:dpkginfo_test>"""]

    test_oci_mock = """
        <ind:textfilecontent54_test id="oval:com.ubuntu.bionic:tst:438810000000" version="1" check_existence="at_least_one_exists" check="at least one" comment="Long Term Support">
            <ind:object object_ref="oval:com.ubuntu.bionic:obj:438810000000"/>
            <ind:state state_ref="oval:com.ubuntu.bionic:ste:438810000000"/>
        </ind:textfilecontent54_test>"""


    obj_mock = ["""
        <unix:uname_object id="oval:com.ubuntu.bionic:obj:438810000000" version="1"/>""",
        """
        <linux:dpkginfo_object id="oval:com.ubuntu.bionic:obj:438810000010" version="1" comment="Long Term Support">
            <linux:name var_ref="oval:com.ubuntu.bionic:var:438810000010" var_check="at least one" />
        </linux:dpkginfo_object>""",
        """
        <linux:dpkginfo_object id="oval:com.ubuntu.bionic:obj:438810000020" version="1" comment="Long Term Support">
            <linux:name var_ref="oval:com.ubuntu.bionic:var:438810000020" var_check="at least one" />
        </linux:dpkginfo_object>""",
        """
        <linux:dpkginfo_object id="oval:com.ubuntu.bionic:obj:438810000030" version="1" comment="Long Term Support">
            <linux:name var_ref="oval:com.ubuntu.bionic:var:438810000030" var_check="at least one" />
        </linux:dpkginfo_object>"""]

    obj_oci_mock = """
        <ind:textfilecontent54_object id="oval:com.ubuntu.bionic:obj:438810000000" version="1" comment="Long Term Support">
            <ind:path>.</ind:path>
            <ind:filename>manifest</ind:filename>
            <ind:pattern operation="pattern match" datatype="string" var_ref="oval:com.ubuntu.bionic:var:438810000000" var_check="at least one" />
            <ind:instance operation="greater than or equal" datatype="int">1</ind:instance>
        </ind:textfilecontent54_object>"""

    state_mock = ["""
        <unix:uname_state id="oval:com.ubuntu.bionic:ste:438810000000" version="1">
            <unix:os_release operation="pattern match">5.0.0-\d+(-oem-osp1)</unix:os_release>
        </unix:uname_state>""",
        """
        <linux:dpkginfo_state id="oval:com.ubuntu.bionic:ste:438810000010" version="1" comment="Long Term Support">
            <linux:evr datatype="debian_evr_string" operation="less than">0:5.0.0-1059.64</linux:evr>
        </linux:dpkginfo_state>""",
        """
        <unix:uname_state id="oval:com.ubuntu.bionic:ste:438810000020" version="1">
            <unix:os_release operation="pattern match">5.0.0-1042-(gke)</unix:os_release>
        </unix:uname_state>""",
        """
        <linux:dpkginfo_state id="oval:com.ubuntu.bionic:ste:438810000030" version="1" comment="Long Term Support">
            <linux:evr datatype="debian_evr_string" operation="less than">0:5.0.0-1042.43</linux:evr>
        </linux:dpkginfo_state>"""]

    state_epoch_mock = """
        <linux:dpkginfo_state id="oval:com.ubuntu.bionic:ste:437210000000" version="1" comment="Long Term Support">
            <linux:evr datatype="debian_evr_string" operation="less than">1:4.2-3ubuntu6.1</linux:evr>
        </linux:dpkginfo_state>"""

    state_oci_mock = """
        <ind:textfilecontent54_state id="oval:com.ubuntu.bionic:ste:438810000000" version="1" comment="Long Term Support">
            <ind:subexpression datatype="debian_evr_string" operation="less than">5.0.0.1042.27</ind:subexpression>
        </ind:textfilecontent54_state>"""

    var_mock = [None,
        """
        <constant_variable id="oval:com.ubuntu.bionic:var:438810000010" version="1" datatype="string" comment="Long Term Support">
            <value>linux-image-5.0.0-1059-oem-osp1</value>
        </constant_variable>""",
        None,
        """
        <constant_variable id="oval:com.ubuntu.bionic:var:438810000030" version="1" datatype="string" comment="Long Term Support">
            <value>linux-image-5.0.0-1042-gke</value>
        </constant_variable>"""]

    var_oci_mock = """
        <constant_variable id="oval:com.ubuntu.bionic:var:438810000010" version="1" datatype="string" comment="Long Term Support">
            <value>^linux-image-5.0.0-1059-oem-osp1(?::\w+|)\s+(.*)$</value>
        </constant_variable>"""

    bin_mock = {'linux-image-gke-5.0': {'version': '5.0.0.1042.27'},
        'linux-image-5.0.0-1059-oem-osp1': {'version': '5.0.0-1059.64'},
        'linux-image-oem-osp1': {'version': '5.0.0.1059.58'},
        'linux-image-5.0.0-1042-gke': {'version': '5.0.0-1042.43'}}

    state_args_mock = test_refs_mock

    var_args_mock = test_refs_mock

    state_oci_args_mock = [{'version': "5.0.0.1042.27",
                           'testref_id': "438810000000"}]

    var_oci_args_mock = ["438810000000", ['linux-image-gke-5.0']]

    cves_list_mock = ['CVE-2020-0067', 'CVE-2020-0543', 'CVE-2020-12114',
        'CVE-2020-12464', 'CVE-2020-12659', 'CVE-2020-1749']
    urls_mock = ['https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/SRBDS']
    cves_url_both_mock = cves_list_mock + urls_mock
    url_ref_mock = \
        "<ref>https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/SRBDS</ref>"
    cves_info_mock = [{'Candidate': 'CVE-2020-0067',
        'PublicDate': '2020-04-17 19:15:00 UTC', 'Priority': 'medium', 'CVSS':
        'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N', 'CVSS_SEVERITY_LEVEL':
        'MEDIUM', 'CVSS_SCORE': '4.4', 'CVE_URL':
        'https://ubuntu.com/security/CVE-2020-0067',
        'MITRE_URL': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0067'},
        {'Candidate': 'CVE-2020-0543', 'PublicDate': '2020-06-09 17:00:00 UTC',
        'Priority': 'medium', 'CVSS': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
        'CVSS_SEVERITY_LEVEL': 'MEDIUM', 'CVSS_SCORE': '5.5', 'CVE_URL':
        'https://ubuntu.com/security/CVE-2020-0543',
        'MITRE_URL': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0543'},
        {'Candidate': 'CVE-2020-12114', 'PublicDate': '2020-05-04 12:15:00 UTC',
        'Priority': 'medium', 'CVSS': 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H',
        'CVSS_SEVERITY_LEVEL': 'MEDIUM', 'CVSS_SCORE': '4.7', 'CVE_URL':
        'https://ubuntu.com/security/CVE-2020-12114',
        'MITRE_URL': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12114'},
        {'Candidate': 'CVE-2020-12464', 'PublicDate': '2020-04-29 18:15:00 UTC',
        'Priority': 'medium', 'CVSS': 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
        'CVSS_SEVERITY_LEVEL': 'MEDIUM', 'CVSS_SCORE': '6.7', 'CVE_URL':
        'https://ubuntu.com/security/CVE-2020-12464',
        'MITRE_URL': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12464'},
        {'Candidate': 'CVE-2020-12659', 'PublicDate': '2020-05-05 07:15:00 UTC',
        'Priority': 'low', 'CVSS': 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
        'CVSS_SEVERITY_LEVEL': 'MEDIUM', 'CVSS_SCORE': '6.7', 'CVE_URL':
        'https://ubuntu.com/security/CVE-2020-12659',
        'MITRE_URL': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12659'},
        {'Candidate': 'CVE-2020-1749', 'PublicDate': '2020-03-04 08:53:00 UTC',
        'Priority': 'medium', 'CVSS': None, 'CVSS_SEVERITY_LEVEL': None, 'CVSS_SCORE':
        None, 'CVE_URL':
        'https://ubuntu.com/security/CVE-2020-1749',
        'MITRE_URL': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1749'}]

    invalid_priority_cve_mock = [{'Candidate': 'CVE-2020-0067',
        'PublicDate': '2020-04-17 19:15:00 UTC', 'Priority': 'untriaged', 'CVSS':
        'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N', 'CVSS_SEVERITY_LEVEL':
        'MEDIUM', 'CVSS_SCORE': '4.4', 'CVE_URL':
        'https://ubuntu.com/security/CVE-2020-0067',
        'MITRE_URL': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0067'}]
    invalid_priority_references_mock = """<reference source="CVE" ref_url="https://ubuntu.com/security/CVE-2020-0067" ref_id="CVE-2020-0067"/>"""
    invalid_priority_ret = """
        <definition id="oval:com.ubuntu.bionic:def:43881000000" version="1" class="patch">
            <metadata>
                <title>USN-4388-1 -- Linux kernel vulnerabilities</title>
                <affected family="unix">
                    <platform>Ubuntu 18.04 LTS</platform>
                </affected>
                <reference source="USN" ref_url="https://ubuntu.com/security/notices/USN-4388-1" ref_id="USN-4388-1"/>
                <reference source="CVE" ref_url="https://ubuntu.com/security/CVE-2020-0067" ref_id="CVE-2020-0067"/>
                <description>It was discovered that the F2FS file system implementation in the Linux kernel did not properly perform bounds checking on xattrs in some situations. A local attacker could possibly use this to expose sensitive information (kernel memory). (CVE-2020-0067)  It was discovered that memory contents previously stored in microarchitectural special registers after RDRAND, RDSEED, and SGX EGETKEY read operations on Intel client and Xeon E3 processors may be briefly exposed to processes on the same or different processor cores. A local attacker could use this to expose sensitive information. (CVE-2020-0543)  Piotr Krysiuk discovered that race conditions existed in the file system implementation in the Linux kernel. A local attacker could use this to cause a denial of service (system crash). (CVE-2020-12114)  It was discovered that the USB susbsystem's scatter-gather implementation in the Linux kernel did not properly take data references in some situations, leading to a use-after-free. A physically proximate attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2020-12464)  Bui Quang Minh discovered that the XDP socket implementation in the Linux kernel did not properly validate meta-data passed from user space, leading to an out-of-bounds write vulnerability. A local attacker with the CAP_NET_ADMIN capability could use this to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2020-12659)  Xiumei Mu discovered that the IPSec implementation in the Linux kernel did not properly encrypt IPv6 traffic in some situations. An attacker could use this to expose sensitive information. (CVE-2020-1749)  Update Instructions:  Run `sudo pro fix USN-4388-1` to fix the vulnerability. The problem can be corrected by updating your system to the following package versions:  linux-image-5.0.0-1042-gke - 5.0.0-1042.43 No subscription required  linux-image-5.0.0-1059-oem-osp1 - 5.0.0-1059.64 No subscription required</description>
                <advisory from="security@ubuntu.com">
                    <severity>Medium</severity>
                    <issued date="2020-06-09"/>
                    <ref>https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/SRBDS</ref>
                </advisory>
            </metadata>
            <criteria operator="OR">
                <criteria operator="AND">
                    <criterion test_ref="oval:com.ubuntu.bionic:tst:438810000000" comment="Long Term Support" />
                    <criterion test_ref="oval:com.ubuntu.bionic:tst:438810000010" comment="Long Term Support" />
                </criteria>
                <criteria operator="AND">
                    <criterion test_ref="oval:com.ubuntu.bionic:tst:438810000020" comment="Long Term Support" />
                    <criterion test_ref="oval:com.ubuntu.bionic:tst:438810000030" comment="Long Term Support" />
                </criteria>
            </criteria>
        </definition>"""

    cve_severity_mock = [2, 2, 2, 2, 1, 2]
    avg_severity_mock = "Medium"

    instructions_mock = """\n
Update Instructions:

Run `sudo pro fix USN-4388-1` to fix the vulnerability. The problem can be corrected
by updating your system to the following package versions:

linux-image-5.0.0-1042-gke - 5.0.0-1042.43
No subscription required

linux-image-5.0.0-1059-oem-osp1 - 5.0.0-1059.64
No subscription required"""

    def test_create_release_def(self):
        def_mock = """
        <definition class="inventory" id="oval:com.ubuntu.bionic:def:100" version="1">
            <metadata>
                <title>Check that Ubuntu 18.04 LTS (bionic) is installed.</title>
                <description></description>
            </metadata>
            <criteria>
                <criterion test_ref="oval:com.ubuntu.bionic:tst:100" comment="Ubuntu 18.04 LTS (bionic) is installed." />
            </criteria>
        </definition>"""

        test_def = oval_lib.OvalGeneratorUSN.create_release_definition(
            self.oval_gen_mock)

        assert test_def == def_mock

    @pytest.mark.parametrize("func_name", ["create_release_definition",
        "create_release_test", "create_release_object",
        "create_release_state"])
    def test_create_release_oci(self, func_name):
        test_ret = getattr(self.oval_gen_mock_oci, func_name)()

        assert test_ret == ""

    def test_create_release_test(self):
        release_test_mock = """
        <ind:textfilecontent54_test check="at least one" check_existence="at_least_one_exists" id="oval:com.ubuntu.bionic:tst:100" version="1" comment="Ubuntu 18.04 LTS (bionic) is installed.">
            <ind:object object_ref="oval:com.ubuntu.bionic:obj:100" />
            <ind:state state_ref="oval:com.ubuntu.bionic:ste:100" />
        </ind:textfilecontent54_test>"""

        test_ret = oval_lib.OvalGeneratorUSN.create_release_test(
            self.oval_gen_mock)

        assert test_ret == release_test_mock

    def test_create_release_obj(self):
        release_obj_mock = """
        <ind:textfilecontent54_object id="oval:com.ubuntu.bionic:obj:100" version="1">
            <ind:filepath datatype="string">/etc/lsb-release</ind:filepath>
                <ind:pattern operation="pattern match">^[\s\S]*DISTRIB_CODENAME=([a-z]+)$</ind:pattern>
            <ind:instance datatype="int">1</ind:instance>
        </ind:textfilecontent54_object>"""

        test_obj = oval_lib.OvalGeneratorUSN.create_release_object(
            self.oval_gen_mock)

        assert test_obj == release_obj_mock

    def test_create_release_state(self):
        release_state_mock = """
        <ind:textfilecontent54_state id="oval:com.ubuntu.bionic:ste:100" version="1" comment="Ubuntu 18.04 LTS">
            <ind:subexpression datatype="string" operation="equals">bionic</ind:subexpression>
        </ind:textfilecontent54_state>"""

        test_state = oval_lib.OvalGeneratorUSN.create_release_state(
            self.oval_gen_mock)

        assert test_state == release_state_mock

    def test_open_nonexistent_cve(self):
        oval_gen_mock = MockOvalGeneratorUSN()

        cve_info = oval_lib.OvalGeneratorUSN.get_cve_info_from_file(
            oval_gen_mock, "CVE-DNE", rel_test_path)

        try:
            assert cve_info is None
        finally:
            oval_gen_mock.file_cleanup()

    @mock.patch("cve_lib.load_cve", autospec=True)
    def test_empty_cve_object(self, load_cve_mock):
        load_cve_mock.return_value = {}

        cve_info = oval_lib.OvalGeneratorUSN.get_cve_info_from_file(
            self.oval_gen_mock, self.test_cve_file, rel_test_path)

        assert cve_info is None

    def test_create_dict_from_cve_file(self):
        cve_dir = os.environ["UCT"]
        dst_cve_file = os.path.join(cve_dir, "active", self.test_cve_file)
        src_cve_file = os.path.join(rel_test_path, self.test_cve_file)
        copyfile(src_cve_file, dst_cve_file)
        corr_cve_info = {
                'Priority': 'high',
                'PublicDate': '2012-05-25',
                'Candidate': self.test_cve_file,
                'CVSS_SCORE': '9.8',
                'CVE_URL': 'https://ubuntu.com/security/CVE-TEST',
                'MITRE_URL': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-TEST',
                'CVSS': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'CVSS_SEVERITY_LEVEL': 'Critical'
        }

        cve_info = oval_lib.OvalGeneratorUSN.get_cve_info_from_file(
            self.oval_gen_mock, self.test_cve_file, cve_dir)

        try:
            assert cve_info == corr_cve_info
        finally:
            # cleanup
            if os.path.exists(dst_cve_file):
                os.remove(dst_cve_file)

            self.oval_gen_mock.file_cleanup()

    def test_get_vers_from_binaries(self):
        vers_map = oval_lib.OvalGeneratorUSN.get_version_from_binaries(
            self.oval_gen_mock, self.bin_mock)

        assert vers_map == self.bin_dict_mock

    def test_create_testref_dictionary(self):
        test_ref, _ = oval_lib.OvalGeneratorUSN.get_testref(
            self.oval_gen_mock, "5.0.0-1059.64", ['linux-image-5.0.0-1059-oem-osp1'],
            43881000000)

        assert test_ref == self.test_refs_mock[0]

    def test_filter_cves(self):
        test_urls, test_cves = oval_lib.OvalGeneratorUSN.filter_cves(
            self.oval_gen_mock, self.cves_url_both_mock)
        assert test_urls == self.urls_mock
        assert test_cves == self.cves_list_mock

    @mock.patch("oval_lib.OvalGeneratorUSN.filter_cves", autospec=True)
    @mock.patch("oval_lib.OvalGeneratorUSN.get_cve_info_from_file",
        autospec=True)
    def test_format_cves_info(self, cve_file_info_mock, filter_cves_mock):
        filter_cves_mock.return_value = [self.urls_mock, self.cves_list_mock]
        cve_file_info_mock.side_effect = self.cves_info_mock

        test_urls, test_cves_info = oval_lib.OvalGeneratorUSN.format_cves_info(
            self.oval_gen_mock, self.cves_url_both_mock, rel_test_path)

        assert test_cves_info == self.cves_info_mock
        assert test_urls == self.urls_mock

    def test_create_cves_references(self):
        refs_test = oval_lib.OvalGeneratorUSN.create_cves_references(
            self.oval_gen_mock, self.cves_info_mock)

        assert refs_test == self.references_mock

    @pytest.mark.parametrize("url,url_mock", [(urls_mock, url_ref_mock),
        (["https://bugs.launchpad.net/mahara/+bug/1836984"],
            "<bug>https://bugs.launchpad.net/mahara/+bug/1836984</bug>"),
        (["https://launchpad.net/bugs/1843533"],
            "<bug>https://launchpad.net/bugs/1843533</bug>")])
    def test_create_bug_references(self, url, url_mock):
        refs_test = oval_lib.OvalGeneratorUSN.create_bug_references(
            self.oval_gen_mock, url)

        assert refs_test == url_mock

    @pytest.mark.parametrize("mock_arg,mock_ret", [(cve_severity_mock,
        avg_severity_mock), (None,'None'), ([0,1,1,1,1,1], 'Medium'),
        ([1,1,0,0,0], 'Low'), ([1,2,3], "High")])
    def test_get_usn_severity(self, mock_arg, mock_ret):
        ret_test = oval_lib.OvalGeneratorUSN.get_usn_severity(
            self.oval_gen_mock, mock_arg)

        assert ret_test == mock_ret

    @mock.patch("oval_lib.OvalGeneratorUSN.format_cves_info", autospec=True)
    @mock.patch("oval_lib.OvalGeneratorUSN.create_cves_references",
        autospec=True)
    @mock.patch("oval_lib.OvalGeneratorUSN.create_bug_references",
        autospec=True)
    @mock.patch("oval_lib.OvalGeneratorUSN.get_usn_severity", autospec=True)
    def test_create_usn_definition(self, get_usn_severity_mock,
            create_bug_ref_mock, create_cve_ref_mock, format_cves_info_mock):
        format_cves_info_mock.return_value = (self.urls_mock,
            self.cves_info_mock)
        create_cve_ref_mock.return_value = self.references_mock
        create_bug_ref_mock.return_value = self.url_ref_mock
        get_usn_severity_mock.return_value = self.avg_severity_mock

        print(self.usn_object_mock)
        definition_ret = oval_lib.OvalGeneratorUSN.create_usn_definition(
            self.oval_gen_mock, self.usn_object_mock, self.usn_mock,
            self.id_base_mock, self.test_refs_mock, rel_test_path,
            self.instructions_mock)

        format_cves_info_mock.assert_called_with(self.oval_gen_mock,
            self.cves_url_both_mock, rel_test_path)
        create_cve_ref_mock.assert_called_with(self.oval_gen_mock,
            self.cves_info_mock)
        get_usn_severity_mock.assert_called_with(self.oval_gen_mock,
            self.cve_severity_mock)
        create_bug_ref_mock.assert_called_with(self.oval_gen_mock,
            self.urls_mock)

        assert definition_ret == self.definition_mock

    @mock.patch("oval_lib.OvalGeneratorUSN.format_cves_info", autospec=True)
    @mock.patch("oval_lib.OvalGeneratorUSN.create_cves_references",
        autospec=True)
    @mock.patch("oval_lib.OvalGeneratorUSN.create_bug_references",
        autospec=True)
    @mock.patch("oval_lib.OvalGeneratorUSN.get_usn_severity", autospec=True)
    def test_invalid_priority_usn_definition(self, get_usn_severity_mock,
            create_bug_ref_mock, create_cve_ref_mock, format_cves_info_mock):
        format_cves_info_mock.return_value = (self.urls_mock,
            self.invalid_priority_cve_mock)
        create_cve_ref_mock.return_value = self.invalid_priority_references_mock
        create_bug_ref_mock.return_value = self.url_ref_mock
        get_usn_severity_mock.return_value = self.avg_severity_mock

        definition_ret = oval_lib.OvalGeneratorUSN.create_usn_definition(
            self.oval_gen_mock, self.usn_object_mock, self.usn_mock,
            self.id_base_mock, self.test_refs_mock, rel_test_path,
            self.instructions_mock)

        assert definition_ret == self.invalid_priority_ret

    @pytest.mark.parametrize("oval_mock,test_ref,ret_mock",
                             [(oval_gen_mock, test_refs_mock[0], test_mock[0]),
                              (oval_gen_mock, test_refs_mock[1], test_mock[1]),
                              (oval_gen_mock_oci, test_refs_mock[0], test_oci_mock)])
    def test_create_usn_test(self, oval_mock, test_ref, ret_mock):
        test_ret = oval_lib.OvalGeneratorUSN.create_usn_test(oval_mock, test_ref)

        assert test_ret == ret_mock

    @pytest.mark.parametrize("oval_mock,usn_id,ret_mock",
                             [(oval_gen_mock, test_refs_mock[0], obj_mock[0]),
                              (oval_gen_mock_oci, test_refs_mock[0], obj_oci_mock)])
    def test_create_usn_obj(self, oval_mock, usn_id, ret_mock):
        test_ret = oval_lib.OvalGeneratorUSN.create_usn_object(oval_mock,
                usn_id)

        assert test_ret == ret_mock

    @pytest.mark.parametrize("oval_mock,args_mock,ret_mock",
                             [(oval_gen_mock, test_refs_mock[0], state_mock[0]),
                              (oval_gen_mock, {'version': "1:4.2-3ubuntu6.1",
                                               'testref_id': "437210000000"},
                                               state_epoch_mock),
                              (oval_gen_mock_oci, state_oci_args_mock[0], state_oci_mock)])
    def test_create_usn_state(self, oval_mock, args_mock, ret_mock):
        test_ret = oval_lib.OvalGeneratorUSN.create_usn_state(
            oval_mock, args_mock)

        assert test_ret == ret_mock

    @pytest.mark.parametrize("oval_mock,ret_mock", [(oval_gen_mock,
        var_mock[1]), (oval_gen_mock_oci, var_oci_mock)])
    def test_create_usn_var(self, oval_mock, ret_mock):
        test_ret = oval_lib.OvalGeneratorUSN.create_usn_variable(
            oval_mock, self.var_args_mock[1])

        assert test_ret == ret_mock

    @mock.patch("oval_lib.OvalGeneratorUSN.get_version_from_binaries",
        autospec=True)
    @mock.patch("oval_lib.OvalGeneratorUSN.get_testref", autospec=True)
    @mock.patch("oval_lib.OvalGeneratorUSN.create_usn_definition",
        autospec=True)
    @mock.patch("oval_lib.OvalGeneratorUSN.create_usn_test", autospec=True)
    @mock.patch("oval_lib.OvalGeneratorUSN.create_usn_object", autospec=True)
    @mock.patch("oval_lib.OvalGeneratorUSN.create_usn_state", autospec=True)
    @mock.patch("oval_lib.OvalGeneratorUSN.create_usn_variable", autospec=True)
    def test_generate_usn_oval(self, usn_var_mock, usn_state_mock,
            usn_obj_mock, usn_test_mock, usn_def_mock, testref_mock,
            binary_vers_mock):
        #Set up dummy vals
        oval_gen_mock = MockOvalGeneratorUSN()

        test_refs_id_calls = [mock.call(oval_gen_mock, self.test_refs_mock[0]),
                              mock.call(oval_gen_mock, self.test_refs_mock[1]),
                              mock.call(oval_gen_mock, self.test_refs_mock[2]),
                              mock.call(oval_gen_mock, self.test_refs_mock[3])]
        state_calls = [mock.call(oval_gen_mock, item)
            for item in self.state_args_mock]
        var_calls = [mock.call(oval_gen_mock, item)
            for item in self.var_args_mock]

        # mock return values
        binary_vers_mock.return_value = self.bin_vers_mock
        usn_def_mock.return_value = self.definition_mock
        usn_test_mock.side_effect = self.test_mock
        usn_obj_mock.side_effect = self.obj_mock
        usn_state_mock.side_effect = self.state_mock
        usn_var_mock.side_effect = self.var_mock
        testref_mock.side_effect = self.test_ref_mock

        oval_lib.OvalGeneratorUSN.generate_usn_oval(
            oval_gen_mock, self.usn_object_mock, self.usn_mock, rel_test_path)

        # assertions
        usn_def_mock.assert_called_with(
            oval_gen_mock, self.usn_object_mock, self.usn_mock,
            self.id_base_mock, self.test_refs_mock, rel_test_path,
            self.instructions_mock)
        usn_test_mock.assert_has_calls(test_refs_id_calls)
        usn_obj_mock.assert_has_calls(test_refs_id_calls)
        usn_state_mock.assert_has_calls(state_calls)
        usn_var_mock.assert_has_calls(var_calls)
        binary_vers_mock.assert_called_once_with(oval_gen_mock, self.bin_mock)

        oval_gen_mock.file_cleanup()

    @mock.patch("oval_lib.datetime")
    @mock.patch("oval_lib.shutil.move", autospec=True)
    def test_write_oval_elements(self, move_mock, datetime_mock):
        test_output_file = os.path.join(self.oval_gen_mock.tmpdir,
                self.oval_gen_mock.output_filepath)
        for elem in supported_oval_elements:
            copyfile("{}{}.xml".format(gold_oval_structure_path, elem),
                "{}{}.xml".format(rel_test_path, elem))

        datetime_mock.now = mock.Mock(
            return_value=datetime(2020, 4, 9, 6, 47, 58, tzinfo=timezone.utc)
        )

        oval_lib.OvalGeneratorUSN.write_oval_elements(self.oval_gen_mock)

        test_file = open(test_output_file, "r")
        gold_file = open("{}oval.xml".format(gold_oval_structure_path), "r")

        try:
            assert gold_file.read() == test_file.read()
        finally:
            # cleanup
            if os.path.exists(test_output_file):
                os.remove(test_output_file)
