#!/usr/bin/python3

import os
import sys
import subprocess
from enum import Enum

class OVALType(Enum):
    USN = '--usn-oval'
    CVE = ''
    PKG = '--pkg-oval'

class TestUtilities:
    cwd = os.getcwd()
    rel_test_path = cwd + "/test/"

    bionic_dpkg_file = "com.ubuntu.bionic.usn.oval.xml"
    trusty_dpkg_file = "com.ubuntu.trusty.usn.oval.xml"
    focal_dpkg_file = "com.ubuntu.focal.usn.oval.xml"
    xenial_dpkg_file = "com.ubuntu.xenial.usn.oval.xml"

    files_to_del = { rel_test_path + bionic_dpkg_file, rel_test_path +
        trusty_dpkg_file, rel_test_path + focal_dpkg_file, rel_test_path +
        xenial_dpkg_file }

    @classmethod
    def create_validate_oci(cls, output_file, new_filename, oscap_args,
            manifest, gold_file, type: OVALType):
        """Generate and validate oci and dpkg oval XML files for a single Ubuntu
        release"""

        new_file = cls.rel_test_path + new_filename

        # generate-oval creates files with identical names per-release
        # This setup allows running multiple tests on the same OVAL file
        # (without regenerating an identical oval) then creating a new OVAL
        # with an identical name and different content for following tests
        # so the OVAL is generated only as needed (less frequently than
        # every test run, more frequently than once per module)
        if not os.path.exists(new_file):
            dpkg_file = cls.rel_test_path + output_file
            oci_file = cls.rel_test_path + "oci." + output_file

            # Generate OVAL
            if sys.version_info[0] < 3:
                pycov = "python-coverage"
            else:
                pycov = "python3-coverage"
            subprocess.check_output([pycov, "run", "-a",
                                     "scripts/generate-oval", "--oci", type.value,
                                     "--output-dir={}".format(cls.rel_test_path)] + oscap_args)

            # Validate file structure
            subprocess.check_output(["oscap", "oval", "validate",
                                    dpkg_file], stderr=subprocess.STDOUT)

            subprocess.check_output(["oscap", "oval", "validate",
                                    oci_file], stderr=subprocess.STDOUT)

            os.rename(oci_file, new_file)

            cls.files_to_del.update([new_file, dpkg_file])

        # Test the oci XML file against a manifest
        manifest_dir = cls.rel_test_path + "manifests/" + manifest + "/"
        cmd_output = subprocess.check_output(["oscap", "oval", "eval",
            new_file], stderr=subprocess.STDOUT, cwd=manifest_dir)
        # Convert to str for py 3 compatibility
        cmd_output = cmd_output.decode("utf-8")

        # Compare output to expected
        with open(cls.rel_test_path + "gold_oci_results/" + gold_file) as f:
            gold_output = f.readlines()

        for line in gold_output:
            assert(line in cmd_output)
