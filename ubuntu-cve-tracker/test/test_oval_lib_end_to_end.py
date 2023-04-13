#!/usr/bin/python3

import pytest
import subprocess
from test_utils import TestUtilities as util
from test_utils import OVALType
class TestOvalLibEndToEnd:
    @pytest.mark.parametrize("output_file,oscap_args",
        [(util.focal_dpkg_file, ["--oval-release", "focal"]),
        (util.xenial_dpkg_file, ["--oval-release", "xenial"])])
    def test_validate_entire_dpkg_oval(self, output_file, oscap_args):
        """Coherence check of entire generated dpkg OVAL"""
        write_file = util.rel_test_path + output_file

        subprocess.check_output(["./scripts/generate-oval", "--usn-oval",
                "--output-dir={}".format(util.rel_test_path)] +  oscap_args,
                stderr=subprocess.STDOUT)

        subprocess.check_output(["oscap", "oval", "validate",
                write_file], stderr=subprocess.STDOUT)

        util.files_to_del.add(write_file)

    @pytest.mark.parametrize("dpkg_file,manifest,release",
         # The timestamped gold manifest oscap output has not been manually
         # checked but it's nice to flag changes to the results of past USNs
         [(util.bionic_dpkg_file, "bionic_20180814", "bionic"),
         (util.trusty_dpkg_file, "trusty_20191107", "trusty")])
    def test_validate_entire_oci_oval(self, dpkg_file, manifest, release):
        """Coherence check of entire generated oci OVAL"""
        util.create_validate_oci(dpkg_file, "{}_full".format(release),
            ["--oval-release", release], manifest, release, OVALType.USN)
