#!/usr/bin/python3

import pytest
from test_utils import TestUtilities as util
from test_utils import OVALType
class TestOvalLibFunctional:
    @pytest.mark.parametrize("manifest",
        # Only one of the binaries in manifest and it is vulnerable
        [("focal_mock_4410_vul_one"),
        # All binaries in manifest and only one is vulnerable
        ("focal_mock_4410_vul_all")])
    def test_multiple_binary_package(self, manifest):
        """Test a package with multiple binaries"""
        util.create_validate_oci(util.focal_dpkg_file, "focal_4410",
            ["--usn-number", "4410-1", "--oval-release", "focal"],
            manifest, "focal_mock_4410_vul", OVALType.USN)

    @pytest.mark.parametrize("manifest",
        # Binary is in manifest and not vulnerable  
        [("bionic_mock_3642_not_vul"),
        # Binary is in manifest and vulnerable 
        ("bionic_mock_3642_vul")])
    def test_single_binary_package(self, manifest):
        """Test a package with a single binary"""
        util.create_validate_oci(util.bionic_dpkg_file, "bionic_3642",
            ["--usn-number", "3642-1", "--oval-release", "bionic"],
            manifest, manifest, OVALType.USN)

    @pytest.mark.parametrize("manifest",
        # Only one of the packages is in manifest, which is vulnerable
        [("bionic_mock_4428_vul_one"),
        # Both packages are in manifest, of which one is vulnerable
        ("bionic_mock_4428_vul_all")])
    def test_multiple_packages_usn(self, manifest):
        """Test USN with multiple source packages"""
        util.create_validate_oci(util.bionic_dpkg_file, "bionic_4428",
            ["--usn-number", "4428-1", "--oval-release", "bionic"],
            manifest, "bionic_mock_4428", OVALType.USN)

    @pytest.mark.parametrize("manifest,gold_file,usn",
        # USN epoch 1 and manifest epoch 0 vulnerable
        [("focal_mock_4361_vul_epoch_0", "focal_mock_4361_vul", "4361-1"),
        # manifest epoch 1 only not vulnerable due to USN epoch 0
        ("focal_mock_4408", "focal_mock_4408", "4408-1"),
        # USN epoch 1 and manifest epoch 1 vulnerable
        ("focal_mock_4361_vul_epoch_1", "focal_mock_4361_vul", "4361-1"),
        # USN epoch 1 and manifest epoch 1 not vulnerable
        ("focal_mock_4361_not_vul", "focal_mock_4361_not_vul", "4361-1"),
        # USN epoch 1 is not vulnerable because it is not in manifest
        ("not_installed_pkg", "focal_mock_4361_not_vul", "4361-1"),
        # manifest epoch 0 is vulnerable only due to USN epoch of 2
        ("focal_mock_4381_vul_epoch_0", "focal_mock_4381_vul", "4381-1"),
        # manifest epoch 1 vulnerable only due to USN epoch of 2
        ("focal_mock_4381_vul_epoch_1", "focal_mock_4381_vul", "4381-1"),
        # USN with epoch 2 and manifest epoch 1 vulnerable
        ("focal_mock_4381_vul_epoch_2", "focal_mock_4381_vul", "4381-1"),
        # USN epoch 2 is not vulnerable because it is not in manifest
        ("not_installed_pkg", "focal_mock_4381_not_vul", "4381-1"),
        # manifest epoch 2 not vulnerable with USN epoch 2
        ("focal_mock_4381_not_vul_epoch_2", "focal_mock_4381_not_vul",
            "4381-1"),
        # manifest epoch 2 not vulnerable with USN epoch 1
        ("focal_mock_4361_not_vul_epoch_2", "focal_mock_4361_not_vul",
            "4361-1"),
        # manifest epoch 2 not vulnerable with USN epoch 0
        ("focal_mock_4441_not_vul_epoch_2", "focal_mock_4441_not_vul",
            "4441-1")])
    def test_epoch(self, manifest, gold_file, usn):
        """Test epochs are used correctly in vulnerability assesments"""
        util.create_validate_oci(util.focal_dpkg_file, "focal_{}".format(usn),
            ["--usn-number", usn, "--oval-release", "focal"], manifest,
            gold_file, OVALType.USN)


