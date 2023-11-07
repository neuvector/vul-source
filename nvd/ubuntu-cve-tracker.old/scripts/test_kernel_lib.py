#!/usr/bin/env pytest-3
# -*- coding: utf-8 -*-
#
# Author: Steve Beattie <sbeattie@ubuntu.com>
# Copyright (C) 2020 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# Simple tests for kernel_lib

import pytest
from kernel_lib import (
    kernel_meta_abi,
    kernel_package_abi,
    kernel_package_version,
    convert_name_to_meta,
    convert_name_to_signed,
)


class TestKernelMabiCalc:
    def test_basic_version(self):
        assert kernel_meta_abi("5.4.0.40.44") == 40

    def test_hwe_version(self):
        assert kernel_meta_abi("5.4.0.40.44~18.04.32") == 40


class TestKernelVersionCalc:
    def test_basic_version(self):
        assert kernel_package_version("4.15.0-45.54") == "4.15.0"

    def test_hwe_version(self):
        assert kernel_package_version("5.4.0-40.44~18.04.32") == "5.4.0"


class TestKernelABICalc:
    def test_basic_version(self):
        assert kernel_package_abi("4.15.0-45.54") == 45

    def test_hwe_version(self):
        assert kernel_package_abi("5.4.0-40.44~18.04.32") == 40


class TestKernelComputeMetaName:
    def test_basic_kernel(self):
        assert convert_name_to_meta("linux") == "linux-meta"

    def test_hwe_kernel(self):
        assert convert_name_to_meta("linux-hwe") == "linux-meta-hwe"

    def test_hwe_versioned_kernel(self):
        assert convert_name_to_meta("linux-hwe-5.4") == "linux-meta-hwe-5.4"

    def test_bad_kernel_name(self):
        with pytest.raises(ValueError):
            convert_name_to_meta("not-linux")


class TestKernelComputeSignedName:
    def test_basic_kernel(self):
        assert convert_name_to_signed("linux") == "linux-signed"

    def test_hwe_kernel(self):
        assert convert_name_to_signed("linux-hwe") == "linux-signed-hwe"

    def test_hwe_versioned_kernel(self):
        assert convert_name_to_signed("linux-hwe-5.4") == "linux-signed-hwe-5.4"

    def test_bad_kernel_name(self):
        with pytest.raises(ValueError):
            convert_name_to_signed("not-linux")
