#!/usr/bin/env pytest

import pytest
import source_map
import cve_lib
import mock

mock_subprojects = {
    "esm-foo/bar": {
        "eol": False,
        "oval": False,
        "components": ["main", "restricted"],
        "packages": ["test/esm-fake-supported.txt"],
        "name": "Ubuntu 01.01 ESM",
        "codename": "Fabulous Fake",
        "ppas": [{"ppa": "ubuntu-esm/esm-bar-security/ubuntu", "pocket": "main"}],
        "parent": "ubuntu/bar",
        "description": "Available with Ubuntu Pro: https://ubuntu.com/pro",
        "stamp": 1618963200,
    }
}

class TestSubprojects:
    @mock.patch("cve_lib.subprojects", mock_subprojects)
    @mock.patch("source_map._find_sources")
    def test_load_subproject_supported(self, _find_sources_mock):
        _find_sources_mock.return_value = []
        map = source_map.load(releases=['esm-foo/bar'])
        assert set(map['esm-foo/bar'].keys()) == set(['foo', 'bar'])

    @pytest.mark.parametrize("release", cve_lib.get_active_esm_releases())
    @mock.patch("source_map._find_sources")
    def test_subproject_esm(self, _find_sources_mock, release):
        _find_sources_mock.return_value = []
        packages = []

        if release not in cve_lib.subprojects:
            for rel in cve_lib.subprojects:
                if 'alias' in cve_lib.subprojects[rel] and \
                cve_lib.subprojects[rel]['alias'] == release:
                    release = rel
                    break

        for package_input_file in cve_lib.subprojects[release]['packages']:
            with open(package_input_file) as data:
                packages += data.read().splitlines()

        packages_clean = set()
        for package in packages:
            package = package.split('#', maxsplit=1)[0].strip()
            if package:
                packages_clean.add(package)

        map = source_map.load(releases=[release])
        assert set(map[release].keys()) == packages_clean