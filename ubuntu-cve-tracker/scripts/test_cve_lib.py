#!/usr/bin/env pytest-3

import datetime
import json
import os
import pytest
import sys
import cve_lib

def pytest_generate_tests(metafunc):
    if "cvss" in metafunc.fixturenames:
        cvss = {}
        nvdcves = ['recent'] + \
            [str(year) for year in range(2004, int(datetime.datetime.now().year))]
        for nvdcve in nvdcves:
            nvdjson = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                   '..', 'nvdcve-1.1-%s.json' % nvdcve)
            try:
                with open(nvdjson) as fp:
                    js = json.load(fp)
                    for cve in js["CVE_Items"]:
                        if "baseMetricV3" in cve["impact"] \
                           and  cve["impact"]["baseMetricV3"]["cvssV3"]["vectorString"] not in cvss:
                            # only test each vectorString once
                            cvss[cve["impact"]["baseMetricV3"]["cvssV3"]["vectorString"]] = cve["impact"]
            except FileNotFoundError:
                print("Failed to find %s to generate test cases..." % nvdjson, file=sys.stderr)
        metafunc.parametrize("cvss", [item for _, item in cvss.items()])

def test_cvss_empty():
    with pytest.raises(ValueError):
        cve_lib.parse_cvss('')

def test_cvss_none():
    with pytest.raises(ValueError):
        cve_lib.parse_cvss(None)

def test_cvss(cvss):
    # hack around the fact that some cvssV3 entries use the cvssV2
    # ADJACENT_NETWORK attackVector which is wrong...
    if cvss["baseMetricV3"]["cvssV3"]["attackVector"] == "ADJACENT_NETWORK":
       cvss["baseMetricV3"]["cvssV3"]["attackVector"] = "ADJACENT"
    js = cve_lib.parse_cvss(cvss["baseMetricV3"]["cvssV3"]["vectorString"])
    # the existing impact may contain a baseMetricV2 or others so only
    # compare CVSS3
    assert(js["baseMetricV3"] == cvss["baseMetricV3"])


class TestPackageOverrideTests:
    def test_get_title_none(self):
        assert cve_lib.lookup_package_override_title('no-such-package') is None

    def test_get_title_linux(self):
        assert cve_lib.lookup_package_override_title('linux') == 'Linux kernel'

    def test_get_desc_none(self):
        assert cve_lib.lookup_package_override_description('no-such-package') is None

    def test_get_desc_linux(self):
        assert cve_lib.lookup_package_override_description('linux') == 'Linux kernel'

    # XXX add a test to validate that all the package description
    # XXX override entries have both a non-empty title and description.


TEST_DATA_DIR = "test/"

# these are tests located in the 'okay' subdirectory that
# cve_lib should successfully parse and return a data structure. A
# corresponding json file is needed in test/good/ that contains the
# resulting structure is needed to compare against.
PARSE_OKAY_TESTS = [
    "priority-negligible", "priority-low", "priority-medium",
    "priority-high", "priority-critical", "priority-untriaged",
    'cve-id-NNNN', 'cve-id-N7',
    "patches-missing-1", "patches-missing-2", "patches-missing-3",
    "patches-missing-4",
]

# these are tests located the 'bad' subdirectory that cve_lib should
# detect have a problem or are invalid in some way and should raise
# an exception.
PARSE_ERROR_TESTS = [
    'priority-invalid-value', 'candidate-missing', 'candidate-bad-id',
    'priority-missing', 'cvss-missing',
]


class TestParseCVEFiles:

    def test_file_not_exist(self):
        with pytest.raises(ValueError):
            cve_lib.load_cve(os.path.join(TEST_DATA_DIR, "okay/does-not-exist"))

    def __check_simple_okay(self, cve_test_file, use_strict=False):
        _test_file = os.path.join(TEST_DATA_DIR, "okay", cve_test_file)
        assert os.path.exists(_test_file)
        cve = cve_lib.load_cve(_test_file, strict=use_strict)
        assert cve is not None
        with open("%s.json" % _test_file, "rt") as f:
            cve_json = json.load(f)
        assert cve_json is not None
        assert cve == cve_json

    @pytest.mark.parametrize("cve_test_file", PARSE_OKAY_TESTS)
    def test_simple_okay(self, cve_test_file):
        self.__check_simple_okay(cve_test_file, use_strict=False)

    @pytest.mark.parametrize("cve_test_file", PARSE_OKAY_TESTS)
    def test_simple_okay_strict(self, cve_test_file):
        self.__check_simple_okay(cve_test_file, use_strict=True)

    @pytest.mark.parametrize("cve_test_file", PARSE_ERROR_TESTS)
    def test_cve_parse_error(self, cve_test_file):
        _test_file = os.path.join(TEST_DATA_DIR, "bad", cve_test_file)
        assert os.path.exists(_test_file)
        with pytest.raises(ValueError):
            _ = cve_lib.load_cve(_test_file, strict=True)

    def test_cve_missing_cvss_score_and_severity(self):
        cve = cve_lib.load_cve(os.path.join(TEST_DATA_DIR, 'bad/cvss-vector-only'), strict=True)
        with pytest.raises(KeyError):
            cve['CVSS'][0]['baseScore']

    def test_cve_missing_cvss_score(self):
        cve = cve_lib.load_cve(os.path.join(TEST_DATA_DIR, 'bad/cvss-score-missing'), strict=True)
        with pytest.raises(KeyError):
            cve['CVSS'][0]['baseScore']

    def test_cve_missing_cvss_severity(self):
        cve = cve_lib.load_cve(os.path.join(TEST_DATA_DIR, 'bad/cvss-severity-missing'), strict=True)
        with pytest.raises(KeyError):
            cve['CVSS'][0]['baseSeverity']

    def test_cve_wrong_cvss_score(self):
        cve = cve_lib.load_cve(os.path.join(TEST_DATA_DIR, 'bad/cvss-wrong-score'), strict=True)
        js = cve_lib.parse_cvss(cve['CVSS'][0]['vector'])
        with pytest.raises(AssertionError):
            assert cve['CVSS'][0]['baseScore'] == js['baseMetricV3']['cvssV3']['baseScore']

    def test_cve_wrong_cvss_severity(self):
        cve = cve_lib.load_cve(os.path.join(TEST_DATA_DIR, 'bad/cvss-wrong-severity'), strict=True)
        js = cve_lib.parse_cvss(cve['CVSS'][0]['vector'])
        with pytest.raises(AssertionError):
            assert cve['CVSS'][0]['baseSeverity'] == js['baseMetricV3']['cvssV3']['baseSeverity']

    def test_all_cves(self):
        (cves, uems, rcves) = cve_lib.get_cve_list_and_retired()
        table = cve_lib.load_all(cves, uems, rcves)
        for cve in sorted(cves):
            cvss = table[cve]['CVSS']
            if cvss:
                js = cve_lib.parse_cvss(cvss[0]['vector'])
                assert cvss[0]['baseScore'] == str(js['baseMetricV3']['cvssV3']['baseScore'])
                assert cvss[0]['baseSeverity'] == js['baseMetricV3']['cvssV3']['baseSeverity']
