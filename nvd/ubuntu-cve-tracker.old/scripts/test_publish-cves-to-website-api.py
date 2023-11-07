#!/usr/bin/env pytest-3

# Dependencies: python3-macaroonbakery

import pytest
import json
import os
import importlib
publish_cves = importlib.import_module("publish-cves-to-website-api")

TEST_DATA_DIR = "test"
PARSE_OKAY_TESTS = [f for f in os.listdir("test/website_api") \
        if f.startswith("use_") and not f.endswith(".json")]

class TestWebSiteAPI:
    def __check_simple_okay(self, cve_test_file):
        _test_file = os.path.join(TEST_DATA_DIR, "website_api", cve_test_file)
        assert os.path.exists(_test_file)
        payload = publish_cves.main(['--dry-run', '--ignore-filename-check', _test_file])
        assert payload is not None
        with open("%s.json" % _test_file, "rt") as f:
            payload_json = json.load(f)
        assert payload_json is not None
        assert payload == payload_json

    @pytest.mark.parametrize("cve_test_file", PARSE_OKAY_TESTS)
    def test_simple_okay(self, cve_test_file):
        self.__check_simple_okay(cve_test_file)
