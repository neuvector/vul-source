#!/usr/bin/env python3

"""
verify the schema of a cve-json5 and cve-json5-api files
set --debug to check cve-json5-api before CNA publication

$ ./scripts/cve_verify_json5.py $PATH_TO_JSON

nb: a cve-json5-api file is a subset of cve-json5 and
    required to interact with the API for CNAs

Copyright 2023, Canonical Ltd.
Author: Mark Esler <mark.esler@canonical.com>
"""


import argparse
import inspect
import json
import pathlib
import sys
from typing import Tuple

import jsonschema


def debug(msg: str) -> None:
    """print to stderr"""
    print("DEBUG: " + msg, file=sys.stderr)


def load_json(path: pathlib.Path) -> dict:
    """loads generic ascii json files"""
    # NOTE: all files *should* be ascii encoding
    #       https://github.com/CVEProject/cvelistV5/issues/25
    # pylint: disable=unspecified-encoding
    with open(path) as j:
        data = json.load(j)
    return data


def load_schema(path: pathlib.Path) -> Tuple[dict, dict]:
    """returns json schemas"""
    json5_schema = load_json(path)
    json5_schema_cna = json5_schema["definitions"]["cnaPublishedContainer"]["properties"]
    return json5_schema, json5_schema_cna


def debug_cve_json5_api_affected() -> bool:
    """
    tests cve["affected"] for CVE Project requirements

    debug relies on inspect.trace to write messages
    if a "pointless-statement" fails, trace prints

    function returns True or False depending if API compliant
    """
    passed = True
    try:
        # check if set
        # pylint: disable=pointless-statement
        cve["affected"]
        # check if set but false
        if not cve["affected"]:
            debug('cve["affected"] is empty')
            raise ValueError
        try:
            # in case of multiple packages, check each package
            # first check is cve["affected"][0]["versions"][0]["status"]
            for i in cve["affected"]:
                if not i["versions"]:
                    debug('cve["affected"]{["versions"]} is empty')
                    raise ValueError
                try:
                    for j in i["versions"]:
                        # pylint: disable=pointless-statement
                        j["status"]
                # pylint: disable=bare-except
                except:
                    passed = False
                    debug('cve["affected"]{["versions"]{["status"}} is missing:')
                    debug(str(inspect.trace()[-1][0].f_locals["j"]))
        # pylint: disable=bare-except
        except:
            passed = False
            debug(f'cve["affected"]{["versions"]} information is missing:')
            debug(str(inspect.trace()[-1][0].f_locals["i"]))
    # pylint: disable=bare-except
    except:
        passed = False
        debug('cve["affected"] does not exist or is empty')
    return passed


def debug_cve_json5_api_metrics() -> None:
    """
    tests cve["metrics"] for CVE Project requirements

    debug relies on inspect.trace to write messages
    if a "pointless-statement" fails, trace prints

    function returns True or False depending if API compliant
    """
    passed = True
    try:
        # pylint: disable=pointless-statement
        cve["metrics"]
        if not cve["metrics"]:
            debug('cve["metrics"] is empty')
            raise ValueError
        try:
            for i in cve["metrics"]:
                if not i["cvssV3_1"]["vectorString"]:
                    debug('cve["metrics"]{["cvssV3_1"]["vectorString"]} is empty')
                    raise ValueError
        # pylint: disable=bare-except
        except:
            passed = False
            debug('cve["metrics"]{["cssV3_1"]["vectorString"]} information is missing:')
            debug(str(inspect.trace()[-1][0].f_locals["i"]))
    # pylint: disable=bare-except
    except:
        passed = False
        debug('cve["metrics"] does not exist or is empty')
    return passed


def debug_cve_json5_api() -> bool:
    """tests fields which the CVE Project requires"""
    return debug_cve_json5_api_affected() and debug_cve_json5_api_metrics


def verify_cve_json5() -> bool:
    """verify cve-json5"""
    return jsonschema.Draft7Validator(schema).is_valid(cve)


def verify_cve_json5_api() -> bool:
    """
    verify cve-json5-api and optionally check for publication

    --debug is required to check API compiance
    """
    if jsonschema.Draft7Validator(schema_cna).is_valid(cve):
        if DEBUG:
            #NOTE: a cve_json5_api file can have a valid syntax, but not be
            #      ready for publication if information is missing
            if debug_cve_json5_api():
                debug("ready for CNA publication")
            else:
                debug("not ready for CNA publication")
        # note: the json5 can be valid, but not API compliant
        #       --debug required for API compliance
        return True
    return False


def verify() -> None:
    """check if file is a valid cve-json5 type"""
    if verify_cve_json5():
        if DEBUG:
            debug(f"{cve_file} is a valid cve-json5 file")
        sys.exit(0)
    elif verify_cve_json5_api():
        if DEBUG:
            debug(f"{cve_file} is a valid cve-json5-api file")
        sys.exit(0)
    else:
        raise TypeError(f"{cve_file} is NOT a valid cve-json5 or cve-json5-api file")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="cve-verify")
    parser.add_argument("cve_json5_paths", nargs="+", type=pathlib.Path)
    parser.add_argument("--debug", help="add debug info, required for API check", action="store_true")
    cve_files = parser.parse_args().cve_json5_paths
    DEBUG = parser.parse_args().debug

    uct_path = pathlib.Path(__file__).resolve().parent.parent
    schema_path = uct_path.joinpath("./scripts/cve-json5-schema.json")
    schema, schema_cna = load_schema(schema_path)

    for cve_file in cve_files:
        cve = load_json(cve_file)
        verify()
