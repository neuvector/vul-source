#!/usr/bin/env python3

import cve_lib
import os
import pickle
import argparse

PICKLE_FILE="/tmp/ignored_eol_releases.pickle"

parser = argparse.ArgumentParser(
        description="Check for EOL releases and change the status to ignored for them")
parser.add_argument("-v", "--verbose", dest="verbose", default=False,
        action="store_true", help="verbose prints")
parser.add_argument("-n", "--dry-run", dest="dry_run", default=False,
        action="store_true", help="do no run")
parser.add_argument("-c", "--cache", dest="cache", default=False,
        action="store_true", help="use cache")
args = parser.parse_args()

if args.cache and os.path.exists(PICKLE_FILE):
    table, cves, rcves = pickle.load(open(PICKLE_FILE, "rb"))
else:
    cves, uems, rcves = cve_lib.get_cve_list_and_retired()
    table = cve_lib.load_all(cves, uems, rcves)
    if args.cache:
        pickle.dump([table, cves, rcves], open(PICKLE_FILE, "wb"))

for cve in cves + rcves:
    filepath = cve_lib.find_cve(cve)
    for pkg in table[cve]["pkgs"]:
        for rel in table[cve]["pkgs"][pkg]:
            state, details = table[cve]["pkgs"][pkg][rel]
            if rel in cve_lib.eol_releases and state == "needed":
                # details = f"end of standard support, was {state} [{details}]"
                details = "end of standard support"
                state = "ignored"
                if args.verbose:
                    print(f"{cve} {pkg} {rel} {state} {details}")
                if not args.dry_run:
                    cve_lib.update_state(filepath, pkg, rel, state, details)
