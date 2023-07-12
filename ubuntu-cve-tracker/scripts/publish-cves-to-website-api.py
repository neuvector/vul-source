#! /usr/bin/env python3
# Standard library
import os
import pprint
import sys
import cve_lib
import re
import argparse
from http.cookiejar import MozillaCookieJar

# Local
## from lib.file_helpers import JsonStore, download_gzip_file
from macaroonbakery import httpbakery

# Uncomment to debug https transactions
#import http
#http.client.HTTPConnection.debuglevel = 1


IGNORE_CACHE = os.path.expanduser("~/.publish-cves-ignore-cache")

def authentication(method, url, payload):
    """
    Authenticate with Macaroons in order to use Webteam API
    """

    client = httpbakery.Client(cookies=MozillaCookieJar(os.path.expanduser("~/.ubuntu.com.login")))

    if os.path.exists(client.cookies.filename):
        client.cookies.load(ignore_discard=True)

    response = client.request(method, url=url, json=payload)
    client.cookies.save(ignore_discard=True)
    return response

def get_codename(raw_codename, cve_releases):
    codename = raw_codename.split("/")[0]

    if codename != "devel":
        return codename

    return get_devel_codename(cve_releases)

def get_tags(cve_data):
    tags = {}
    for pkg in cve_data['tags']:
        tags[pkg] = []
        for tag in cve_data['tags'][pkg]:
            tags[pkg].append(tag)
    return tags

def get_patches(cve_data):
    patches = {}
    for pkg in cve_data['patches']:
        patches[pkg] = [patch_type + ": " + entry for patch_type, entry in cve_data['patches'].get(pkg)]
    return patches

def get_devel_codename(cve_releases):
    for skip_release in ['upstream', 'devel', 'product', 'snap']:
        if skip_release in cve_releases:
            cve_releases.remove(skip_release)

    if len(cve_releases) <= 0:
        print ("WARNING: No valid ubuntu releases in CVE", file=sys.stderr)
        return None

    cve_releases = cve_lib.release_sort(cve_releases)

    devel_release_index = cve_lib.releases.index(cve_releases[-1]) + 1
    if devel_release_index >= len(cve_lib.releases) or devel_release_index < 0:
        print (
            "WARNING: Could not determine devel release codename. Perhaps it hasn't "
            "been added to cve_lib.all_releases yet?",
            file=sys.stderr
        )
        return None

    cve_devel_release = cve_lib.releases[devel_release_index]

    return cve_devel_release


def post_single_cve(cve_filename):
    # Upload active and ignored (in Ubuntu)
    cve_data = cve_lib.load_cve(cve_filename)

    references = cve_data["References"].split("\n")
    if references[0] == "":
        references.pop(0)

    cvss3 = None
    impact = None
    if len(cve_data["CVSS"]) > 0:
        if "3." in cve_data["CVSS"][0]['vector']:
            # Use CVSS3
            try:
                impact = cve_lib.parse_cvss(cve_data["CVSS"][0]['vector'])
                cvss3 = impact['baseMetricV3']['cvssV3']['baseScore']
            except ValueError as e:
                print(
                    "%s: bad CVSS data %s, skipping: %s" % (cve_filename, cve_data["CVSS"][0]['vector'], e),
                    file=sys.stderr
                )
                cvss3 = None
                impact = None

    packages = []
    tags = get_tags(cve_data)
    patches = get_patches(cve_data)
    for pkg in cve_data["pkgs"]:
        statuses = []
        cve_releases = cve_data["pkgs"][pkg].keys()
        cve_releases = [rel for rel in cve_releases if rel in cve_lib.releases]

        for codename in cve_lib.releases + ["upstream"]:
            status = None
            pocket = "security"

            # Set the public release first
            if codename in cve_data["pkgs"][pkg]:
                status = cve_data["pkgs"][pkg][codename]

            if status and status[0] != "released" and codename in cve_lib.get_active_releases_with_esm():
                # Check for possible product statuses
                for release in [
                        codename + "/esm",
                        "esm-infra/" + codename,
                        "esm-apps/" + codename,
                        "ros-esm/" + codename,
                        codename]:
                    if release in cve_data["pkgs"][pkg]:
                        esm_status = cve_data["pkgs"][pkg][release]
                        # Use the ESM status if there is an ESM release or release is EOL
                        if esm_status[0] == "released" or codename in cve_lib.eol_releases:
                            if esm_status[0] == "released" and "esm" in release:
                                pocket = "esm-infra" if codename == "trusty" \
                                        else release.split("/")[0]
                            status = esm_status
                            break

            if status:
                statuses.append(
                    {
                        "release_codename": codename,
                        "status": status[0],
                        "description": status[1],
                        "pocket": pocket,
                    }
                )
        package = {
            "name": pkg,
            "source": f"https://launchpad.net/ubuntu/+source/{pkg}",
            "ubuntu": f"https://packages.ubuntu.com/search?suite=all&section=all&arch=any&searchon=sourcenames&keywords={pkg}",
            "debian": f"https://tracker.debian.org/pkg/{pkg}",
            "statuses": statuses,
        }
        packages.append(package)

    status = "active"

    if "** REJECT **" in cve_data["Description"]:
        status = "rejected"

    notes = []

    for [author, note] in cve_data["Notes"]:
        notes.append({"author": author, "note": note})

    priority = cve_data["Priority"][0]

    if priority == "untriaged":
        priority = "unknown"

    cve = {
        "id": cve_data["Candidate"],
        "description": cve_data["Description"],
        "ubuntu_description": cve_data["Ubuntu-Description"],
        # plenty of CVEs in retired/ do not have a Mitigation section at all
        "mitigation": cve_data.get("Mitigation", ""),
        "notes": notes,
        "priority": priority,
        "cvss3": cvss3,  # CVSS3 computed base score
        "references": references,
        "bugs": cve_data["Bugs"].strip().split("\n"),
        "packages": packages,
        "status": status,
        "tags": tags,
        "patches": patches,
    }

    if impact:
        cve["impact"] = impact # Full CVSS3 base vector structure

    if cve_data["PublicDate"] != "unknown":
        cve["published"] = cve_data["PublicDate"]

    return cve

def load_ignore_cache():
    ignore_cache = set()
    with open(IGNORE_CACHE) as ic:
        for cve in ic:
            ignore_cache.add(cve.strip())

    return ignore_cache

def add_cve_to_ignore_cache(cve_id):
    with open(IGNORE_CACHE, "at") as ic:
        ic.write(cve_id + "\n")


OK_REGEX = re.compile(r'^<Response \[2..\]>$')
security_website_endpoint = "cves.json"

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="This file loads CVEs to webteam's db, using the endpoint ubuntu.com/security/cve",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-n", "--dry-run", action="store_true", default=False,
        help="Simulate, don't actually push to webteams db.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False,
        help="Print details of data sent to the webteams db.",
    )
    parser.add_argument(
        "--stop", action="store_true",
        help="Exit after non-200 status.",
    )
    parser.add_argument(
        "--chunksize", action="store",
        type=int,
        help="Number of CVEs to submit in each block",
        default=25,
    )
    parser.add_argument(
        "--ignore-filename-check", action="store_false",
        help="Ignore if the file name isn't in the CVE-YYYY-NNNNN format",
        dest="filename_check",
        default=True
    )
    parser.add_argument(
        "--endpoint",
        action="store",
        type=str,
        default="https://ubuntu.com/security/",
        help="API endpoint url.",
    )
    parser.add_argument(
        "file_path",
        action="store",
        type=str,
        nargs="+",
        help="[Required] The path of the CVE file(s) or folder(s)",
    )
    args = parser.parse_args(argv)

    ## if args:
    ## headers = {"Content-type": "application/json"}
    cves = []
    CVE_filename_regex = re.compile(".*/?CVE-\\d{4}-\\d{4,7}$" if args.filename_check else ".*")
    NFU_filename_regex = re.compile(".*/not-for-us.txt$")
    ignore_paths = ['experimental', 'subprojects', 'scripts']
    cache_not_for_us_cve_ids = list()

    for cve_filename in args.file_path:

        if os.path.isdir(cve_filename):
            list_cve_files = []
            # Note os.listdir gives unsorted list depending on filestystem
            for file in os.listdir(cve_filename):
                print(file)
                if re.match(CVE_filename_regex, file):
                    list_cve_files.append(file)

            list_cves = sorted(list_cve_files)
            print(f"Processing {len(list_cves)} in '{cve_filename}' directory")
            for index in range(len(list_cves)):
                relative_path = f"{cve_filename}/{list_cves[index]}"
                cve = post_single_cve(relative_path)
                cves.append(cve)

        elif re.match(NFU_filename_regex, cve_filename):
            ignore_cache = load_ignore_cache()

            not_for_us_cve_ids = cve_lib.parse_CVEs_from_uri(cve_filename)
            print(f"Processing {len(not_for_us_cve_ids)} from '{cve_filename}' as not for us")

            cache_not_for_us_cve_ids = [cve_id for cve_id in not_for_us_cve_ids if cve_id not in ignore_cache]
            print(f"{len(cache_not_for_us_cve_ids)} not-for-us CVEs have not yet been processed")

            for cve_id in cache_not_for_us_cve_ids:
                cves.append(
                    {
                        "id": cve_id,
                        "notes": [
                            {
                                "author": "ubuntu-security",
                                "note": "Does not apply to software found in Ubuntu.",
                            }
                        ],
                        "references": [
                            f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
                            ],
                        "status": "not-in-ubuntu",
                    }
                )

        elif any(x in cve_filename for x in ignore_paths):
            print(f"skipping {cve_filename}")
            continue

        elif re.match(CVE_filename_regex, cve_filename) and os.path.isfile(cve_filename):
            ## print(f"Processing '{cve_filename}' as single CVE file")
            cve = post_single_cve(cve_filename)
            cves.append(cve)

        else:
            print(f"'{cve_filename}' is not a CVE file. Skipping...")

    print(f"{len(cves)} total CVEs")

    # Split into chunks
    chunksize = args.chunksize
    for chunk in [
        cves[i : i + chunksize] for i in range(0, len(cves), chunksize)  # noqa: E203
    ]:
        push_chunks(args, args.endpoint, chunk)

    for cve_id in cache_not_for_us_cve_ids:
        add_cve_to_ignore_cache(cve_id)

    return cves

def push_chunks(args, url, chunk):
    if args.verbose:
        pprint.pprint(chunk)
    if args.dry_run:
        return
    resp = authentication("PUT", f"{url}{security_website_endpoint}", chunk)
    print(resp, str(resp.text).rstrip()[0:4096])
    if args.stop and not OK_REGEX.match(str(resp)):
        print("CHUNK FAILED")
        pprint.pprint(chunk)
        sys.exit(1)

def push_individual_cves(args, url, chunk):
    for cve in chunk:
        if args.verbose:
            pprint.pprint(cve)
        if args.dry_run:
            continue
        resp = authentication("PUT", f"{url}{security_website_endpoint}", [cve])
        print(resp, str(resp.text).rstrip()[0:4096])
        if args.stop and not OK_REGEX.match(str(resp)):
            print("CVE FAILED")
            pprint.pprint(cve)
            sys.exit(1)

if __name__ == "__main__":
    main()
