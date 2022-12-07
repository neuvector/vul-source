#! /usr/bin/env python3
# imported from https://github.com/canonical-web-and-design/ubuntu.com/blob/master/webapp/security/fixtures/usns.py
# this is called by scripts/publish-usn-to-website as per step 8 on the wiki
# https://wiki.ubuntu.com/SecurityTeam/UpdatePublication#Announce_Publication
#
# initial upload of all USNs can be done as follows
# cd $UCT && ./scripts/fetch-db database.pickle.bz2
# ./scripts/convert-pickle.py --input database.pickle --output database.json --prefix 'USN-'
# ./scripts/publish-usn-to-website-api.py --json ./database.json --action add
#
# to test with a single USN you can use these commands:
# export USN-9999
# ../usn-tool/usn.py --db database.pickle --export-json $USN > $USN.json
# ./scripts/publish-usn-to-website-api.py --prefix "USN-" --action add --json $USN.json


# Standard library
import argparse
import json
import sys
import os
import re
from datetime import datetime
from http.cookiejar import MozillaCookieJar

# Packages
from macaroonbakery import httpbakery

# These are the pockets of packages that are published to the main
# ubuntu archive, and thus have publicly visible versions in launchpad.
# Packages published in pockets not in this list are (currently?)
# published in private ppas and thus do not have a publicly visible
# versioned URL.
ARCHIVE_POCKETS = ['security', 'updates']

def authentication(method, url, payload):
    """
    Authenticate with Macaroons in order to use Webteam API
    """

    client = httpbakery.Client(
        cookies=MozillaCookieJar(
            os.path.join(os.path.expanduser("~"), ".ubuntu.com.login")
        )
    )

    if os.path.exists(client.cookies.filename):
        client.cookies.load(ignore_discard=True)

    response = client.request(method, url=url, json=payload)
    client.cookies.save(ignore_discard=True)
    return response


def guess_binary_links(binary, info, sources):
    """Guess links to the source package based on binary package and version.
    Keyword Arguments:
    binary -- the name of the binary
    info -- dict containing the version and possibly the source name for the binary
    sources -- a dictionary of source package names to source package versions
    """
    match_first = False
    source_match = None
    version_match = None
    source_link = None
    version_link = None

    if not sources:
        # Old USNs may not have any sources listed. We can't make any sort of a
        # guess in this situation.
        return (None, None)
    if len(sources) == 1:
        # There's a many-to-one mapping of binaries to a source package. Use
        # the only possible source package for all binaries.
        match_first = True
    elif not "version" in info:
        # There are multiple combinations of possible binary to source package
        # mappings. We can't make an educated guess if we don't have a valid
        # binary package version so don't attempt to construct a link.
        return (None, None)

    bin_version = info.get("version")

    if "source" in info:
        # info dict contains a reference to the source name, so use it
        source_match = info.get("source")
        if source_match in sources:
            version_match = sources[source_match].get("version")
        else:
            print(
                "Warning: %s %s refers to source %s, but the source package is not found in the soures section."
                % (binary, bin_version, source_match),
                file=sys.stderr,
            )
            # XXX protect this with a command line option?
            if source_match.startswith("linux-meta") or source_match.startswith(
                "linux-signed"
            ):
                version_match = bin_version
                print(
                    "(%s %s) kernel source %s detected, hackishly using binary version as source version."
                    % (binary, bin_version, source_match),
                    file=sys.stderr,
                )
    else:
        for source in sources:
            source_version = sources[source].get("version")
            if match_first or bin_version == source_version:
                source_match = source
                version_match = source_version
                break

    if source_match:
        source_link = "https://launchpad.net/ubuntu/+source/" + source_match
        if version_match:
            # Be certain to use the source package version rather than the
            # binary package version here or the link will be broken for
            # certain packages
            version_link = source_link + "/" + version_match

    return (source_link, version_link)


parser = argparse.ArgumentParser(description="CLI to post USNs",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument(
    "--action",
    action="store",
    type=str,
    default="add",
    choices=["add", "update", "remove"],
    help="API action to perform",
)
parser.add_argument(
    "--json",
    action="store",
    type=str,
    help="Path to json file. Required for --action add/update. Can be used instead of --usns for --action remove",
)
parser.add_argument(
    "--usns",
    action="store",
    nargs="+",
    help="Can be used instead of --json with --action remove",
)
parser.add_argument(
    "--endpoint",
    action="store",
    type=str,
    default="https://ubuntu.com/security/notices",
    help="API endpoint url.",
)
parser.add_argument(
    "--stop",
    action="store_true",
    help="Exit after non-200 status. If upserting, exit after both attempted add/update operations fail",
)
parser.add_argument(
    "--no-upsert",
    action="store_true",
    help="No update after non-200 status on add, No add after non-200 status on update",
)
parser.add_argument(
    "--prefix",
    action="store",
    type=str,
    default=None,
    help="prefix for value of id field. eg: 'USN-'",
)
parser.add_argument(
    "--startwith",
    action="store",
    type=str,
    help="USN ID (without USN- prefix) to start with. Useful for resuming an interupted batch operation.",
)
parser.add_argument(
    "--debug",
    action="store_true",
    help="Don't perform action; instead emit json to stdout",
)

args = parser.parse_args()

if args.json and not os.path.exists(args.json):
    sys.exit(f"Error: {args.json} not found")
if (args.action == "add" or args.action == "update") and not args.json:
    sys.exit(f"Error: --action {args.action} requires --json")
if args.action == "remove" and not args.json and not args.usns:
    sys.exit("Error: --action remove requires --json or --usns")
if args.startwith and not re.match("\d{1,5}-\d{1,2}", args.startwith):
    sys.exit("Error: --startwith must match '\d{1,5}-\d{1,2}'")

# if we have a list of USNs instead of a json file
# we can just remove/DELETE them
if args.action == "remove" and args.usns:
    http_method = "DELETE"
    for usn in args.usns:
        endpoint = f"{args.endpoint}/{usn}.json"
        if args.debug:
            print(f"DEBUG: would send delete http request for: {endpoint}")
        else:
            response = authentication(method=http_method, url=endpoint, payload=None)
            print(response, response.text[0:60])
            if args.stop and not re.match(r"^<Response \[2..\]>$", str(response)):
                sys.exit(1)
    sys.exit(0)

# read in the json
with open(args.json, "r") as fh:
    usn_json = json.load(fh)

# split usn ids into tuples for sorting
def usn_key(usn):
    if not usn:
        return ()
    return tuple([int(n) for n in usn[0].split("-")])


def check_response(response):
    if not re.match(r"^<Response \[2..\]>$", str(response)):
        # communicating with the endpoint failed, display the full
        # response
        print(notice["id"], response, response.text)
        return False
    else:
        print(notice["id"], response, response.text[0:60])
        return True


# Check USN after publishing to make sure it has the required information
# on each binary for the ua client to properly work
def check_usn(usn):
    success = True
    for release in usn["release_packages"]:
        for package in usn["release_packages"][release]:
            if not package["is_source"]:
                for attr in ["is_visible", "source_link", "pocket"]:
                    if attr not in package or package[attr] == "":
                        print(
                            f"{package['name']} is missing required attribute '{attr}' on {release}"
                        )
                        success = False
    return success


payload = sorted(usn_json.items(), key=usn_key)

for notice_id, notice in payload:

    if args.startwith and usn_key([notice_id]) < usn_key([args.startwith]):
        continue

    # format release_packages
    release_packages = {}

    for codename, packages in notice["releases"].items():
        release_packages[codename] = []
        if "sources" in packages:
            for name, info in packages["sources"].items():
                release_packages[codename].append(
                    {
                        "name": name,
                        "version": info["version"],
                        "description": info.get("description", ""),
                        "is_source": "true",
                    }
                )

        binaries_key = "allbinaries"
        if binaries_key not in packages:
            binaries_key = "binaries"
        for name, info in packages[binaries_key].items():
            if "sources" in packages:
                source_link, version_link = guess_binary_links(
                    name, info, packages["sources"]
                )
                # if this package was not published in one of the
                # archive pockets, then the version link will not exist
                # on launchpad, so drop it. At some point, we can put
                # something more useful in its place.
                if (version_link and "pocket" in info and info["pocket"] not in ARCHIVE_POCKETS):
                    version_link = None
            else:
                source_link = ""
                version_link = ""
            is_visible = "false"
            if name in packages["binaries"]:
                is_visible = "true"
            release_package_info = {
                "name": name,
                "version": info["version"],
                "is_source": "false",
                "source_link": source_link,
                "version_link": version_link,
                "is_visible": is_visible,
            }
            if "pocket" in info:
                release_package_info["pocket"] = info["pocket"]

            release_packages[codename].append(release_package_info)

    # format CVEs and references
    cves = []
    references = []
    if "cves" in notice:
        for reference in notice["cves"]:
            if re.match("CVE-\d{4}-\d+", reference) and not reference in cves:
                cves.append(reference)
            else:
                references.append(reference)

    # Our internal USN schema does not contain a prefix for USNs ids as the website schema does.
    # The publish-usn-to-website shell script adds the prefix, but if we are invoking this script directly,
    # we can add it here with the --prefix argument; otherwise the web api will fail
    notice_id_value = notice["id"]
    if args.prefix and not notice_id_value.startswith(args.prefix):
        notice_id_value = args.prefix + notice_id_value

    # Build json payload
    json_data = {
        "id": notice_id_value,
        "description": notice["description"],
        "references": references,
        "cves": cves,
        "release_packages": release_packages,
        "title": notice["title"],
        "published": datetime.utcfromtimestamp(notice["timestamp"]).isoformat(),
        "summary": notice.get("isummary", notice["title"]),
        "instructions": notice.get(
            "action",
            "In general, a standard system update will make all the necessary changes.",
        ),
    }
    if "is_hidden" in notice:
        json_data["is_hidden"] = notice["is_hidden"]

    # Build endpoint
    if args.debug:
        print(json.dumps(json_data, sort_keys=True, indent=2))
        continue
    elif args.action == "add":
        upsert = not args.no_upsert
        http_method = "POST"
        endpoint = f"{args.endpoint}.json"
    elif args.action == "update":
        upsert = not args.no_upsert
        http_method = "PUT"
        endpoint = f"{args.endpoint}/{notice_id_value}.json"
    elif args.action == "remove":
        upsert = False
        http_method = "DELETE"
        endpoint = f"{args.endpoint}/{notice_id_value}.json"
        json_data = None

    # print("DEBUG json_data is %s" % json_data)
    response = authentication(method=http_method, url=endpoint, payload=json_data)
    successful_response = check_response(response)

    if upsert and not successful_response:
        if args.action == "add":
            # print(f"{notice['id']} add failed, trying update")
            http_method = "PUT"
            endpoint = f"{args.endpoint}/{notice['id']}.json"
        elif args.action == "update":
            # print(f"{notice['id']} update failed, trying add")
            http_method = "POST"
            endpoint = f"{args.endpoint}.json"
        response = authentication(method=http_method, url=endpoint, payload=json_data)
        successful_response = check_response(response)

    if args.stop and not successful_response:
        sys.exit(1)

    # validate all required fields were properly added on PUT or POST methods
    if successful_response and (http_method == "PUT" or http_method == "POST"):
        endpoint = f"{args.endpoint}/{notice_id_value}.json"
        response = authentication(method="GET", url=endpoint, payload=None)
        if check_response(response) and check_usn(response.json()):
            print(f"{notice_id_value} is OK")
        else:
            print(f"{notice_id_value} has issues")
            sys.exit(1)
