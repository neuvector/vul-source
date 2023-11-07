#!/usr/bin/python3
import glob
import json
import os
import re
import sys

import cve_lib

def parse_boilerplate(filepath):
    cve_data = cve_lib.load_cve(filepath)
    # capture tags, Notes, and package relationships
    data = dict()
    data.setdefault("aliases", list())
    # tags are a set but json can't serialise a set so convert to a list first
    data.setdefault("tags", list(cve_data.get("tags", list())))
    data.setdefault("notes", cve_data.get("Notes", list()))
    data.setdefault("pkgs", cve_data.get("pkgs", dict()))
    return data


def load_boilerplates():
    data = dict()
    aliases = dict()
    for filepath in glob.glob("active/00boilerplate.*"):
        name = ".".join(filepath.split(".")[1:])
        # check if is a symlink and if so don't bother loading the file
        # directly but add an entry as this is an alias
        if os.path.islink(filepath):
            orig = os.readlink(filepath)
            orig_name = ".".join(orig.split(".")[1:])
            aliases.setdefault(orig_name, set())
            aliases[orig_name].add(name)
            continue
        bpdata = parse_boilerplate(filepath)
        # having a package reference itself as we have in the boilerplates
        # is redundant - although this is not always the case as we may
        # have a boilerplate filename like openjdk yet there is no openjdk
        # package (just openjdk-8 etc) - so ignore any failures here
        try:
            del bpdata["pkgs"][name]
        except KeyError:
            pass
        data.setdefault(name, bpdata)
    for alias in aliases:
        data[alias]["aliases"] = list(aliases[alias])
    return data


def load_package_info_overrides():
    with open("meta_lists/package_info_overrides.json", "r") as fp:
        data = json.load(fp)
        return data


overrides_data = load_package_info_overrides()

# turn this into empty data
for pkg in overrides_data:
    for key in ["aliases", "tags", "notes"]:
        overrides_data[pkg][key] = []
    overrides_data[pkg]["pkgs"] = {}
bp_data = load_boilerplates()
# merge the two data sources manually so we can ensure that we retain all keys
# from both independent data sources
data = dict(overrides_data)
for pkg in bp_data:
    if pkg in data:
        for key in bp_data[pkg]:
            data[pkg][key] = bp_data[pkg][key]
    else:
        data[pkg] = bp_data[pkg]

print(json.dumps(data, indent=2))
sys.exit(0)

# TODO - decide if we want to keep this - for now leave it out

def parse_embedded_code_copies(filepath):
    begin_re = re.compile(r"^---BEGIN$")
    pkg_re = re.compile(r"^([a-zA-Z0-9.+_-]+).*$")
    #	[release] - srcpkg version|<status> (sort; bug #)
    embedding_re = re.compile(r"^\t(\[([a-z]+)\] )?- ([a-zA-Z0-9.+-]+) ([a-zA-Z0-9:~.+-]+|<(unfixed|removed|itp|not-affected|unknown|unfixable)>)( \((static|embed|modified-embed|fork|old-version)(; (.*))?\))?.*$")
    note_re = re.compile(r"^\tNOTE: (.*)$")
    data = dict()
    pkgs = dict()
    notes = dict()
    with open(filepath, "r") as fp:
        linenum = 0
        begin = False
        pkg = None
        embedding_pkg = None
        for line in fp.readlines():
            linenum += 1
            # strip trailing space
            line = line.rstrip()
            if not begin:
                if begin_re.match(line):
                    begin = True
                continue
            if len(line) == 0:
                continue
            # is this a new package
            m = pkg_re.match(line)
            if m is not None:
                pkg = m[1]
                pkgs[pkg] = dict()
                continue
            # is this an entry for a package
            m = embedding_re.match(line)
            if m is not None:
                assert pkg is not None
                if m[2] is not None:
                    # release
                    pass
                embedding_pkg = m[3]
                status = m[4]
                sort = m[7]
                pkgs[pkg][embedding_pkg] = (status, sort)
                continue
            m = note_re.match(line)
            if m is not None:
                assert pkg is not None
                assert embedding_pkg is not None
                notes.setdefault(pkg, dict())
                notes[pkg][embedding_pkg] = m[1]
                continue
            print("%s: %d: Failed to parse: '%s'" % (filepath, linenum, line), file=sys.stderr)
    data["pkgs"] = pkgs
    data["notes"] = notes
    return data

# also parse debian's embedded-code-copies and amalgate that into data
config = cve_lib.read_config()
debian_embedded_copies = os.path.join(config['secure_testing_path'], "data", "embedded-code-copies")
code_copies = parse_embedded_code_copies(debian_embedded_copies)
for pkg in code_copies["pkgs"]:
    data.setdefault(pkg, {"aliases": [],
                          "tags": [],
                          "notes": [],
                          "pkgs": {}})
    for embedding_pkg in code_copies["pkgs"][pkg]:
        data[pkg]["pkgs"].setdefault(embedding_pkg, ("needs-triage", ""))
        # use the sort to create a more informative description of the
        # relationship between pkg and embedding_pkg
        status, sort = code_copies["pkgs"][pkg][embedding_pkg]
        template = "%s embeds a copy of %s"
        if sort == "static":
            template = "%s statically links against %s so needs to be rebuilt"
        elif sort == "modified-embed":
            template = "%s embeds a modified copy of %s so should be checked if is affected"
        elif sort == "fork":
            template = "%s contains a fork of %s so should be checked if is affected"
        elif sort == "old-version":
            template = "%s contains an older version of %s so should be checked if is affected"
        note = template % (embedding_pkg, pkg)
        if pkg in code_copies["notes"] and embedding_pkg in code_copies["notes"][pkg]:
            note = note + " - " + code_copies["notes"][pkg][embedding_pkg]
        data[pkg]["notes"].append(("dst", note))
