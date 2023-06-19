#!/usr/bin/env python3

# Author: Kees Cook <kees@ubuntu.com>
# Author: Jamie Strandboge <jamie@ubuntu.com>
# Author: Marc Deslauriers <marc.deslauriers@canonical.com>
# Copyright (C) 2005-2017 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 2 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# Fetch the USN database and pass it as the first argument
#  wget http://people.canonical.com/~ubuntu-security/usn/database.pickle
#  ./scripts/sync-from-usns.py database.pickle
#
from __future__ import print_function

import argparse
import os
import os.path
import re
import sys
import textwrap

import cve_lib
import usn_lib

from source_map import version_compare, load

def extract_cve_descriptions(usn, usnnum, verbose):
    descriptions = dict()
    cves = set()
    for cve in usn.get('cves', []):
        if cve.startswith('CVE-'):
            cves.add(cve)
    if len(cves) == 0:
        return descriptions

    try:
        # FIXME: the usn_lib should be doing the utf-8'ing, but
        # we can't do that until Python 3.
        # "pickle.open(..., encoding='utf-8')"
        # http://docs.python.org/py3k/library/pickle.html
        if sys.version_info[0] == 3:
            description = usn['description'].strip()
        else:
            description = usn['description'].decode("utf-8").strip()
    except:
        print("[%s]" % (usn['description']), file=sys.stderr)
        raise
    chunks = [x.replace('\n', ' ').replace('   ', ' ').replace('  ', ' ').strip() for x in description.split('\n\n')]

    # Drop un-parened USN qualifiers
    affected = re.compile(' (Only )?Ubuntu [^ ]+( LTS)?(, (and )?Ubuntu [^ ]+( LTS)?)? (was|were) (not )?affected\.')
    cve_list_regex = re.compile(r' ?\((CVE-\d{4}-\d{4,7},? ?)+\)')
    cve_regex = re.compile(r'CVE-\d{4}-\d{4,7}')
    if len(chunks) == 1:
        # This description applies to all the CVEs
        for cve in cves:
            descriptions[cve] = textwrap.fill(description, 75)
    else:
        # Extracting (CVE-YYYY-NNNN, CVE-...)
        for chunk in chunks:
            chunk = affected.sub('', chunk)
            cve_list = cve_list_regex.search(chunk)
            description = cve_list_regex.sub('', chunk)

            if not cve_list:
                if verbose:
                    print("USN %s: CVE list is missing: '%s'" % (usnnum, chunk), file=sys.stderr)
                continue

            # In case the CVE list is in the middle of the description,
            # so we can preserve the dot.
            if description[-2:] == '..':
                description = description[:-1]

            cves = cve_regex.findall(cve_list.group())
            for cve in cves:
                descriptions[cve] = textwrap.fill(description, 75)

    return descriptions

def parse_args():
    parser = argparse.ArgumentParser(description="Sync cve status from USN database")
    parser.add_argument("--usn", help="Limit report/update to a single USN", metavar="USN", default=None)
    parser.add_argument("-u", "--update", help="Update CVEs with released package versions", action='store_true')
    parser.add_argument("-U", "--use-usn", help="Use the version in the USN if it differs from the version in UCT", action='store_true')
    parser.add_argument("-v", "--verbose", help="Report logic while processing USNs", action='store_true')
    parser.add_argument("-d", "--debug", help="Report additional debugging while processing USNs", action='store_true')
    parser.add_argument("-r", "--retired", help="Process retired CVEs in addition to active ones", action='store_true')
    parser.add_argument('-g', "--git-stage", help="When updating, stage for commit by adding to git's index (requires --update)", action='store_true')
    parser.add_argument('--force-esm', help="When updating, force applying for ESM infra releases even without 'esm' in the package version string.", action='store_true')
    parser.add_argument("database", nargs="?", help="Use alternate USN database (default: %(default)s)", action='store', default=config['usn_db_copy'])
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    config = cve_lib.read_config()

    args = parse_args()
    if args.git_stage:
        if not args.update:
            print('--git-stage option requires --update as well, exiting', file=sys.stderr)
            exit(1)
        if not cve_lib.git_is_tree_clean(debug=True):
            print('Please commit or stash your existing changes to UCT first. Aborting.',
                file=sys.stderr)
            exit(1)

    if args.force_esm and not args.usn:
            print('--force-esm option requires a specific usn to operate on, exiting.', file=sys.stderr)
            exit(1)

    if args.debug:
        print("Loading %s ..." % (args.database), file=sys.stderr)

    cves = dict()
    reverted = usn_lib.get_reverted()
    ignored_description = usn_lib.get_ignored_description()
    db = usn_lib.load_database(args.database)
    usnlist = [args.usn]
    if not args.usn:
        usnlist = db
 
    srcmap = {}
    for usn in usnlist:
        ubuntu_descriptions = dict()
        if args.debug:
            print('Checking %s' % (usn), file=sys.stderr)
        if 'cves' not in db[usn]:
            continue

        # Should we update Ubuntu-Description? (only post USN 800 let's say)
        # Ignored non "-1" USNs for sanity...
        usn_parts = [int(x) for x in usn.split('-')]
        if usn_parts[0] > 800 and usn_parts[1] == 1:
            update_descriptions = False
            for rel in db[usn]['releases']:
                # FIXME: known stable kernel release list should be specified somewhere
                # else.
                if len(set(db[usn]['releases'][rel].get('sources', [])).intersection(set(cve_lib.kernel_srcs))) > 0:
                    update_descriptions = True
                    if args.debug:
                        print('Extracting Ubuntu-Description from %s' % (usn), file=sys.stderr)
                    break
            if update_descriptions and usn not in ignored_description:
                ubuntu_descriptions = extract_cve_descriptions(db[usn], usn, args.verbose)

        for cve in db[usn]['cves']:
            if args.debug:
                print('Want %s' % (cve), file=sys.stderr)
            if not cve.startswith('CVE-'):
                if args.debug:
                    print("Skipping (does not start with 'CVE-')", file=sys.stderr)
                continue
            # Skip checking CVEs that were reverted for a given USN
            if usn in reverted and cve in reverted[usn]:
                if args.debug:
                    print("Skipping (was reverted)", file=sys.stderr)
                continue
            filename = '%s/%s' % (cve_lib.active_dir, cve)
            if os.path.exists('%s/%s' % (cve_lib.retired_dir, cve)):
                if args.retired:
                    # include retired CVEs (may create false warnings)
                    filename = '%s/%s' % (cve_lib.retired_dir, cve)
                else:
                    # Skip retired CVEs
                    if args.debug:
                        print("Skipping (already retired)", file=sys.stderr)
                    continue
            if os.path.exists('%s/%s' % (cve_lib.ignored_dir, cve)):
                # Skip ignored CVEs, may have been REJECTED after USN publication
                if args.debug:
                    print("Skipping (already ignored)", file=sys.stderr)
                continue
            if os.path.exists(filename):
                if args.verbose:
                    print('USN %s refers to %s' % (usn, cve))
                try:
                    data = cve_lib.load_cve(filename)
                except ValueError as e:
                    print(e, file=sys.stderr)
                    continue
                cves.setdefault(cve, data)

                # update Ubuntu-Description
                if cve in ubuntu_descriptions:
                    if usn in ignored_description and cve in ignored_description[usn]:
                        if args.debug:
                            print("Skipping update of description due to ignore list", file=sys.stderr)
                    else:
                        desc = ubuntu_descriptions[cve]
                        if data.get('Ubuntu-Description', None) != '\n' + desc:
                            print("USN %s has updated Ubuntu-Description for %s:\n %s" % (usn, cve, "\n ".join(desc.strip().splitlines())), file=sys.stderr)
                            if args.debug:
                                print("[%s]\n[%s]" % (data.get('Ubuntu-Description', ''), '\n' + desc), file=sys.stderr)
                            if args.update:
                                cve_lib.update_multiline_field(filename, 'Ubuntu-Description', desc)
                                if args.git_stage:
                                    cve_lib.git_add(filename)

                # update References
                if 'References' in data:
                    usn_ref = "https://ubuntu.com/security/notices/USN-" + usn
                    found = False
                    if usn_ref in data['References']:
                        found = True
                    if not found:
                        print("%s references %s" % (usn_ref, cve), file=sys.stderr)
                        if args.update:
                            cve_lib.add_reference(filename, usn_ref)
                            if args.git_stage:
                                cve_lib.git_add(filename)

                # Record what the PublicDate field was when we published, in case
                # NVD moves it around.
                if 'PublicDateAtUSN' not in data:
                    if data['PublicDate'].strip() == "":
                        print("Yikes, empty PublicDate for %s" % (cve), file=sys.stderr)
                        sys.exit(1)
                    if args.update:
                        cve_lib.prepend_field(filename, 'PublicDateAtUSN', data['PublicDate'])
                        if args.git_stage:
                            cve_lib.git_add(filename)

                for rel in db[usn]['releases']:
                    if 'sources' not in db[usn]['releases'][rel]:
                        if args.debug:
                            print("  strange: %s listed, but without any changed sources -- skipping release" % (rel))
                        continue
                    cve_rel = rel
                    if not cve_lib.is_active_release(rel) and cve_lib.is_active_esm_release(rel):
                        cve_rel = cve_lib.get_esm_name(rel)
                    for src in db[usn]['releases'][rel]['sources']:
                        version = db[usn]['releases'][rel]['sources'][src]['version']
                        esm_version_match = re.search("[\+~]esm\d+", version)
                        if esm_version_match:
                            if cve_lib.is_active_release(rel):
                                cve_rel = cve_lib.get_esm_name(rel, 'universe')
                            else:
                                if not rel in srcmap:
                                    srcmap[rel] = load(releases=[rel], skip_eol_releases=False)[rel]
                                if cve_lib.is_universe(srcmap, src, rel, None):
                                    cve_rel = cve_lib.get_esm_name(rel, 'universe')
                                else:
                                    cve_rel = cve_lib.get_esm_name(rel)
                        # If the version doesn't match 'esm' and this is
                        # for an esm release, then skip (because that would
                        # match for all the USNs that were published prior
                        # to a release going into ESM infra status),
                        # *unless* the --force-esm argument has been passed
                        # for updates prepared by other teams that do not
                        # use the "esm" in the version string convention,
                        # like the kernel team.
                        elif not args.force_esm and not esm_version_match and 'esm' in cve_rel:
                            continue

                        if src not in cves[cve]['pkgs'] or cve_rel not in cves[cve]['pkgs'][src]:
                            # HACK: ignore abandoned linux topic branches
                            if src in ['linux-ti-omap', 'linux-qcm-msm']:
                                continue
                            # HACK: ignore firefox-* packages since we track
                            # xulrunner. These existed only from hardy-karmic.
                            if src in ['firefox-3.0', 'firefox-3.1', 'firefox-3.5']:
                                continue
                            # skip eol releases
                            if not cve_lib.is_active_release(rel) and not cve_lib.is_active_esm_release(rel):
                                continue
                            print("USN-%s touches %s in %s with %s (but is not listed in %s)" % (usn, src, cve_rel, cve, filename), file=sys.stderr)
                            continue
                        state, notes = cves[cve]['pkgs'][src][cve_rel]

                        # A CVE is tied to a USN, which means sometimes the CVE
                        # doesn't affect all releases of package, so skip
                        # not-affected without comment
                        if state == 'not-affected':
                            if args.verbose:
                                print("  %s/%s marked 'not-affected' -- ignoring" % (src, cve_rel))
                            continue

                        if state == 'DNE' and cve_lib.is_active_esm_release(rel):
                            if args.verbose:
                                print("  %s/%s marked 'DNE' -- ignoring" % (src, cve_rel))
                            continue
                        # if state == 'pending' and notes == db[usn]['releases'][rel]['sources'][src]['version']:
                        #    # Found aligned pending/released pair
                        #    pass

                        if state not in ['needed', 'deferred', 'pending', 'released', 'active', 'needs-triage', 'ignored']:
                            print("USN-%s fixed %s in %s %s/%s (but is marked %s)!?" % (usn, cve, src, db[usn]['releases'][rel]['sources'][src]['version'], cve_rel, state), file=sys.stderr)
                            continue

                        if state != 'released':
                            # CVE db is the "master" for when a CVE was fixed,
                            # so only fill in the version from the USN if the
                            # fixed version is not already known to the CVE db.
                            detail = ""
                            version = notes
                            usn_ver = db[usn]['releases'][rel]['sources'][src]['version']
                            if version == "":
                                version = usn_ver
                            elif version != usn_ver:
                                detail = " (USN: %s ) " % (usn_ver)
                            print("USN-%s fixed %s in %s %s%s/%s (was %s)" % (usn, cve, src, version, detail, cve_rel, state), file=sys.stderr)
                            if version_compare(version, usn_ver) > 0 and not (state == 'deferred' or state == 'ignored' or args.use_usn):
                                print("ERROR: Version in CVE (%s) is higher than USN version! Skipping" % cve, file=sys.stderr)
                                continue
                            if args.use_usn or state == 'deferred' or state == 'ignored':
                                version = usn_ver
                            if args.update:
                                cve_lib.update_state(filename, src, cve_rel, 'released', version)

                                if esm_version_match:
                                    continue

                                if not cve_rel in srcmap:
                                    srcmap[cve_rel] = load(releases=[cve_rel], skip_eol_releases=False)[cve_rel]

                                esm_rel = cve_lib.get_esm_name(cve_rel, 'universe' if cve_lib.is_universe(srcmap, src, cve_rel, None) else 'main')
                                if esm_rel and esm_rel in cves[cve]['pkgs'][src]:
                                    status_esm = cves[cve]['pkgs'][src][esm_rel][0]
                                    if status_esm != 'released' and status_esm != 'not-affected' and status_esm != 'ignored':
                                        print("USN-%s fixed %s in %s %s%s/%s (was %s)" % (usn, cve, src, version, detail, esm_rel, status_esm), file=sys.stderr)
                                        cve_lib.update_state(filename, src, esm_rel, 'not-affected', version)

                                if args.git_stage:
                                    cve_lib.git_add(filename)
                        elif args.debug:
                            print("  %s/%s marked 'released' -- ignoring" % (src, cve_rel))
            else:
                print("USN-%s fixed %s but it is neither active nor retired" % (usn, cve), file=sys.stderr)
