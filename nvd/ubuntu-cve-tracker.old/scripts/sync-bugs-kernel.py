#!/usr/bin/env python2

## NOTE: tested on Bug 1399142 899463

# Author: Kees Cook <kees@ubuntu.com>
# Author: Marc Deslauriers <marc.deslauriers@canonical.com>
# Copyright (C) 2011-2012 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 2 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# Fetch the USN database and pass it as the first argument
#  wget http://people.canonical.com/~ubuntu-security/usn/database.pickle
#  ./scripts/sync-bugs-kernel.py database.pickle
#
# This script is intended to sync state between the tracker and LP, as defined
# in the README.
#
from __future__ import print_function

import glob
import optparse
import os
import os.path
import subprocess
import sys

import cve_lib
import urlparse
from lp_lib import UCTLaunchpad

priority_to_importance = {
    'critical':   'Critical',
    'high':       'High',
    'medium':     'Medium',
    'low':        'Low',
    'negligible': 'Wishlist',
}

parser = optparse.OptionParser()
parser.add_option("--cve", help="Limit processing to a comma-separated list of CVEs", metavar="CVE[,CVE...]", default=None)
parser.add_option("-u", "--update", help="Update CVEs and LP bugs with state changes", action='store_true')
parser.add_option("--confirm-update", help="Update CVEs and LP bugs with state changes only after confirming actions (enables verbose mode)", action='store_true')
parser.add_option("-v", "--verbose", help="Report logic while processing USNs", action='store_true')
parser.add_option("-d", "--debug", help="Report additional debugging while processing USNs", action='store_true')
parser.add_option("--allow-missing-tasks", help="Do not create missing tasks", action='store_true')
parser.add_option("--allow-eol-tasks", help="Do not delete ignored/EoL tasks", action='store_true')
parser.add_option("--allow-missing-nominations", help="Do not create missing release nominations", action='store_true')
parser.add_option("--bug-creation-cutoff", help="Do not create missing bugs older than this date (default: 2011-06-01)", action='store', metavar="YYYY-MM-DD", default="2011-06-01")
parser.add_option("--search", help="Search Launchpad for unlinked kernel CVE bugs (usually times out, unfortunately)", action='store_true')
parser.add_option("--notify", help="Send notification when prompting for a response (the default)", action='store_true', dest="notify", default=True)
parser.add_option("--no-notify", help="Do not send notification when prompting for a response", action='store_false', dest="notify")
(opt, args) = parser.parse_args()

# for bugs where we don't want to disturb the description set the
# following tag
UCT_DESC_IGNORE_TAG = 'kernel-cve-skip-description'

uctlp = UCTLaunchpad(opt)
# Use devel version so we get the bugtask delete API
uctlp.lp_version = "devel"

config = cve_lib.read_config()
ktools = config.get('kernel_team_tools_path', None)
if not ktools:
    raise ValueError("'kernel_team_tools_path' missing in ~/.ubuntu-cve-tracker.conf")

os.chdir(os.environ['UCT'])
if opt.cve:
    cves = ['%s/%s' % (cve_lib.active_dir, x) for x in opt.cve.split(',')]
else:
    cves = glob.glob('%s/CVE-*' % cve_lib.active_dir)

if opt.confirm_update:
    opt.verbose = True

if opt.notify:
    try:
        import pynotify as notify
        notify.init('$UCT sync-bugs-kernel.py')
    except ImportError:
        print('Unable to load notification library, disabling notifications', file=sys.stderr)
        print('Perhaps install python-notify?', file=sys.stderr)
        opt.notify = False


# This doesn't actually work because LP is stupid, and can't search for
# subject words with "-"s in them. !!!
def slow_bug_search(cve):
    return None
    if opt.verbose:
        print("Finding LP bugs for %s ..." % (cve), file=sys.stderr)
    for task in uctlp.ubuntu.searchTasks(
                    search_text=cve,
                    status=["New", "Confirmed", "Triaged", "In Progress", "Fix Committed", "Fix Released"],
                    omit_targeted=False,
                    omit_duplicates=True):
        print(task.bug.title)


def load_kernel_bugs():
    bugs = dict()
    if opt.verbose:
        print("Finding open LP bugs for kernel ...", file=sys.stderr)
    for task in uctlp.ubuntu.searchTasks(
                    tags=['kernel-cve-tracker', 'kernel-cve-tracking-bug'],
                    tags_combinator='Any',
                    omit_targeted=False,
                    omit_duplicates=True):
        if not task.bug.title.startswith('CVE-'):
            continue
        cve = task.bug.title[0:13]
        bugs[cve] = task.bug
    if opt.verbose:
        print("\tfound %d" % (len(bugs)), file=sys.stderr)
    return bugs


need_kernel_bugs = set()


def add_to_needed_set(cve):
    need_kernel_bugs.add(cve)


def report_needed_set():
    for cve in need_kernel_bugs:
        print("Want to create LP bug for %s ..." % (cve), file=sys.stderr)


def create_kernel_bug(data):
    when = [int(x) for x in data['PublicDate'].split('-')]
    cutoff = [int(x) for x in opt.bug_creation_cutoff.split('-')]
    if when[0] < cutoff[0] or \
       (when[0] == cutoff[0] and when[1] < cutoff[1]) or \
       (when[0] == cutoff[0] and when[1] == cutoff[1] and when[2] < cutoff[2]):
        if opt.debug:
            print("Skipping LP bug for %s (%s < %s) ..." % (data['Candidate'], data['PublicDate'], opt.bug_creation_cutoff), file=sys.stderr)
        return None
    if not opt.update:
        add_to_needed_set(data['Candidate'])
        return None
    if opt.verbose:
        print("Creating LP bug for %s ..." % (data['Candidate']), file=sys.stderr)

    bug = None
    os.chdir(ktools)
    p = subprocess.Popen(['./stable/create-cve-tracker', '--verbose', '--cve', data['Candidate'][4:]], stdout=subprocess.PIPE, close_fds=True)
    for line in p.stdout:
        sys.stdout.write(line)
        if line.startswith('http') and 'bugs' in line:
            bug = int(line.strip().split('/')[-1])
    os.chdir(os.environ['UCT'])
    if p.wait() != 0:
        raise ValueError('Bug creation failed (rc %d)' % (p.returncode))

    return uctlp.lp.bugs[bug]


def set_task_importance(taskdict, src, release, importance):
    touched = False
    task = taskdict[src][release]
    if task.importance != importance:
        touched = True
        if not opt.update:
            if opt.verbose:
                print("\twant to update importance %s %s %s" % (src, release, importance), file=sys.stderr)
            return touched
        if opt.verbose:
            print('\t%s,%s: update importance => %s' % (src, release, importance))
        task.importance = importance
        uctlp.save(task)
    return touched


def set_task_status(taskdict, src, release, state):
    touched = False
    task = taskdict[src][release]
    if task.status != state:
        touched = True
        if not opt.update:
            if opt.verbose:
                print("\twant to update status %s %s (%s => %s)" % (src, release, task.status, state), file=sys.stderr)
            return touched
        if opt.verbose:
            print('\t%s,%s: update status (%s => %s)' % (src, release, task.status, state))
        task.status = state
        uctlp.save(task)
    return touched


def set_task_status_iff_exists(taskdict, src, release, state):
    touched = False
    if release not in taskdict[src].keys():
        print("\tskiping update of status (%s) to non-existent key %s %s" % (state, src, release), file=sys.stderr)
        return False
    task = taskdict[src][release]
    if task.status != state:
        touched = True
        if not opt.update:
            if opt.verbose:
                print("\twant to update status %s %s (%s => %s)" % (src, release, task.status, state), file=sys.stderr)
            return touched
        if opt.verbose:
            print('\t%s,%s: update status (%s => %s)' % (src, release, task.status, state))
        task.status = state
        uctlp.save(task)
    return touched


def delete_task(taskdict, src, release, reason):
    task = taskdict[src][release]
    touched = True
    if not opt.update:
        if opt.verbose:
            print("\twant to delete %s task %s %s" % (reason, src, release), file=sys.stderr)
        return touched
    if opt.verbose:
        print('\t%s,%s: deleted %s task' % (reason, src, release))
    task.lp_delete()
    return touched


def set_task_eol(taskdict, src, release):
    touched = False
    # should we don't something special with 'Fix Committed'?
    # task = taskdict[src][release]
    # if task.status != 'Fix Released' and task.status != 'Won\'t Fix':
    #    if set_task_status(taskdict, src, release, 'Invalid'): touched = True
    if delete_task(taskdict, src, release, 'EoL'):
        touched = True
    return touched


def set_bug_description(bug, description):
    touched = False
    description = description.strip()
    # Do no blow away non-New description with useless description
    if bug.description != 'Placeholder' and description == 'Description needed':
        return touched
    # check to see if we've marked the bug to not have its description overwritten
    if UCT_DESC_IGNORE_TAG in bug.tags:
        print("\tbug is tagged to ignore description updates, skipping", file=sys.stderr)
        return touched
    if bug.description != description:
        touched = True
        if not opt.update:
            if opt.verbose:
                print("\twant to update description [%s] -> [%s]" % (bug.description, description), file=sys.stderr)
            return touched
        if opt.verbose:
            print("\tdescription update [%s]" % (description), file=sys.stderr)
        bug.description = description
        uctlp.save(bug)
    return touched


def set_uct_state(data, src, rel, state):
    touched = False
    if data['pkgs'][src][rel][0] != state:
        touched = True
        if not opt.update:
            if opt.verbose:
                print("\twant to update UCT state %s %s (%s => %s)" % (src, rel, data['pkgs'][src][rel][0], state), file=sys.stderr)
            return touched
        if opt.verbose:
            print('\t%s,%s: update UCT state (%s => %s)' % (src, rel, data['pkgs'][src][rel][0], state))
        data['pkgs'][src][rel][0] = state
        # FIXME: for now, leave "note" alone
        cve_lib.update_state('%s/%s' % (cve_lib.active_dir, data['Candidate']), src, rel, state, data['pkgs'][src][rel][1])
    return touched


def add_uct_sha(data, src, sha_pair_to_add):
    if not opt.update:
        if opt.verbose:
            print("\twant to add SHAs to %s: %s" % (src, sha_pair_to_add), file=sys.stderr)
        return

    if opt.verbose:
        print("\tadding SHAs to %s: %s" % (src, sha_pair_to_add))

    raise ValueError("TODO")

    # if value.strip() != data.get(patchfield, ''):
    #     data[patchfield] = cve_lib.update_multiline_field('%s/%s' % (cve_lib.active_dir, data['Candidate']), patchfield, value)


def del_uct_sha(data, src, sha_pair_to_remove):
    if not opt.update:
        if opt.verbose:
            print("\twant to delete SHA from %s: %s" % (src, sha_pair_to_remove), file=sys.stderr)
        return

    if opt.verbose:
        print("\tremoving SHA from %s: %s" % (src, sha_pair_to_remove))

    raise ValueError("TODO")

    # if value.strip() != data.get(patchfield, ''):
    #     data[patchfield] = cve_lib.update_multiline_field('%s/%s' % (cve_lib.active_dir, data['Candidate']), patchfield, value)

# FIXME: there is a lot of copy/paste loop code here to walk the bug
# task vs uct status maps. This should probably be generalized into a
# callable function with some kind of callback system... hmmm.


def sync_to_bug_phase1(bug, tasks, data):
    touched = False
    if opt.verbose:
        print("\tsync to bug (phase 1)", file=sys.stderr)

    # Scan for EOL source packages and mark appropriately
    for src in tasks:
        if src not in cve_lib.kernel_srcs:
            continue
        for rel in cve_lib.eol_releases:
            # Already have a nomination for this release?
            if rel in tasks[src] and not opt.allow_eol_tasks and set_task_eol(tasks, src, rel):
                touched = True

    for src in data['pkgs']:
        if src not in cve_lib.kernel_srcs:
            continue

        if src not in tasks:
            # Logic for handling the missing tasks has already happened,
            # so unconditionally allow it here to avoid blowing up, since
            # a full abort is not needed.
            continue

        for rel in data['pkgs'][src]:
            release = rel
            if release == 'devel':
                release = cve_lib.devel_release
            if release in ['', 'upstream'] + cve_lib.eol_releases:
                continue
            # TODO: product kernels should be synced to a particular LP
            # project. This url is cve_lib.supported_products[src][1]
            if release == 'product' or release == 'snap':
                continue

            if release not in tasks[src]:
                continue

            state = data['pkgs'][src][rel][0]
            if release not in tasks[src] and state != 'DNE':
                print("\tmissing task for %s,%s" % (src, release), file=sys.stderr)
                continue

            # Update Status
            if state == 'DNE':
# replace next line with following commented line when deleting tasks is fixed
                if set_task_status_iff_exists(tasks, src, release, 'Invalid'):
                    touched = True
#                if delete_task(tasks, src, release, 'DNE'): touched = True
            elif state == 'pending' and tasks[src][release].status in ['Invalid', 'New', 'Confirmed', 'Triaged', 'In Progress']:
                if set_task_status(tasks, src, release, 'Fix Committed'):
                    touched = True
            elif state == 'released':
                if set_task_status(tasks, src, release, 'Fix Released'):
                    touched = True
            elif state in ['not-affected', 'ignored'] and tasks[src][release].status == "New":
                if set_task_status(tasks, src, release, 'Invalid'):
                    touched = True
            elif state == 'deferred':
                print("\tskipping deferred for %s, %s" % (src, release), file=sys.stderr)
                continue
            # Update Importance
            priority = cve_lib.contextual_priority(data, src, rel)[1]
            if set_task_importance(tasks, src, release, priority_to_importance[priority]):
                touched = True

    return touched


def sync_from_bug_phase2(bug, tasks, data):
    touched = False
    if opt.verbose:
        print("\tsync from bug (phase 2)", file=sys.stderr)

    for src in data['pkgs']:
        if src not in cve_lib.kernel_srcs:
            continue

        if src not in tasks:
            # Logic for handling the missing tasks has already happened,
            # so unconditionally allow it here to avoid blowing up, since
            # a full abort is not needed.
            continue

        for rel in data['pkgs'][src]:
            release = rel
            if release == 'devel':
                release = cve_lib.devel_release
            if release in ['', 'upstream'] + cve_lib.eol_releases:
                continue

            if release not in tasks[src]:
                continue

            state = data['pkgs'][src][rel][0]
            status = tasks[src][release].status

            if state == 'deferred':
                print("\tskipping deferred for %s, %s" % (src, release), file=sys.stderr)
                continue
            if status in ['Confirmed', 'Triaged', 'In Progress']:
                if set_uct_state(data, src, rel, 'needed'):
                    touched = True
            elif status in ['New'] and state != 'needed':
                if set_uct_state(data, src, rel, 'needs-triage'):
                    touched = True
            elif status in ['Invalid'] and state not in ['DNE', 'ignored']:
                if set_uct_state(data, src, rel, 'not-affected'):
                    touched = True

    for line in bug.description.splitlines():
        line = line.strip()
        if line.startswith('Add-Break-Fix:') or line.startswith('Del-Break-Fix:'):
            touched = True
            value = line.split(':', 1)[1].strip()
            shas = []
            if ' ' in value:
                shas = value.split(' ')
            else:
                shas = ['-', value]
            if len(shas) > 0:
                if line.startswith('Del'):
                    del_uct_sha(data, shas)
                else:
                    add_uct_sha(data, shas)
    return touched


def _extract_sha(sha):
    if '/' in sha:
        sha = sha.split('/')[-1]
    if '=' in sha:
        sha = sha.split('=')[-1]
    return sha


def _update_description_from_uct(bug, tasks, data):
    shas = []
    for src in data['pkgs']:
        if src not in cve_lib.kernel_srcs:
            continue

        if src not in tasks:
            # Logic for handling the missing tasks has already happened,
            # so unconditionally allow it here to avoid blowing up, since
            # a full abort is not needed.
            continue

        for (field, value) in data['patches'][src]:
            if field not in ['upstream', 'break-fix']:
                continue
            broken = None
            sha = None
            if field == 'upstream':
                broken = '-'
                sha = _extract_sha(value)
            if field == 'break-fix' and ' ' in value:
                broken, sha = [_extract_sha(x) for x in value.split(' ', 1)]
            if sha:
                shas.append((broken, sha))

    description = data['Description'].strip().replace('\n', ' ').strip()
    if description == "":
        description = data['Ubuntu-Description'].strip().replace('\n', ' ').strip()
        if description == "":
            description = "Description needed"
    description += "\n\n"
    for broken, sha in shas:
        description += "Break-Fix: %s %s\n" % (broken, sha)
    return set_bug_description(bug, description)


def sync_to_bug_phase3(bug, tasks, data):
    touched = False
    if opt.verbose:
        print("\tsync to bug (phase 3)", file=sys.stderr)

    for src in data['pkgs']:
        if src not in cve_lib.kernel_srcs:
            continue

        if src not in tasks:
            # Logic for handling the missing tasks has already happened,
            # so unconditionally allow it here to avoid blowing up, since
            # a full abort is not needed.
            continue

        for rel in data['pkgs'][src]:
            release = rel
            if release == 'devel':
                release = cve_lib.devel_release
            if release in ['', 'upstream'] + cve_lib.eol_releases:
                continue

            if release not in tasks[src]:
                continue

            state = data['pkgs'][src][rel][0]

            if state == 'needs-triage':
                if set_task_status(tasks, src, release, 'New'):
                    touched = True

    if _update_description_from_uct(bug, tasks, data):
        touched = True

    return touched


def sync_new_bug(bug, tasks, data):
    touched = False
    if opt.debug:
        print("\tsync new bug", file=sys.stderr)
    for src in data['pkgs']:
        if src not in cve_lib.kernel_srcs:
            continue

        if src not in tasks:
            # Logic for handling the missing tasks has already happened,
            # so unconditionally allow it here to avoid blowing up, since
            # a full abort is not needed.
            continue

        for rel in data['pkgs'][src]:
            release = rel
            if release == 'devel':
                release = cve_lib.devel_release
            if release in ['', 'upstream'] + cve_lib.eol_releases:
                continue

            if release not in tasks[src]:
                continue

            state = data['pkgs'][src][rel][0]
            if tasks[src][release].status != 'New':
                continue
            if state == 'DNE':
                if set_task_status_iff_exists(tasks, src, release, 'Invalid'):
                    touched = True
# can switch to delete when tasks deletion is fixed
#                if delete_task(tasks, src, release, 'DNE'): touched = True
            elif state == 'not-affected':
                if set_task_status(tasks, src, release, 'Invalid'):
                    touched = True
            elif state == 'pending':
                if set_task_status(tasks, src, release, 'Fix Committed'):
                    touched = True
            elif state == 'released':
                if set_task_status(tasks, src, release, 'Fix Released'):
                    touched = True

    if _update_description_from_uct(bug, tasks, data):
        touched = True

    return touched


def generate_task_map(bug):
    tasks = dict()
    for task in bug.bug_tasks:
        package, project, release = uctlp.extract_task(task)
        if project is None:
            # The project-less place-holder
            continue
        if project.lower() != 'ubuntu':
            print("WARNING: bug %d has task not in ubuntu project" % (bug.id), file=sys.stderr)
            continue
        # NOTE: record the task even if no release has been nominated
        # for the package so that we don't get errors later trying to
        # create a task that already exists; also, so that the missing
        # nominations will get created.
        package = package.lower()
        tasks.setdefault(package, dict())
        if release is None:
            # The release-less place-holder
            continue
        release = release.lower()
        tasks[package].setdefault(release, task)
    return tasks


def uct_src_all_nominations_DNE(src, data):
    for rel in cve_lib.releases:
        if src in data['pkgs'] and rel in data['pkgs'][src]:
            state = data['pkgs'][src][rel][0]
            if state != 'DNE':
                return False
    return True


def refresh_task_packages(bug, tasks, data):
    refresh = False

    verified_nominations = dict()
    for rel in cve_lib.releases:
        if rel not in cve_lib.eol_releases:
            verified_nominations[rel] = False

    for src in cve_lib.kernel_srcs:
        if src not in tasks:
            # srcs that only have DNE for all releases don't need tasks
            if uct_src_all_nominations_DNE(src, data):
                continue

            if opt.allow_missing_tasks:
                if opt.debug:
                    print("\tmissing task for '%s'" % (src), file=sys.stderr)
                continue
            elif not opt.update:
                print("\twant to add missing task for '%s'" % (src), file=sys.stderr)
            refresh = True
            if opt.update:
                if opt.verbose:
                    print("\tadding task for '%s'" % (src), file=sys.stderr)
                try:
                    bug.addTask(target=uctlp.ubuntu.getSourcePackage(name=src))
                except:
                    print("Unexpected error:", sys.exc_info()[0])
            continue

        # if the cve tracker doesn't have an entry for the source
        # package that the bug report has, move on to the next package.
        if src not in data['pkgs']:
            if opt.debug:
                print("\tskipping missing cve task for '%s'" % (src), file=sys.stderr)
            continue

        for rel in cve_lib.releases:
            # EOL releases should not have nominations added
            if rel in cve_lib.eol_releases:
                continue

            if rel == cve_lib.devel_release:
                data_rel = 'devel'
            else:
                data_rel = rel

            # Since LP attaches nominations across all packages, we only
            # have to do it once, not for each source package in the list.
            # but we do need to check them nomination release, if a
            # srcpkg DNE in a release it will be skipped below
            if verified_nominations[rel] is True:
                if opt.debug:
                    print("\talready verified nomination for release '%s'" % (rel), file=sys.stderr)
                continue

            # Already have a nomination for this release?
            if rel in tasks[src]:
                # Skip if we already have a nomination for this release
                verified_nominations[rel] = True
                if opt.debug:
                    print("\tskipping already nominated task for '%s' in release '%s'" % (src, rel), file=sys.stderr)
                continue

            # releases don't need nominations for DNE entries
            if data_rel not in data['pkgs'][src] or (data['pkgs'][src][data_rel][0] in ['DNE', 'not-affected']):
                if opt.debug:
                    print("\tskipping unneeded nomination task for '%s' in release '%s'" % (src, rel), file=sys.stderr)
                continue

            if opt.allow_missing_nominations:
                if opt.debug:
                    print("\tmissing nomination for %s" % (rel), file=sys.stderr)
                continue
            elif not opt.update:
                print("\twant to add missing nomination for %s %s" % (src, rel), file=sys.stderr)

            refresh = True
            if opt.update:
                # Find or create a nomination to approve
                try:
                    nom = bug.getNominationFor(target=uctlp.cached('series', rel))
                except:
                    if opt.verbose:
                        print("\tadding nomination for %s" % (rel), file=sys.stderr)
                    if bug.title in ['CVE-2010-3448', 'CVE-2011-1833', 'CVE-2012-4398']:
                        print("\t%s is in broken nomination list, skipping" % (bug.title), file=sys.stderr)
                        continue
                    try:
                        nom = bug.addNomination(target=uctlp.cached('series', rel))
                    except:
                        print("\tFailed to add nomination for '%s' to Bug: '%s'. You may need to add to broken list" % (rel, bug.title), file=sys.stderr)
                if opt.verbose:
                    print("\tapproving nomination for %s" % (rel), file=sys.stderr)
                # FIXME: launchpad nominations are busted for these bugs :(
                # LP: #706999 and LP: #732628
                if bug.title in ['CVE-2010-3448', 'CVE-2011-1833', 'CVE-2012-4398', 'CVE-2015-8709']:
                    print("\t%s is in broken list, skipping" % (bug.title), file=sys.stderr)
                    continue
                try:
                    nom.approve()
                except:
                    print("\tFailed to approve nomination for '%s' to Bug: '%s'. You may need to add to broken list" % (rel, bug.title), file=sys.stderr)

            verified_nominations[rel] = True

    return refresh


def sync_kernel_bug(bug, data, bugs_field):
    touched = False
    if opt.debug:
        if opt.update:
            print("Syncing LP bug %s with %s ..." % (bug, data['Candidate']), file=sys.stderr)
        else:
            print("Pretending to sync LP bug %s with %s ..." % (bug, data['Candidate']), file=sys.stderr)

    # Rebuild bug list
    if bugs_field != data['Bugs'].strip():
        print("\t'Bugs' field needs updating ...")
        if opt.update:
            cve_lib.update_multiline_field('%s/%s' % (cve_lib.active_dir, data['Candidate']), 'Bugs', bugs_field)

    # Generate task mapping dict(src -> dict( rel -> task ) )
    tasks = generate_task_map(bug)
    if refresh_task_packages(bug, tasks, data):
        touched = True
        tasks = generate_task_map(bug)

    if bug.description == 'Placeholder':
        # New bug, overwrite stuff
        if sync_new_bug(bug, tasks, data):
            touched = True
    # Active bug, overwrite what we can, then pull back the rest
    if sync_to_bug_phase1(bug, tasks, data):
        touched = True
    if sync_from_bug_phase2(bug, tasks, data):
        touched = True
    if sync_to_bug_phase3(bug, tasks, data):
        touched = True

    return touched


if __name__ == '__main__':
    # Find only open kernel CVEs
    info = dict()
    for filename in cves:
        cve = os.path.basename(filename)
        data = cve_lib.load_cve(filename)
        for src in cve_lib.kernel_srcs:
            if src not in data['pkgs']:
                continue
            found = False
            for rel in data['pkgs'][src]:
                if rel == "upstream":
                    continue
                if not data['pkgs'][src][rel][0] in cve_lib.status_closed:
                    # print "Want %s (%s: %s)" % (cve, src, data['pkgs'][src][rel][0])
                    info.setdefault(cve, data)
                    found = True
                    break
            if found:
                break

    # Load LP bugs
    buglist = dict()
    if not opt.cve and opt.search:
        buglist = load_kernel_bugs()

    # Load kernel CVEs
    for cve in sorted(info.keys()):
        # Load bug list
        bugs = []
        bugs_remote = []
        for uri in info[cve]['Bugs'].splitlines():
            uri = uri.strip()
            if uri == "":
                continue
            o = urlparse.urlparse(uri)
            if o.netloc.endswith('launchpad.net'):
                bugs.append(int(uri.split('/')[-1]))
            else:
                bugs_remote.append(uri)

        # Find or create bug
        if len(bugs) == 0:
            if cve not in buglist:
                found = slow_bug_search(cve)
                if not found:
                    found = create_kernel_bug(info[cve])
                if found:
                    buglist[cve] = found
            if cve in buglist:
                bugs = [buglist[cve].id]
            else:
                if opt.verbose:
                    print("%s: bug needed" % (cve))
                continue
        elif len(bugs) == 1:
            if cve not in buglist:
                # Link manually created or closed bugs
                buglist[cve] = uctlp.lp.bugs[bugs[0]]
            if bugs[0] != buglist[cve].id:
                # FIXME: automatically handle duplicates here instead of bailing
                print("%s: bug mismatch! (tracker:%d LP:%d)" % (cve, bugs[0], buglist[cve].id), file=sys.stderr)
                continue
        else:
            # Bail on multiple bugs
            print("%s: more than 1 LP bug: %s" % (cve, " ".join(["%d" % (x) for x in bugs])), file=sys.stderr)
            continue
        bug = bugs[0]

        # Check for duplicates
        dup = buglist[cve].duplicate_of
        if dup:
            buglist[cve] = dup
            bug = buglist[cve].id

        if opt.verbose:
            print("%s: LP: #%d" % (cve, bug))

        # Rebuild bug list
        bugs_text = "\n".join(bugs_remote + ['https://launchpad.net/bugs/%d' % (bug)])
        bugs_text = bugs_text.strip()

        # Synchronize with LP
        saved_update = opt.update
        if opt.confirm_update:
            opt.update = False
        made_changes = sync_kernel_bug(buglist[cve], info[cve], bugs_text)

        if made_changes and opt.confirm_update:
            if opt.notify:
                n = notify.Notification("%s: LP: #%d" % (cve, bug), "Make changes to bug?", "dialog-error")
                n.set_timeout(notify.EXPIRES_DEFAULT)
                n.show()
            print("Okay? [y/N] ", end=' ')
            ans = sys.stdin.readline()
            if ans.strip().lower().startswith('y'):
                opt.update = True
                sync_kernel_bug(buglist[cve], info[cve], bugs_text)
            else:
                print("Continuing ...")

        opt.update = saved_update

    if opt.verbose:
        report_needed_set()
